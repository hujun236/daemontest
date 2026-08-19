package main

// securechannel.go — encrypted data plane established on top of a negotiated
// SPAKE2 session.
//
// Encryption is AES-256-GCM. The 12-byte nonce is
//   [4-byte direction prefix][8-byte big-endian sequence number]
// Seq is strictly increasing per direction and never reused, which prevents
// replay. A gap in the sequence is accepted (WebSocket/DataChannel are ordered,
// so a gap only appears after a dropped message — decode and advance).
//
// Text messages are wrapped as an outer envelope whose `type` is one of
// enc_term / enc_file / enc_proxy, so the relay can still apply its rate-limit
// and free-plan policy without ever seeing the plaintext. Binary frames get a
// [0x07][8B seq][ciphertext] prefix and stay binary frames, so the relay's
// free-plan binary handling is unchanged.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync"
)

// Direction constants for the nonce prefix. App→Daemon is "C2S", Daemon→App is
// "S2C". The app sends with K_c2s + dirC2S; the daemon sends with K_s2c + dirS2C.
var (
	dirC2S = [4]byte{'C', '2', 'S', 0}
	dirS2C = [4]byte{'S', '2', 'C', 0}
)

var (
	errSecureInactive = errors.New("secure channel not active")
	errSecureReplay   = errors.New("secure channel replay or out-of-order seq")
	errSecureDecrypt  = errors.New("secure channel decrypt failed")
)

// NewSecureChannel builds an active channel. sendKey/recvKey are the 32-byte
// traffic keys (K_s2c/K_c2s for the daemon, K_c2s/K_s2c for the app); sendDir/
// recvDir are the matching 4-byte nonce prefixes.
func NewSecureChannel(sendKey, recvKey [32]byte, sendDir, recvDir []byte) (*SecureChannel, error) {
	gcmSend, err := newGCM(sendKey[:])
	if err != nil {
		return nil, err
	}
	gcmRecv, err := newGCM(recvKey[:])
	if err != nil {
		return nil, err
	}
	return &SecureChannel{
		sendKey: sendKey, recvKey: recvKey,
		sendDir: sendDir, recvDir: recvDir,
		gcmSend: gcmSend, gcmRecv: gcmRecv,
		active: true,
	}, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// SecureChannel is the per-direction encrypted transport.
type SecureChannel struct {
	mu      sync.Mutex
	active  bool
	sendKey [32]byte
	recvKey [32]byte
	sendDir []byte
	recvDir []byte
	gcmSend cipher.AEAD
	gcmRecv cipher.AEAD
	sendSeq uint64
	recvSeq uint64
	hasRecv bool
}

// Active reports whether encryption is on.
func (c *SecureChannel) Active() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

// Reset zeroes the keys and returns the channel to inactive. Called on
// channel switch, disconnect and handshake failure.
func (c *SecureChannel) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.active = false
	c.sendSeq = 0
	c.recvSeq = 0
	c.hasRecv = false
	for i := range c.sendKey {
		c.sendKey[i] = 0
	}
	for i := range c.recvKey {
		c.recvKey[i] = 0
	}
	c.gcmSend = nil
	c.gcmRecv = nil
}

// SeqState reports the current send/recv sequence numbers (test/debug aid).
func (c *SecureChannel) SeqState() (send, recv uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sendSeq, c.recvSeq
}

func makeNonce(dir []byte, seq uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, dir)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

// WrapJSON encrypts an inner Message and returns the outer envelope Message.
// The crypto seq lives on the outer envelope; any inner seq field (used for
// terminal output ordering) is untouched.
func (c *SecureChannel) WrapJSON(inner *Message) (*Message, error) {
	plain, err := json.Marshal(inner)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active || c.gcmSend == nil {
		return nil, errSecureInactive
	}
	if len(plain) > SecureMaxTextPayload {
		return nil, errors.New("secure wrap: inner JSON exceeds SecureMaxTextPayload")
	}
	seq := c.sendSeq
	c.sendSeq++
	ct := c.gcmSend.Seal(nil, makeNonce(c.sendDir, seq), plain, nil)
	return &Message{
		Type: outerTypeFor(inner.Type),
		Seq:  seq,
		Data: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// UnwrapJSON decrypts an outer enc_* Message back to the inner Message.
func (c *SecureChannel) UnwrapJSON(outer *Message) (*Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active || c.gcmRecv == nil {
		return nil, errSecureInactive
	}
	ct, err := base64.StdEncoding.DecodeString(outer.Data)
	if err != nil {
		return nil, errSecureDecrypt
	}
	seq := outer.Seq
	if c.hasRecv && seq <= c.recvSeq {
		return nil, errSecureReplay
	}
	plain, err := c.gcmRecv.Open(nil, makeNonce(c.recvDir, seq), ct, nil)
	if err != nil {
		return nil, errSecureDecrypt
	}
	c.recvSeq = seq
	c.hasRecv = true

	var inner Message
	if err := json.Unmarshal(plain, &inner); err != nil {
		return nil, errSecureDecrypt
	}
	return &inner, nil
}

// WrapBinary encrypts a raw binary frame and returns [0x07][8B seq][ciphertext].
func (c *SecureChannel) WrapBinary(frame []byte) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active || c.gcmSend == nil {
		return nil
	}
	seq := c.sendSeq
	c.sendSeq++
	ct := c.gcmSend.Seal(nil, makeNonce(c.sendDir, seq), frame, nil)
	out := make([]byte, 1+8+len(ct))
	out[0] = OpcodeSecureBinary
	binary.BigEndian.PutUint64(out[1:9], seq)
	copy(out[9:], ct)
	return out
}

// UnwrapBinary decrypts a secure binary frame back to the original frame
// (which keeps its own opcode byte, 0x01 file / 0x05 proxy).
func (c *SecureChannel) UnwrapBinary(frame []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active || c.gcmRecv == nil {
		return nil, errSecureInactive
	}
	if len(frame) < 10 || frame[0] != OpcodeSecureBinary {
		return nil, errSecureDecrypt
	}
	seq := binary.BigEndian.Uint64(frame[1:9])
	if c.hasRecv && seq <= c.recvSeq {
		return nil, errSecureReplay
	}
	plain, err := c.gcmRecv.Open(nil, makeNonce(c.recvDir, seq), frame[9:], nil)
	if err != nil {
		return nil, errSecureDecrypt
	}
	c.recvSeq = seq
	c.hasRecv = true
	return plain, nil
}

// outerTypeFor maps an inner message type to the visible envelope type.
// file/dir/req_pending → enc_file; proxy_* → enc_proxy; else enc_term.
func outerTypeFor(innerType string) string {
	if strings.HasPrefix(innerType, "file_") || strings.HasPrefix(innerType, "dir_") ||
		innerType == TypeFileList || innerType == TypeReqPending {
		return TypeEncFile
	}
	if strings.HasPrefix(innerType, "proxy_") {
		return TypeEncProxy
	}
	return TypeEncTerm
}

// isEncryptedType reports whether a type is an outer encrypted envelope.
func isEncryptedType(t string) bool {
	return t == TypeEncTerm || t == TypeEncFile || t == TypeEncProxy
}

// plaintextExemptTypes — these messages are never wrapped, even while the
// secure channel is active. Handshake and relay-control messages must stay
// plaintext so the relay can still route them and the security code is never
// exposed. session_info stays plaintext because it is the pre-handshake
// trigger (it advertises sec_code_required).
var plaintextExemptTypes = map[string]bool{
	// E2E handshake
	TypePakeStart: true, TypePakeReply: true, TypeSecConfirm: true,
	TypeSecOK: true, TypeSecureReady: true, TypeSecStatus: true,
	// security code (legacy plaintext path + handshake failure feedback)
	TypeSecCodeVerify: true, TypeSecCodeOK: true, TypeSecCodeError: true,
	// transport / signaling / relay-generated
	TypeChannelSelect: true, TypeChannelSelected: true, TypeChannelFailed: true,
	TypePeerOnline: true, TypePeerOffline: true, TypeKicked: true,
	TypePing: true, TypePong: true,
	// pre-handshake trigger
	TypeSessionInfo: true,
}

// isPlaintextExempt reports whether a message type must stay unencrypted.
func isPlaintextExempt(t string) bool { return plaintextExemptTypes[t] }
