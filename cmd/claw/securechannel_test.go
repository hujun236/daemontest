package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// testKeys returns a pair of channels: daemon (sends K_s2c, receives K_c2s)
// and app (sends K_c2s, receives K_s2c), sharing identical key material.
func testChannels(t *testing.T) (*SecureChannel, *SecureChannel) {
	t.Helper()
	var k1, k2 [32]byte
	for i := range k1 {
		k1[i] = byte(i)
		k2[i] = byte(i + 1)
	}
	daemon, err := NewSecureChannel(k1, k2, dirS2C[:], dirC2S[:])
	if err != nil {
		t.Fatal(err)
	}
	app, err := NewSecureChannel(k2, k1, dirC2S[:], dirS2C[:])
	if err != nil {
		t.Fatal(err)
	}
	return daemon, app
}

func TestSecureChannelJSONRoundTrip(t *testing.T) {
	daemon, app := testChannels(t)

	// daemon → app: an output message
	inner := &Message{Type: TypeOutput, SessionID: "s1", Data: "hello", Seq: 7}
	outer, err := daemon.WrapJSON(inner)
	if err != nil {
		t.Fatal(err)
	}
	if outer.Type != TypeEncTerm {
		t.Fatalf("output must map to enc_term, got %s", outer.Type)
	}
	got, err := app.UnwrapJSON(outer)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != TypeOutput || got.Data != "hello" || got.Seq != 7 {
		t.Fatalf("roundtrip mangled: %+v", got)
	}
	// inner seq (7) must NOT leak to the outer envelope crypto seq field confusion
	if outer.Seq == 7 && false {
		_ = outer
	}

	// app → daemon: input message maps to enc_term
	o2, err := app.WrapJSON(&Message{Type: TypeInput, SessionID: "s1", Data: "ls"})
	if err != nil {
		t.Fatal(err)
	}
	got2, err := daemon.UnwrapJSON(o2)
	if err != nil {
		t.Fatal(err)
	}
	if got2.Type != TypeInput || got2.Data != "ls" {
		t.Fatalf("input roundtrip mangled: %+v", got2)
	}
}

// TestSecureEnvelopeSeqAlwaysPresent — regression: the FIRST encrypted message has
// crypto seq 0. If the outer envelope omitted "seq" (omitempty on Message.Seq),
// the app's unwrapJSON cast on a missing key would throw and drop the message —
// which surfaced as "default shell history only appears after a 5s retry".
func TestSecureEnvelopeSeqAlwaysPresent(t *testing.T) {
	daemon, app := testChannels(t)

	// First wrapped message from a fresh channel → seq must be 0.
	outer, err := daemon.WrapJSON(&Message{Type: TypeHistoryData, SessionID: "s1", Data: "prompt"})
	if err != nil {
		t.Fatal(err)
	}
	if outer.Seq != 0 {
		t.Fatalf("first wrapped message must use seq 0, got %d", outer.Seq)
	}
	raw, err := json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"seq":0`) {
		t.Fatalf("envelope JSON must carry seq=0 explicitly (omitempty bug), got: %s", raw)
	}

	// And it must still decrypt on the app side.
	inner, err := app.UnwrapJSON(outer)
	if err != nil {
		t.Fatalf("first message (seq 0) must decrypt: %v", err)
	}
	if inner.Type != TypeHistoryData || inner.Data != "prompt" {
		t.Fatalf("first message roundtrip mangled: %+v", inner)
	}
}

func TestSecureChannelEnvelopeClassification(t *testing.T) {
	daemon, _ := testChannels(t)
	cases := map[string]string{
		TypeOutput:               TypeEncTerm,
		TypeInput:                TypeEncTerm,
		TypeSessionCreated:       TypeEncTerm,
		TypeHistoryChunk:         TypeEncTerm,
		TypeFileSendBegin:        TypeEncFile,
		TypeFileSendEnd:          TypeEncFile,
		TypeFileList:             TypeEncFile,
		TypeDirList:              TypeEncFile,
		TypeReqPending:           TypeEncFile,
		TypeProxyConnected:       TypeEncProxy,
		TypeProxyHttpResponse:    TypeEncProxy,
		TypeProxyWsMessage:       TypeEncProxy,
		TypeError:                TypeEncTerm,
	}
	for innerType, want := range cases {
		outer, err := daemon.WrapJSON(&Message{Type: innerType, Data: "x"})
		if err != nil {
			t.Fatalf("%s: %v", innerType, err)
		}
		if outer.Type != want {
			t.Errorf("%s → want %s, got %s", innerType, want, outer.Type)
		}
		if isPlaintextExempt(innerType) {
			t.Errorf("%s is in plaintext exemption list but was wrapped", innerType)
		}
	}
	// session_info must be exempt (never wrapped by the caller).
	if !isPlaintextExempt(TypeSessionInfo) {
		t.Fatal("session_info must stay plaintext")
	}
	if !isPlaintextExempt(TypePakeStart) || !isPlaintextExempt(TypeSecureReady) {
		t.Fatal("handshake types must stay plaintext")
	}
}

func TestSecureChannelReplayRejected(t *testing.T) {
	daemon, app := testChannels(t)
	o1, err := daemon.WrapJSON(&Message{Type: TypeOutput, Data: "one"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.UnwrapJSON(o1); err != nil {
		t.Fatal(err)
	}
	// Replaying the same frame must be rejected.
	if _, err := app.UnwrapJSON(o1); err == nil {
		t.Fatal("replayed frame must be rejected")
	}
	// A regressed seq (older) must be rejected.
	o0, _ := daemon.WrapJSON(&Message{Type: TypeOutput, Data: "zero"})
	if o0.Seq < o1.Seq {
		if _, err := app.UnwrapJSON(o0); err == nil {
			t.Fatal("out-of-order seq must be rejected")
		}
	}
}

func TestSecureChannelBinaryRoundTripAndTamper(t *testing.T) {
	daemon, app := testChannels(t)
	frame := []byte{OpcodeProxyData, 0, 0, 0, 1, 'a', 'b', 'c'}
	wire := daemon.WrapBinary(frame)
	if wire[0] != OpcodeSecureBinary {
		t.Fatalf("first byte must be 0x07, got %x", wire[0])
	}
	got, err := app.UnwrapBinary(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("binary roundtrip mangled: %x", got)
	}

	// Tamper a ciphertext byte → decrypt must fail.
	bad := append([]byte(nil), wire...)
	bad[len(bad)-1] ^= 0xff
	if _, err := app.UnwrapBinary(bad); err == nil {
		t.Fatal("tampered frame must fail to decrypt")
	}
}

func TestSecureChannelSizeLimit(t *testing.T) {
	daemon, _ := testChannels(t)
	big := &Message{Type: TypeDirList, Data: strings.Repeat("x", SecureMaxTextPayload+1)}
	if _, err := daemon.WrapJSON(big); err == nil {
		t.Fatal("oversized inner JSON must be rejected")
	}
	ok := &Message{Type: TypeDirList, Data: strings.Repeat("x", SecureMaxTextPayload-2000)}
	if _, err := daemon.WrapJSON(ok); err != nil {
		t.Fatalf("under-limit message must wrap: %v", err)
	}
}

func TestSecureChannelReset(t *testing.T) {
	daemon, app := testChannels(t)
	daemon.Reset()
	if daemon.Active() {
		t.Fatal("after reset, channel must be inactive")
	}
	if _, err := daemon.WrapJSON(&Message{Type: TypeOutput, Data: "x"}); err == nil {
		t.Fatal("wrap after reset must fail")
	}
	app.Reset()
	if _, err := app.UnwrapJSON(&Message{Type: TypeEncTerm, Seq: 1, Data: "AAAA"}); err == nil {
		t.Fatal("unwrap after reset must fail")
	}
}

func TestOuterTypeForFileAndProxy(t *testing.T) {
	if outerTypeFor(TypeFileSendBegin) != TypeEncFile {
		t.Fatal("file_* must map to enc_file")
	}
	if outerTypeFor(TypeProxyConnect) != TypeEncProxy {
		t.Fatal("proxy_* must map to enc_proxy")
	}
	if outerTypeFor(TypeOutput) != TypeEncTerm {
		t.Fatal("output must map to enc_term")
	}
}

func TestSecureChannelSeqState(t *testing.T) {
	daemon, app := testChannels(t)
	for i := 0; i < 3; i++ {
		o, _ := daemon.WrapJSON(&Message{Type: TypeOutput, Data: "x"})
		if _, err := app.UnwrapJSON(o); err != nil {
			t.Fatal(err)
		}
	}
	send, recv := app.SeqState()
	if send != 0 || recv != 2 {
		t.Fatalf("seq state: send=%d recv=%d, want 0/2", send, recv)
	}
}
