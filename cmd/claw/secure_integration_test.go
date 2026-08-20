package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
)

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}
func (nopLogger) Fatalf(string, ...any) {}
func (nopLogger) Writer() io.Writer     { return io.Discard }

// testDaemonHarness builds a minimal Daemon with a fake TS relay whose sendCh
// (text) and binaryCh (binary) we drain directly, isolating the security-code
// file under a temp $HOME.
func testDaemonHarness(t *testing.T, code string) (*Daemon, chan relayMsg, chan relayMsg) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if code != "" {
		if err := SaveSecurityCode(code); err != nil {
			t.Fatal(err)
		}
	}
	sendCh := make(chan relayMsg, 128)
	binCh := make(chan relayMsg, 128)
	relay := &WSTurnRelay{
		sendCh:    sendCh,
		binaryCh:  binCh,
		closeCh:   make(chan struct{}),
		connected: true,
		conn:      &websocket.Conn{},
	}
	d := &Daemon{
		accessKey:   "TestAccessKey0123456789",
		logger:      nopLogger{},
		channelMode: "ts",
		wsRelay:     relay,
		subscribed:  make(map[string]bool),
	}
	if code != "" {
		atomic.StoreInt32(&d.secCodeEnabled, 1)
	}
	atomic.StoreInt32(&d.secCodeAttemptsLeft, MaxSecCodeAttempts)
	return d, sendCh, binCh
}

// nextMsg pops and decodes the next outgoing daemon message.
func nextMsg(t *testing.T, ch chan relayMsg) *Message {
	t.Helper()
	select {
	case rm := <-ch:
		var m Message
		if err := json.Unmarshal(rm.data, &m); err != nil {
			t.Fatalf("decode daemon message: %v (%s)", err, rm.data)
		}
		return &m
	default:
		t.Fatal("expected a daemon message, none queued")
		return nil
	}
}

// appSide simulates the Flutter app's SPAKE2 client over the same wire.
func appSide(t *testing.T, code, accesskey string) (*Spake2State, []byte) {
	t.Helper()
	client, err := NewSpake2Client(scalarFromPassword(code))
	if err != nil {
		t.Fatal(err)
	}
	sid := []byte("app-side-sid-16B")
	return client, sid
}

func TestSecureHandshakeFullFlow(t *testing.T) {
	const code = "123456"
	d, ch, binCh := testDaemonHarness(t, code)

	client, sid := appSide(t, code, d.accessKey)

	// 1. pake_start
	d.handleMessage(&Message{
		Type: TypePakeStart,
		Sid:  base64.StdEncoding.EncodeToString(sid),
		Pa:   base64.StdEncoding.EncodeToString(client.Share()),
	}, "TS")

	reply := nextMsg(t, ch)
	if reply.Type != TypePakeReply {
		t.Fatalf("expected pake_reply, got %s", reply.Type)
	}
	pb, _ := base64.StdEncoding.DecodeString(reply.Pb)
	if err := client.SetPeerShare(pb); err != nil {
		t.Fatal(err)
	}
	keys, err := client.Finish(sid, d.accessKey)
	if err != nil {
		t.Fatal(err)
	}

	// 2. sec_confirm
	d.handleMessage(&Message{
		Type:  TypeSecConfirm,
		TagA:  base64.StdEncoding.EncodeToString(TagA(keys, client.Transcript())),
	}, "TS")

	okMsg := nextMsg(t, ch)
	if okMsg.Type != TypeSecOK {
		t.Fatalf("expected sec_ok, got %s", okMsg.Type)
	}
	readyMsg := nextMsg(t, ch)
	if readyMsg.Type != TypeSecureReady {
		t.Fatalf("expected secure_ready, got %s", readyMsg.Type)
	}
	if !d.secureActive() {
		t.Fatal("daemon secure channel must be active after handshake")
	}
	if atomic.LoadInt32(&d.secCodeVerified) != 1 {
		t.Fatal("secCodeVerified must be set by PAKE success")
	}

	// 3. daemon → app: output gets encrypted into enc_term
	appCh, err := NewSecureChannel(keys.Kc2s, keys.Ks2c, dirC2S[:], dirS2C[:])
	if err != nil {
		t.Fatal(err)
	}
	d.sendJSON(&Message{Type: TypeOutput, SessionID: "s1", Data: "hello encrypted", Seq: 42})
	outMsg := nextMsg(t, ch)
	if outMsg.Type != TypeEncTerm {
		t.Fatalf("output must be wrapped as enc_term, got %s", outMsg.Type)
	}
	inner, err := appCh.UnwrapJSON(outMsg)
	if err != nil {
		t.Fatalf("app decrypt: %v", err)
	}
	if inner.Type != TypeOutput || inner.Data != "hello encrypted" || inner.Seq != 42 {
		t.Fatalf("inner mangled: %+v", inner)
	}

	// 4. app → daemon: input encrypted, daemon unwraps and dispatches.
	// TypeInput would touch ptyMgr (nil here) — use a nil-safe type to verify
	// the unwrap+dispatch path without a real PTY.
	wrappedCancel, err := appCh.WrapJSON(&Message{Type: TypeFileSendCancel, FileID: 7})
	if err != nil {
		t.Fatal(err)
	}
	d.handleMessage(wrappedCancel, "TS") // must not panic; unwrapped & dispatched to nil-safe handler

	// 5. binary roundtrip through the daemon funnels
	daemonFrame := []byte{OpcodeFileTransfer, 0, 0, 0, 1, 0, 0, 0, 0, 'd', 'a', 't', 'a'}
	d.sendBytes(daemonFrame)
	binMsg := <-binCh
	if binMsg.msgType != 2 { // websocket.BinaryMessage
		t.Fatalf("expected binary frame, got type %d", binMsg.msgType)
	}
	binPlain, err := appCh.UnwrapBinary(binMsg.data)
	if err != nil {
		t.Fatalf("app binary decrypt: %v", err)
	}
	if string(binPlain) != string(daemonFrame) {
		t.Fatal("binary roundtrip mangled")
	}

	// 6. handshake/control messages stay plaintext even while secure
	d.sendJSON(&Message{Type: TypeChannelSelected, Data: "ts"})
	ctrl := nextMsg(t, ch)
	if ctrl.Type != TypeChannelSelected {
		t.Fatalf("channel_selected must pass through plaintext, got %s", ctrl.Type)
	}
	d.sendJSON(&Message{Type: TypeSessionInfo})
	si := nextMsg(t, ch)
	if si.Type != TypeSessionInfo {
		t.Fatalf("session_info must stay plaintext, got %s", si.Type)
	}
}

func TestSecureHandshakeWrongCode(t *testing.T) {
	d, ch, _ := testDaemonHarness(t, "123456")

	client, sid := appSide(t, "654321", d.accessKey) // wrong code on the app side
	d.handleMessage(&Message{
		Type: TypePakeStart,
		Sid:  base64.StdEncoding.EncodeToString(sid),
		Pa:   base64.StdEncoding.EncodeToString(client.Share()),
	}, "TS")
	reply := nextMsg(t, ch)
	if reply.Type != TypePakeReply {
		t.Fatalf("expected pake_reply, got %s", reply.Type)
	}
	pb, _ := base64.StdEncoding.DecodeString(reply.Pb)
	client.SetPeerShare(pb)
	keys, _ := client.Finish(sid, d.accessKey)

	before := atomic.LoadInt32(&d.secCodeAttemptsLeft)
	d.handleMessage(&Message{
		Type: TypeSecConfirm,
		TagA: base64.StdEncoding.EncodeToString(TagA(keys, client.Transcript())),
	}, "TS")

	errMsg := nextMsg(t, ch)
	if errMsg.Type != TypeSecCodeError {
		t.Fatalf("expected sec_code_error, got %s", errMsg.Type)
	}
	after := atomic.LoadInt32(&d.secCodeAttemptsLeft)
	if after != before-1 {
		t.Fatalf("attempt budget must decrement: %d → %d", before, after)
	}
	if d.secureActive() {
		t.Fatal("secure channel must NOT be active after wrong code")
	}
}

func TestSecureForcedEncryptionNoCode(t *testing.T) {
	// Forced encryption: even a daemon WITHOUT a real security code completes
	// the handshake using the public default (000000) and then encrypts.
	d, ch, binCh := testDaemonHarness(t, "") // no security code

	client, sid := appSide(t, defaultSecCode, d.accessKey)
	d.handleMessage(&Message{
		Type: TypePakeStart,
		Sid:  base64.StdEncoding.EncodeToString(sid),
		Pa:   base64.StdEncoding.EncodeToString(client.Share()),
	}, "TS")

	reply := nextMsg(t, ch)
	if reply.Type != TypePakeReply {
		t.Fatalf("no-code daemon must answer pake_start with the default code, got %s", reply.Type)
	}
	pb, _ := base64.StdEncoding.DecodeString(reply.Pb)
	client.SetPeerShare(pb)
	keys, err := client.Finish(sid, d.accessKey)
	if err != nil {
		t.Fatal(err)
	}
	d.handleMessage(&Message{Type: TypeSecConfirm, TagA: base64.StdEncoding.EncodeToString(TagA(keys, client.Transcript()))}, "TS")
	if ok := nextMsg(t, ch); ok.Type != TypeSecOK {
		t.Fatalf("expected sec_ok, got %s", ok.Type)
	}
	if ready := nextMsg(t, ch); ready.Type != TypeSecureReady {
		t.Fatalf("expected secure_ready, got %s", ready.Type)
	}
	if !d.secureActive() {
		t.Fatal("no-code daemon must still have an active secure channel")
	}

	// Data must be encrypted, not plaintext.
	appCh, _ := NewSecureChannel(keys.Kc2s, keys.Ks2c, dirC2S[:], dirS2C[:])
	d.sendJSON(&Message{Type: TypeOutput, Data: "encrypted even without a code"})
	out := nextMsg(t, ch)
	if out.Type != TypeEncTerm {
		t.Fatalf("expected enc_term envelope, got %s", out.Type)
	}
	inner, err := appCh.UnwrapJSON(out)
	if err != nil || inner.Data != "encrypted even without a code" {
		t.Fatalf("decrypt failed: %v", err)
	}
	_ = binCh
}

func TestSecureResetDropsStale(t *testing.T) {
	const code = "123456"
	d, ch, _ := testDaemonHarness(t, code)

	// complete a handshake quickly
	client, sid := appSide(t, code, d.accessKey)
	d.handleMessage(&Message{Type: TypePakeStart, Sid: b64(sid), Pa: b64(client.Share())}, "TS")
	reply := nextMsg(t, ch)
	pb, _ := base64.StdEncoding.DecodeString(reply.Pb)
	client.SetPeerShare(pb)
	keys, _ := client.Finish(sid, d.accessKey)
	d.handleMessage(&Message{Type: TypeSecConfirm, TagA: b64(TagA(keys, client.Transcript()))}, "TS")
	nextMsg(t, ch) // sec_ok
	nextMsg(t, ch) // secure_ready

	appCh, _ := NewSecureChannel(keys.Kc2s, keys.Ks2c, dirC2S[:], dirS2C[:])

	// Peer offline → reset.
	d.resetSecure("test")
	if d.secureActive() {
		t.Fatal("channel must be inactive after reset")
	}
	// A stale encrypted frame arriving after reset must be dropped, not dispatched.
	stale, _ := appCh.WrapJSON(&Message{Type: TypeFileSendCancel, FileID: 1})
	d.handleMessage(stale, "TS")
	select {
	case m := <-ch:
		t.Fatalf("stale encrypted frame must be dropped, but daemon responded %s", m.data)
	default:
	}
}

// TestSecureContentGatedBeforeHandshake: before the SPAKE2 handshake completes,
// the daemon must NOT serve any session content (session_list / history /
// file / proxy) — forced encryption means an unverified connection gets
// "Security code required", never plaintext content.
func TestSecureContentGatedBeforeHandshake(t *testing.T) {
	d, ch, _ := testDaemonHarness(t, "123456")

	// No handshake performed. session_list must be rejected.
	d.handleMessage(&Message{Type: TypeSessionList}, "TS")
	errMsg := nextMsg(t, ch)
	if errMsg.Type != TypeError || errMsg.Error != "Security code required" {
		t.Fatalf("session_list before handshake must be rejected, got %+v", errMsg)
	}

	// request_history must be rejected too.
	d.handleMessage(&Message{Type: TypeRequestHistory, SessionID: "s1"}, "TS")
	errMsg2 := nextMsg(t, ch)
	if errMsg2.Type != TypeError || errMsg2.Error != "Security code required" {
		t.Fatalf("request_history before handshake must be rejected, got %+v", errMsg2)
	}

	// File/proxy requests must be rejected.
	d.handleMessage(&Message{Type: TypeDirListRequest, Data: "/"}, "TS")
	if m := nextMsg(t, ch); m.Type != TypeError {
		t.Fatalf("dir_list_request before handshake must be rejected, got %+v", m)
	}
	d.handleMessage(&Message{Type: TypeProxyHttpFetch, SessionID: "p1"}, "TS")
	if m := nextMsg(t, ch); m.Type != TypeError {
		t.Fatalf("proxy_http_fetch before handshake must be rejected, got %+v", m)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
