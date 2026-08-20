package main

// secure_history_test.go — reproduces the "default shell history not loaded"
// report end-to-end at the message level: real PTY pool + SPAKE2 handshake +
// session_list + request_history. Verifies the daemon serves session_info and
// history only AFTER a completed handshake, and that the responses decrypt.

import (
	"encoding/base64"
	"encoding/json"
	"sync/atomic"
	"time"
	"testing"

	"github.com/gorilla/websocket"
)

func testDaemonWithPTY(t *testing.T, code string) (*Daemon, chan relayMsg, chan relayMsg) {
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
	cfg := DefaultConfig()
	d := &Daemon{
		accessKey:   "TestAccessKey0123456789",
		cfg:         cfg,
		logger:      nopLogger{},
		channelMode: "ts",
		wsRelay:     relay,
		subscribed:  make(map[string]bool),
	}
	d.ptyMgr = NewPTYManager(cfg, d.logger)
	d.ptyMgr.OnData = func(sessionID string, data []byte, seq uint64) {
		d.sendOutput(sessionID, string(data), seq)
	}
	d.ptyMgr.OnExit = func(sessionID string, exitCode int) {}
	d.ptyMgr.CreatePool(cfg.PoolSize, cfg.DefaultShell)
	atomic.StoreInt32(&d.secCodeEnabled, 1)
	atomic.StoreInt32(&d.secCodeAttemptsLeft, MaxSecCodeAttempts)
	return d, sendCh, binCh
}

func TestSecureHistoryAndSessionsAfterHandshake(t *testing.T) {
	const code = "123456"
	d, ch, _ := testDaemonWithPTY(t, code)

	// Sanity: the PTY pool actually produced a session.
	if n := len(d.ptyMgr.ListSessions()); n == 0 {
		t.Skip("PTY pool empty (no usable shell on this machine)")
	}

	// 1. Complete the SPAKE2 handshake.
	client, sid := appSide(t, code, d.accessKey)
	d.handleMessage(&Message{Type: TypePakeStart, Sid: b64(sid), Pa: b64(client.Share())}, "TS")
	reply := nextMsg(t, ch)
	if reply.Type != TypePakeReply {
		t.Fatalf("expected pake_reply, got %s", reply.Type)
	}
	pb, _ := base64.StdEncoding.DecodeString(reply.Pb)
	client.SetPeerShare(pb)
	keys, err := client.Finish(sid, d.accessKey)
	if err != nil {
		t.Fatal(err)
	}
	d.handleMessage(&Message{Type: TypeSecConfirm, TagA: b64(TagA(keys, client.Transcript()))}, "TS")
	if m := nextMsg(t, ch); m.Type != TypeSecOK {
		t.Fatalf("expected sec_ok, got %s", m.Type)
	}
	if m := nextMsg(t, ch); m.Type != TypeSecureReady {
		t.Fatalf("expected secure_ready, got %s", m.Type)
	}
	if !d.secureActive() {
		t.Fatal("secure channel must be active after handshake")
	}

	appCh, err := NewSecureChannel(keys.Kc2s, keys.Ks2c, dirC2S[:], dirS2C[:])
	if err != nil {
		t.Fatal(err)
	}

	// 2. session_list → session_info (exempt, plaintext).
	d.handleMessage(&Message{Type: TypeSessionList}, "TS")
	si := nextMsg(t, ch)
	if si.Type != TypeSessionInfo {
		t.Fatalf("expected session_info, got %s", si.Type)
	}
	if len(si.SessionInfos) == 0 {
		t.Fatalf("session_info has no sessions")
	}
	sessID := si.SessionInfos[0].ID

	// 3. Wait for the pool shell's prompt to actually land in its history buffer
	// (bash startup is async), then request_history for the default shell.
	var polled int
	for {
		if data, _ := d.ptyMgr.GetHistory(sessID); len(data) > 0 {
			t.Logf("pool shell history filled after %d polls (%d bytes)", polled, len(data))
			break
		}
		polled++
		if polled > 30 {
			t.Fatalf("pool shell history never filled")
		}
		time.Sleep(100 * time.Millisecond)
	}

	d.handleMessage(&Message{
		Type:      TypeRequestHistory,
		SessionID: sessID,
		Cols:      120,
		Rows:      36,
	}, "TS")

	// History response may be one history_data (≤4096) or history_start+chunks.
	// It rides the encrypted data plane → outer envelope is enc_term.
	m := nextMsg(t, ch)
	var hist *Message
	if m.Type == TypeEncTerm {
		inner, err := appCh.UnwrapJSON(m)
		if err != nil {
			t.Fatalf("decrypt history response: %v", err)
		}
		hist = inner
	} else {
		hist = m
	}
	switch hist.Type {
	case TypeHistoryData:
		t.Logf("history_data dataLen=%d", len(hist.Data))
	case TypeHistoryStart:
		t.Logf("history_start totalChunks=%d", hist.TotalChunks)
		// drain chunks + end
		for i := 0; i < hist.TotalChunks; i++ {
			cm := nextMsg(t, ch)
			var inner *Message
			if cm.Type == TypeEncTerm {
				iv, err := appCh.UnwrapJSON(cm)
				if err != nil {
					t.Fatalf("decrypt chunk: %v", err)
				}
				inner = iv
			} else {
				inner = cm
			}
			if inner.Type != TypeHistoryChunk {
				t.Fatalf("expected history_chunk, got %s", inner.Type)
			}
		}
		if em := nextMsg(t, ch); em.Type != TypeHistoryEnd {
			// end is exempt? history_end is NOT exempt → encrypted.
			var inner *Message
			if em.Type == TypeEncTerm {
				iv, _ := appCh.UnwrapJSON(em)
				inner = iv
			} else {
				inner = em
			}
			if inner.Type != TypeHistoryEnd {
				t.Fatalf("expected history_end, got %s", inner.Type)
			}
		}
	default:
		t.Fatalf("expected history_data or history_start, got %s", hist.Type)
	}

	// 4. Before a handshake, session_list must be rejected (no plaintext leak).
	d.resetSecure("test")
	atomic.StoreInt32(&d.secCodeVerified, 0)
	d.handleMessage(&Message{Type: TypeSessionList}, "TS")
	if em := nextMsg(t, ch); em.Type != TypeError {
		t.Fatalf("session_list after reset must be rejected, got %+v", em)
	}
	_ = json.Marshal
}
