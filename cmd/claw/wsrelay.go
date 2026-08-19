package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// LoginError login failure error (should not reconnect)
type LoginError struct {
	Msg string
}

func (e *LoginError) Error() string {
	return e.Msg
}

// IPBlockedError IP is temporarily blocked by TurnServer (retry with long backoff)
type IPBlockedError struct {
	Msg string
}

func (e *IPBlockedError) Error() string {
	return e.Msg
}

// relayMsg forwarded message with message type
type relayMsg struct {
	data    []byte
	msgType int // websocket.TextMessage or websocket.BinaryMessage
}

// WSTurnRelay WebSocket TURN relay client
type WSTurnRelay struct {
	accessKey string
	cfg       *Config
	logger    Logger

	mu        sync.RWMutex
	conn      *websocket.Conn
	connected bool
	sendCh    chan relayMsg // text message channel (terminal I/O, control messages)
	binaryCh  chan relayMsg // binary message channel (file chunks)
	closeCh   chan struct{}
	once      sync.Once
	missedPongs int32 // number of consecutive missed pongs

	OnMessage       func(msg *Message)
	OnBinaryMessage func(data []byte) // binary message callback
	OnP2PSignal     func(msg map[string]any)
}

// NewWSTurnRelay create WebSocket TURN client
func NewWSTurnRelay(accessKey string, cfg *Config, logger Logger) *WSTurnRelay {
	return &WSTurnRelay{
		accessKey: accessKey,
		cfg:      cfg,
		logger:   logger,
		sendCh:   make(chan relayMsg, 16),
		binaryCh: make(chan relayMsg, 16),
		closeCh:  make(chan struct{}),
	}
}

// Connect connect directly to TurnServer WebSocket, send login, block until login_ok or timeout
func (w *WSTurnRelay) Connect(url string) error {

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		NetDial: func(network, addr string) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetNoDelay(true)
			}
			return c, nil
		},
	}
	header := http.Header{}
	header.Set("User-Agent", "CliAnyWhere/daemon")
	header.Set("Cookie", "fromapp=clianywhere")
	conn, _, err := dialer.Dial(url+"?role=daemon", header)
	if err != nil {
		return fmt.Errorf("WebSocket connection failed: %w", err)
	}

	// send login
	loginMsg, _ := json.Marshal(map[string]any{
		"type":      "login",
		"accesskey": w.accessKey,
		"version":   Version,
	})
	if err := conn.WriteMessage(websocket.TextMessage, loginMsg); err != nil {
		conn.Close()
		return fmt.Errorf("send login failed: %w", err)
	}

	// wait for login_ok (10s timeout)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, message, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return fmt.Errorf("wait for login_ok failed: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	var resp map[string]any
	if err := json.Unmarshal(message, &resp); err != nil {
		conn.Close()
		return fmt.Errorf("parse login response failed: %w", err)
	}

	// Fatal flag handling — TS attaches fatal:true to any permanent,
	// non-retryable error (currently: accesskey not found in globalserver;
	// future fatal cases can reuse the same flag). On fatal:true the daemon
	// stops the reconnect loop without exiting the process, so the user can
	// switch to a valid accesskey and retry without restarting the daemon.
	if fatal, _ := resp["fatal"].(bool); fatal {
		conn.Close()
		msg, _ := resp["msg"].(string)
		return &LoginError{Msg: fmt.Sprintf("login rejected (fatal): %v", msg)}
	}

	// IP blocked by TurnServer (same-day ban, resets next day):
	// caller uses a long backoff to avoid wasteful polling.
	if resp["type"] == "login_error" {
		msg, _ := resp["msg"].(string)
		if strings.HasPrefix(msg, "IP blocked") {
			conn.Close()
			return &IPBlockedError{Msg: fmt.Sprintf("login rejected: %v", resp["msg"])}
		}
		conn.Close()
		return fmt.Errorf("login rejected (will retry): %v", resp["msg"])
	}

	if resp["type"] != "login_ok" {
		conn.Close()
		return fmt.Errorf("unexpected response (will retry): %s", string(message))
	}

	w.mu.Lock()
	w.conn = conn
	w.connected = true
	w.mu.Unlock()

	atomic.StoreInt32(&w.missedPongs, 0)

	// start read/write goroutines
	go w.writeLoop()
	go w.readLoop()
	go w.pingLoop()

	return nil
}

// SendRaw send raw JSON bytes (text frame)
// NOTE: only take a conn snapshot inside the RLock — never hold the lock while
// parking on the sendCh send. Holding RLock across a full-channel send together
// with writeMsg's exclusive Lock forms a deadlock cycle (handler holds RLock
// waiting for writeLoop to drain; writeLoop waits for Lock) that permanently
// wedges the relay when the TCP link dies silently.
func (w *WSTurnRelay) SendRaw(data []byte) {
	w.mu.RLock()
	conn := w.conn
	connected := w.connected
	w.mu.RUnlock()

	if conn == nil || !connected {
		return
	}
	select {
	case w.sendCh <- relayMsg{data: data, msgType: websocket.TextMessage}:
	case <-w.closeCh:
	}
}

// SendBinaryBlocking blocking send binary data (for file chunks), via binaryCh independent channel
func (w *WSTurnRelay) SendBinaryBlocking(data []byte) {
	w.mu.RLock()
	connected := w.connected
	w.mu.RUnlock()

	if !connected {
		return
	}

	select {
	case w.binaryCh <- relayMsg{data: data, msgType: websocket.BinaryMessage}:
	case <-w.closeCh:
	}
}

// SendBinaryCancelable cancellable blocking send, returns false immediately when cancel is closed
func (w *WSTurnRelay) SendBinaryCancelable(data []byte, cancel <-chan struct{}) bool {
	w.mu.RLock()
	connected := w.connected
	w.mu.RUnlock()

	if !connected {
		return false
	}

	select {
	case w.binaryCh <- relayMsg{data: data, msgType: websocket.BinaryMessage}:
		return true
	case <-w.closeCh:
		return false
	case <-cancel:
		return false
	}
}

// SendBinary send binary data (binary frame)
func (w *WSTurnRelay) SendBinary(data []byte) {
	w.SendBinaryBlocking(data)
}

// SendJSON send JSON message via WebSocket (via sendCh text channel)
// Same rule as SendRaw: no lock held while parking on the channel send.
func (w *WSTurnRelay) SendJSON(msg *Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	w.mu.RLock()
	conn := w.conn
	connected := w.connected
	w.mu.RUnlock()

	if conn == nil || !connected {
		return
	}
	select {
	case w.sendCh <- relayMsg{data: data, msgType: websocket.TextMessage}:
	case <-w.closeCh:
	}
}

// Close close connection
func (w *WSTurnRelay) Close() {
	w.once.Do(func() {
		close(w.closeCh)
		w.mu.Lock()
		if w.conn != nil {
			w.conn.Close()
		}
		w.mu.Unlock()
	})
}

// Done return a channel that is closed when connection closes
func (w *WSTurnRelay) Done() <-chan struct{} {
	return w.closeCh
}

// DrainSendCh wait until sendCh and binaryCh are both empty. Blocking.
// Used when switching from TS to P2P: drain all buffered text/binary messages
// before the caller decides what to do with the TS connection.
func (w *WSTurnRelay) DrainSendCh() {
	for {
		w.mu.RLock()
		sendLen := len(w.sendCh)
		binaryLen := len(w.binaryCh)
		w.mu.RUnlock()
		if sendLen == 0 && binaryLen == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Connected return whether connected
func (w *WSTurnRelay) Connected() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.connected
}

func (w *WSTurnRelay) readLoop() {
	defer func() {
		w.mu.Lock()
		w.connected = false
		w.mu.Unlock()
		w.Close()
	}()

	for {
		select {
		case <-w.closeCh:
			return
		default:
		}

		msgType, message, err := w.conn.ReadMessage()
		if err != nil {
			return
		}

		// binary messages passed directly to daemon (file chunk data)
		if msgType == websocket.BinaryMessage {
			if w.OnBinaryMessage != nil {
				w.OnBinaryMessage(message)
			}
			continue
		}

		// text message: parse type field first to determine message category
		var peek struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(message, &peek) != nil {
			continue
		}

		switch peek.Type {
		case "pong":
			atomic.StoreInt32(&w.missedPongs, 0)
			continue
		case "p2p_offer", "p2p_answer", "p2p_ice", "peer_online", "peer_offline":
			// P2P signaling message, pass raw map
			if w.OnP2PSignal != nil {
				var data map[string]any
				if json.Unmarshal(message, &data) == nil {
					w.OnP2PSignal(data)
				}
			}
		default:
			// terminal I/O message
			var m Message
			if err := json.Unmarshal(message, &m); err != nil {
				continue
			}
			if w.OnMessage != nil {
				w.OnMessage(&m)
			}
		}
	}
}

// writeLoop unified write loop, text messages (terminal I/O) prioritized over binary (file chunks)
func (w *WSTurnRelay) writeLoop() {
	for {
		// try to drain text messages first (high priority)
		select {
		case <-w.closeCh:
			return
		case msg := <-w.sendCh:
			w.writeMsg(msg)
			continue
		default:
		}

		// when no text messages, wait for any type
		select {
		case <-w.closeCh:
			return
		case msg := <-w.sendCh:
			w.writeMsg(msg)
		case msg := <-w.binaryCh:
			w.writeMsg(msg)
		}
	}
}

func (w *WSTurnRelay) writeMsg(msg relayMsg) {
	w.mu.Lock()
	conn := w.conn
	w.mu.Unlock()

	if conn == nil {
		return
	}
	// Write deadline: on a silently-dead link (no FIN/RST) writes into the
	// kernel send buffer "succeed" for a long time and nothing ever errors.
	// A deadline guarantees a stuck write fails within 10s, triggering
	// Close() → closeCh → every goroutine parked on sendCh unwinds and the
	// supervisor loop reconnects. Pings every 8s ensure outbound traffic is
	// always pending, so detection is bounded at ~18s.
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteMessage(msg.msgType, msg.data); err != nil {
		w.Close()
	}
}

// pingLoop send ping heartbeat to TurnServer every 8s, disconnect and reconnect after 3 consecutive missed pongs
func (w *WSTurnRelay) pingLoop() {
	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.closeCh:
			return
		case <-ticker.C:
			missed := atomic.LoadInt32(&w.missedPongs)
			if missed >= 3 {
				w.Close()
				return
			}

			w.mu.RLock()
			conn := w.conn
			connected := w.connected
			w.mu.RUnlock()

			if conn == nil || !connected {
				return
			}

			atomic.AddInt32(&w.missedPongs, 1)
			pingMsg, _ := json.Marshal(map[string]any{"type": "ping"})
			select {
			case w.sendCh <- relayMsg{data: pingMsg, msgType: websocket.TextMessage}:
			case <-w.closeCh:
				return
			}
		}
	}
}
