package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v3"
)

// Daemon main daemon process — coordinates PTY management and single-channel communication (WebRTC P2P or TS WebSocket, one at a time)
// channelMode empty string defaults to TS (compat), browser explicitly selects channel via channel_select message
type Daemon struct {
	accessKey string
	cfg       *Config
	logger    Logger
	ptyMgr    *PTYManager

	rtc   *WebRTCConn
	rtcMu sync.RWMutex

	// Trickle ICE: buffer ICE candidates that arrive before rtc is created
	pendingICE     []map[string]any
	pendingICEMode bool // true means buffering (startP2PAsAnswerer in progress)

	wsRelay *WSTurnRelay
	wsMu    sync.RWMutex

	channelMode string // "p2p" or "ts", empty string means not selected (defaults to TS)
	channelMu   sync.RWMutex

	// cached public IP, fallback when STUN fails
	cachedPublicIP string
	publicIPMu     sync.RWMutex

	// mutual-kick flag: set to 1 when kicked is received, blocks ongoing P2P establishment
	kicked int32

	// security code: enabled flag and per-connection verification state
	// secCodeEnabled: 1=code file exists, 0=no code set (updated on save/clear, no file IO in hot path)
	// secCodeVerified: 1=current app has verified, 0=not yet (reset on peer_online/p2p_offer/code change)
	// secCodeAttemptsLeft: failed verify budget for the entire daemon lifetime — once it hits 0
	//   the daemon exits. NOT reset on new connections, code change, or successful verify.
	//   Only initialized once in Init() (daemon restart resets it).
	secCodeEnabled       int32
	secCodeVerified      int32
	secCodeAttemptsLeft  int32

	// E2E secure channel (SPAKE2 + AES-GCM). secure is nil until a handshake
	// completes; the single-slot handshake fields track one in-progress SPAKE2
	// server exchange (a new pake_start overwrites any previous one).
	secure       *SecureChannel
	secureMu     sync.Mutex
	pakeServer   *Spake2State
	pakeSid      []byte
	pakeAccessKey string
	pakeTimer    *time.Timer

	// set of sessions subscribed by frontend: only sessions that went through request_history receive real-time output
	subscribed map[string]bool
	subMu      sync.RWMutex

	// file transfer
	fileTransfer *FileTransferManager

	// HTTP proxy tunnel
	proxyManager *ProxyManager

	ipcServer *http.Server

	// connection state notification (for GUI; CLI version uses nil, no impact)
	OnStateChange func(state string) // "stopped", "connecting", "connected"

	// connection state (atomic, for status command query)
	connState atomic.Value // string: "stopped", "connecting", "connected"

	// stop signal: Stop() closes this channel, startTSRelay exits loop on detection
	stopCh    chan struct{}
	stopOnce  sync.Once

	// TS relay loop lifecycle: per-loop cancel + done channel so that
	// replacing accesskey can synchronously stop the old loop before
	// starting a new one (otherwise two loops race on the same accesskey
	// and TurnServer's mutual-kick kills the daemon).
	tsMu         sync.Mutex
	tsLoopCancel context.CancelFunc
	tsLoopDone   chan struct{}

	// local WebSocket service (local attach)
	localServer *LocalServer
}

// NewDaemon create daemon instance
func NewDaemon(accessKey string, cfg *Config, logger Logger) *Daemon {
	return &Daemon{
		accessKey:  accessKey,
		cfg:        cfg,
		logger:     logger,
		subscribed: make(map[string]bool),
		stopCh:     make(chan struct{}),
	}
}

// Init initialize local resources (does not depend on accessKey, called once at startup)
// creates PTY pool, local WS, IPC and other local services, then daemon attach is available
func (d *Daemon) Init() {
	// 1. initialize PTY manager
	d.ptyMgr = NewPTYManager(d.cfg, d.logger)

	d.ptyMgr.OnData = func(sessionID string, data []byte, seq uint64) {
		d.sendOutput(sessionID, string(data), seq)
	}

	d.ptyMgr.OnExit = func(sessionID string, exitCode int) {
		d.subMu.Lock()
		delete(d.subscribed, sessionID)
		d.subMu.Unlock()

		d.sendJSON(&Message{
			Type:      TypeSessionExited,
			SessionID: sessionID,
			ExitCode:  exitCode,
		})
		d.replenishPool()
	}

	// 2. create initial session pool
	d.ptyMgr.CreatePool(d.cfg.PoolSize, d.cfg.DefaultShell)

	// 2.5 initialize secCodeEnabled from file
	if HasSecurityCode() {
		atomic.StoreInt32(&d.secCodeEnabled, 1)
	}
	atomic.StoreInt32(&d.secCodeAttemptsLeft, MaxSecCodeAttempts)

	// 3. initialize file transfer manager
	d.fileTransfer = NewFileTransferManager(d, d.logger)

	// 4. initialize HTTP proxy tunnel manager
	d.proxyManager = NewProxyManager(d, d.logger)

	// 5. start HTTP IPC server (for daemon send)
	d.startIPCServer()

	// 6. start local WebSocket service (for local attach)
	d.localServer = StartLocalServer(d, d.logger, nil)
}

// StartRemote start remote connection with accessKey (signaling + TS relay)
// can be called at any time after Init(), supports hot-connect (e.g. called after binding completes)
func (d *Daemon) StartRemote(accessKey string) {
	d.accessKey = accessKey

	// start TurnServer WebSocket connection (auto-selects best in background + auto-reconnect)
	d.startTSRelay()

}

// handleP2PSignal handle P2P signaling messages from TS WebSocket
func (d *Daemon) handleP2PSignal(raw map[string]any) {
	msgType, _ := raw["type"].(string)

	// forcets mode: silently discard P2P signaling, let frontend timeout and fallback
	if d.cfg.ForceTS {
		return
	}

	switch msgType {
	case "p2p_offer":
		sdpOffer, _ := raw["sdp"].(string)
		if sdpOffer == "" {
			return
		}
		// Take out the early ICE candidates buffered by handleP2PICE before
		// the offer arrived, and hand them to startP2PAsAnswerer for replay,
		// so they are not lost when the buffer is cleared.
		d.rtcMu.Lock()
		earlyICE := d.pendingICE
		d.pendingICE = nil
		d.pendingICEMode = true
		d.rtcMu.Unlock()
		go d.startP2PAsAnswerer(sdpOffer, earlyICE)

	case "peer_online":
		// New app connection: reset security-code verification state (per-connection)
		// Note: secCodeAttemptsLeft is NOT reset — it is a daemon-lifetime budget
		d.logger.Infof("[TS] peer_online: new app connection, resetting secCodeVerified")
		atomic.StoreInt32(&d.secCodeVerified, 0)
		// Keys are per-connection: a new peer must re-run the handshake.
		d.resetSecure("peer_online")

	case "peer_offline":
		d.handlePeerOffline()

	case "p2p_ice":
		d.handleP2PICE(raw)
	}
}

// startP2PAsAnswerer after receiving p2p_offer from browser, create WebRTC answerer.
// earlyICE holds the early candidates buffered by handleP2PICE before the offer arrived; they must be replayed together.
func (d *Daemon) startP2PAsAnswerer(sdpOffer string, earlyICE []map[string]any) {
	// new frontend sent p2p_offer, old connection is done, clearing kicked flag
	atomic.StoreInt32(&d.kicked, 0)
	// New app connection: reset security-code verification state
	// Note: secCodeAttemptsLeft is NOT reset — it is a daemon-lifetime budget
	atomic.StoreInt32(&d.secCodeVerified, 0)
	d.resetSecure("p2p_offer")

	// close old P2P connection
	d.CloseRTC()

	// Subscriptions and local controllers are intentionally NOT cleared here.
	// They are session-level / transport-independent and survive channel switches.

	// use WebRTCConn answerer mode
	rtc := NewWebRTCConn(d.accessKey, d.cfg, d.logger)

	// ICE candidates sent via TS WebSocket
	rtc.OnICECandidateFunc = func(candidate, sdpMid string, sdpMLineIndex int) {
		data, _ := json.Marshal(map[string]any{
			"type":            "p2p_ice",
			"candidate":       candidate,
			"sdp_mid":         sdpMid,
			"sdp_mline_index": sdpMLineIndex,
		})
		d.wsSendRaw(data)
	}

	// terminal I/O message callback
	rtc.OnMessage = func(msg *Message) {
		d.handleMessage(msg, "P2P")
	}

	// binary frame callback
	rtc.OnBinaryMessage = func(data []byte) {
		d.handleBinary(data)
	}

	// use multiple STUN servers to increase candidate diversity and improve P2P success rate
	iceServers := []webrtc.ICEServer{
		{URLs: []string{
			"stun:stun.qq.com:3478",
			"stun:stun.cloudflare.com:3478",
			"stun:stun.l.google.com:19302",
			"stun:stun1.l.google.com:19302",
		}},
	}

	// create answer
	answer, err := rtc.Answer(sdpOffer, iceServers)
	if err != nil {
		return
	}

	// send answer back to browser (via TS)
	d.wsSendRaw(map[string]any{
		"type":       "p2p_answer",
		"sdp_answer": answer,
	})

	// set rtc and replay buffered ICE candidates
	// Take the buffered slice inside the lock, then replay outside the lock
	// to avoid pion re-entry/deadlock via AddICECandidate callbacks.
	d.rtcMu.Lock()
	d.rtc = rtc
	buffered := d.pendingICE
	d.pendingICE = nil
	d.pendingICEMode = false
	d.rtcMu.Unlock()

	// First replay the early candidates buffered before the offer arrived,
	// then replay the candidates that arrived after the offer but before rtc was ready.
	for _, raw := range earlyICE {
		candidate, _ := raw["candidate"].(string)
		sdpMid, _ := raw["sdp_mid"].(string)
		sdpMLineIndex := 0
		if v, ok := raw["sdp_mline_index"].(float64); ok {
			sdpMLineIndex = int(v)
		}
		if candidate != "" {
			rtc.AddRemoteICE(candidate, sdpMid, sdpMLineIndex)
		}
	}
	// replay buffered candidates that arrived while rtc was nil
	for _, raw := range buffered {
		candidate, _ := raw["candidate"].(string)
		sdpMid, _ := raw["sdp_mid"].(string)
		sdpMLineIndex := 0
		if v, ok := raw["sdp_mline_index"].(float64); ok {
			sdpMLineIndex = int(v)
		}
		if candidate != "" {
			rtc.AddRemoteICE(candidate, sdpMid, sdpMLineIndex)
		}
	}

	// waiting for connection to establish (10s timeout)
	if err := rtc.WaitConnected(10 * time.Second); err != nil {
		rtc.Close()
		d.rtcMu.Lock()
		if d.rtc == rtc {
			d.rtc = nil
		}
		d.rtcMu.Unlock()
		return
	}


	// block until P2P disconnects
	rtc.WaitDisconnected()

	// P2P disconnected
	d.rtcMu.Lock()
	if d.rtc == rtc {
		d.rtc = nil
	} else {
		// d.rtc taken over by new connection, old goroutine does not interfere
		d.rtcMu.Unlock()
		rtc.Close()
		return
	}
	d.rtcMu.Unlock()

	// if current mode is p2p, notify browser channel is down
	d.channelMu.RLock()
	mode := d.channelMode
	d.channelMu.RUnlock()
	if mode == "p2p" {
		d.channelMu.Lock()
		d.channelMode = "" // reset, waiting for browser to re-select
		d.channelMu.Unlock()
		// notify browser via TS
		d.wsSendRaw(map[string]any{
			"type":    "channel_failed",
			"channel": "p2p",
		})
	}

	rtc.Close()

	// P2P disconnected, cancel all in-progress file transfers
	if d.fileTransfer != nil {
		d.fileTransfer.CancelAll()
	}
	if d.proxyManager != nil {
		d.proxyManager.CloseAll()
	}

	// clear subscriptions only if TS is not available as fallback.
	// If TS is still connected, app can fall back to it and subscriptions persist.
	d.wsMu.RLock()
	tsAlive := d.wsRelay != nil && d.wsRelay.Connected()
	d.wsMu.RUnlock()
	if !tsAlive {
		d.subMu.Lock()
		d.subscribed = make(map[string]bool)
		d.subMu.Unlock()
	}
}

// handleP2PICE handle ICE candidates from browser
func (d *Daemon) handleP2PICE(raw map[string]any) {
	candidate, _ := raw["candidate"].(string)
	sdpMid, _ := raw["sdp_mid"].(string)
	sdpMLineIndex := 0
	if v, ok := raw["sdp_mline_index"].(float64); ok {
		sdpMLineIndex = int(v)
	}

	d.rtcMu.Lock()
	// Buffering conditions are relaxed:
	//   - pendingICEMode=true: a new offer has arrived and rtc is still being
	//     created (including the edge case where d.rtc still points to the old
	//     connection)
	//   - d.rtc==nil: the offer has not arrived yet, so early p2p_ice from the
	//     app is also buffered
	// Buffer whenever either condition holds, to avoid candidates being dropped
	// or fed to the stale rtc.
	if d.pendingICEMode || d.rtc == nil {
		d.pendingICE = append(d.pendingICE, raw)
		d.rtcMu.Unlock()
		return
	}
	rtc := d.rtc
	d.rtcMu.Unlock()

	rtc.AddRemoteICE(candidate, sdpMid, sdpMLineIndex)
}

// wsSendRaw send raw JSON via TS WebSocket
func (d *Daemon) wsSendRaw(v any) {
	var data []byte
	switch val := v.(type) {
	case []byte:
		data = val
	default:
		var err error
		data, err = json.Marshal(v)
		if err != nil {
			return
		}
	}

	d.wsMu.RLock()
	relay := d.wsRelay
	d.wsMu.RUnlock()
	if relay != nil && relay.Connected() {
		relay.SendRaw(data)
	}
}

// startTSRelay synchronously stop any running TS relay loop, then start a new one.
// Returns once the previous loop has fully exited (so at most one loop is ever
// running). This is what lets us hot-swap accesskey without two loops racing
// on the same key and triggering TurnServer's mutual-kick.
func (d *Daemon) startTSRelay() {
	d.tsMu.Lock()
	// cancel old loop and wait for it to fully exit before starting a new one
	if d.tsLoopCancel != nil {
		oldCancel := d.tsLoopCancel
		oldDone := d.tsLoopDone
		d.tsMu.Unlock()

		oldCancel()
		// wait for old loop to exit; it may be blocked in relay.Connect
		// (10s timeout) or sleepOrStopCtx, so this is bounded
		<-oldDone

		d.tsMu.Lock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	d.tsLoopCancel = cancel
	d.tsLoopDone = done
	d.tsMu.Unlock()

	go func() {
		defer close(done)
		d.tsRelayLoop(ctx)
	}()
}

// tsRelayLoop background manager for TurnServer WebSocket connection (direct connect + auto-reconnect)
// exits when stopCh is closed, the per-loop ctx is canceled (accesskey swap), or login fatally fails.
func (d *Daemon) tsRelayLoop(ctx context.Context) {
	for {
		// check stop / cancel signal
		select {
		case <-d.stopCh:
			d.notifyState("stopped")
			return
		case <-ctx.Done():
			// canceled by restart; daemon stays alive, do not notify stopped
			return
		default:
		}

		// 1. probe TS servers and select best
		d.notifyState("connecting")
		best, err := SelectBestTurnServer(d.logger)
		if err != nil {
			d.logger.Errorf("[TS] select turn server failed: %v", err)
			switch d.sleepOrStopCtx(ctx, 10*time.Second) {
			case tsSleepStop:
				d.notifyState("stopped")
				return
			case tsSleepCancel:
				return
			}
			continue
		}
		if best == nil {
			d.logger.Errorf("[TS] no turn server available")
			switch d.sleepOrStopCtx(ctx, 10*time.Second) {
			case tsSleepStop:
				d.notifyState("stopped")
				return
			case tsSleepCancel:
				return
			}
			continue
		}

		// 2. connecting directly to TS
		relay := NewWSTurnRelay(d.accessKey, d.cfg, d.logger)
		relay.SecCodeEnabled = HasSecurityCode()
		relay.SecureCap = true
		relay.OnMessage = func(msg *Message) {
			d.handleMessage(msg, "TS")
		}
		relay.OnBinaryMessage = func(data []byte) {
			d.handleBinary(data)
		}
		relay.OnP2PSignal = func(raw map[string]any) {
			d.handleP2PSignal(raw)
		}

		if err := relay.Connect(best.WSURL()); err != nil {
			// login failed (invalid accesskey etc.): log error and exit, no reconnect
			if _, ok := err.(*LoginError); ok {
				d.logger.Errorf("[TS] login failed: %v", err)
				d.notifyState("stopped")
				return
			}
			// IP blocked by TurnServer (same-day ban): long backoff
			if _, ok := err.(*IPBlockedError); ok {
				d.logger.Errorf("[TS] %v (retry in 1h)", err)
				switch d.sleepOrStopCtx(ctx, 1*time.Hour) {
				case tsSleepStop:
					d.notifyState("stopped")
					return
				case tsSleepCancel:
					return
				}
				continue
			}
			// other connection errors: retry
			d.logger.Errorf("[TS] connection failed: %v", err)
			switch d.sleepOrStopCtx(ctx, 10*time.Second) {
			case tsSleepStop:
				d.notifyState("stopped")
				return
			case tsSleepCancel:
				return
			}
			continue
		}

		// replace old connection
		d.wsMu.Lock()
		if d.wsRelay != nil {
			d.wsRelay.Close()
		}
		d.wsRelay = relay
		d.wsMu.Unlock()

		d.notifyState("connected")

		// waiting for disconnect / stop / cancel
		select {
		case <-relay.Done():
			// connection disconnected
		case <-d.stopCh:
			relay.Close()
			d.notifyState("stopped")
			return
		case <-ctx.Done():
			relay.Close()
			// canceled by restart; daemon stays alive, do not notify stopped
			return
		}


		// TS disconnected, cancel all in-progress file transfers
		if d.fileTransfer != nil {
			d.fileTransfer.CancelAll()
		}
		if d.proxyManager != nil {
			d.proxyManager.CloseAll()
		}

		// clear subscriptions, stop PTY output
		// preserve subscriptions when P2P is active — P2P is independent of TS
		// and survives TS reconnects. Clearing subscriptions while P2P is live
		// causes silent output loss (app keeps P2P heartbeat, sees no output).
		d.rtcMu.RLock()
		p2pActive := d.rtc != nil && d.rtc.Connected()
		d.rtcMu.RUnlock()
		if !p2pActive {
			d.subMu.Lock()
			d.subscribed = make(map[string]bool)
			d.subMu.Unlock()
		}

		d.wsMu.Lock()
		if d.wsRelay == relay {
			d.wsRelay = nil
		}
		d.wsMu.Unlock()

		switch d.sleepOrStopCtx(ctx, 5*time.Second) {
		case tsSleepStop:
			d.notifyState("stopped")
			return
		case tsSleepCancel:
			return
		}
	}
}

// tsSleepResult indicates why sleepOrStopCtx woke up.
type tsSleepResult int

const (
	tsSleepTimeout tsSleepResult = iota // timer expired, continue loop
	tsSleepStop                         // stopCh closed, exit and notify "stopped"
	tsSleepCancel                       // ctx canceled (accesskey replacement), exit silently
)

// sleepOrStopCtx waits for duration, returning the reason it woke up.
// stopCh → daemon is shutting down; ctx.Done → accesskey replacement.
// The distinction matters because a restart should not flash "stopped" to
// the UI — the new loop will immediately transition to "connecting".
func (d *Daemon) sleepOrStopCtx(ctx context.Context, duration time.Duration) tsSleepResult {
	select {
	case <-d.stopCh:
		return tsSleepStop
	case <-ctx.Done():
		return tsSleepCancel
	case <-time.After(duration):
		return tsSleepTimeout
	}
}

// notifyState notify state change (no-op when OnStateChange is nil, CLI version unaffected)
func (d *Daemon) notifyState(state string) {
	d.connState.Store(state)
	switch state {
	case "connecting":
		d.logger.Infof("[TS] connecting to turn server...")
	case "connected":
		d.logger.Infof("[TS] connected to turn server")
	case "stopped":
		d.logger.Infof("[TS] connection stopped")
	}
	if d.OnStateChange != nil {
		// Invoke the callback asynchronously to prevent synchronous I/O
		// inside the callback from blocking the main loop.
		// (Historical lesson: writeEarlyLog blocking on a write() syscall
		// once deadlocked startTSRelay permanently.)
		go d.OnStateChange(state)
	}
	// push state to all local WS clients for real-time UI updates
	if d.localServer != nil {
		d.localServer.PushState(state, d.accessKey)
	}
}

// GetState returns current connection state: "stopped", "connecting", "connected"
// returns "" before StartRemote is called
func (d *Daemon) GetState() string {
	if v := d.connState.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// exitWithReason writes exit info to ~/.clianywhere/exit.log then calls os.Exit(0).
// Use instead of bare os.Exit(0) so crashes leave a trace.
func (d *Daemon) exitWithReason(reason, detail string) {
	home, err := os.UserHomeDir()
	if err == nil {
		line := fmt.Sprintf("[%s] reason=%s detail=%s\n", time.Now().Format(time.DateTime), reason, detail)
		f, err := os.OpenFile(filepath.Join(home, accessKeyDir, "exit.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			f.WriteString(line)
			f.Close()
		}
	}
	os.Exit(0)
}

func (d *Daemon) Stop() {
	d.stopOnce.Do(func() {
		close(d.stopCh)
		// cancel TS relay loop too so it exits even if blocked in
		// sleepOrStopCtx or between iterations
		d.tsMu.Lock()
		tsCancel := d.tsLoopCancel
		d.tsMu.Unlock()
		if tsCancel != nil {
			tsCancel()
		}
		// also close current TS connection to speed up exit
		d.wsMu.RLock()
		relay := d.wsRelay
		d.wsMu.RUnlock()
		if relay != nil {
			relay.Close()
		}
		d.CloseRTC()
		if d.fileTransfer != nil {
			d.fileTransfer.CancelAll()
		}
		if d.proxyManager != nil {
			d.proxyManager.CloseAll()
		}
	})
}

// CloseRTC close current WebRTC connection (does not destroy PTY and TS connections)
func (d *Daemon) CloseRTC() {
	d.rtcMu.Lock()
	defer d.rtcMu.Unlock()
	if d.rtc != nil {
		d.rtc.Close()
		d.rtc = nil
	}
}

// Destroy destroy all resources (called on exit)
func (d *Daemon) Destroy() {
	// close file transfer
	if d.fileTransfer != nil {
		d.fileTransfer.CancelAll()
	}

	// close proxy tunnel
	if d.proxyManager != nil {
		d.proxyManager.CloseAll()
	}

	// close IPC server
	if d.ipcServer != nil {
		d.ipcServer.Close()
	}

	// close local WS service
	if d.localServer != nil {
		d.localServer.Close()
	}

	d.rtcMu.Lock()
	if d.rtc != nil {
		d.rtc.Close()
	}
	d.rtcMu.Unlock()

	d.wsMu.Lock()
	if d.wsRelay != nil {
		d.wsRelay.Close()
	}
	d.wsMu.Unlock()

	if d.ptyMgr != nil {
		d.ptyMgr.DestroyAll()
	}
}

// handleMessage handle messages from app (shared by WebRTC and WS)
func (d *Daemon) handleMessage(msg *Message, source string) {
	// E2E: decrypt encrypted envelopes before dispatch. When the secure channel
	// is inactive any enc_* frame is dropped (protocol violation).
	inner, ok := d.unwrapIncomingJSON(msg)
	if !ok {
		return
	}
	msg = inner

	switch msg.Type {
	case TypePakeStart:
		d.handlePakeStart(msg)
	case TypeSecConfirm:
		d.handleSecConfirm(msg)
	case TypeKicked:
		if msg.Reason == "daemon_replaced" {
			d.logger.Infof("[TS] kicked: new daemon with same accesskey connected, exiting")
			d.exitWithReason("kicked", msg.Reason)
		}
		atomic.StoreInt32(&d.kicked, 1)
		if d.fileTransfer != nil {
			d.fileTransfer.CancelAll()
		}
		if d.proxyManager != nil {
			d.proxyManager.CloseAll()
		}
		d.CloseRTC()
		d.rtcMu.Lock()
		d.pendingICE = nil
		d.pendingICEMode = false
		d.rtcMu.Unlock()
		d.channelMu.Lock()
		d.channelMode = ""
		d.channelMu.Unlock()
		d.subMu.Lock()
		d.subscribed = make(map[string]bool)
		d.subMu.Unlock()
	case TypePeerOffline:
		d.handlePeerOffline()
	// TypeSecCodeVerify (plaintext code) intentionally removed: forced
	// encryption means verification only happens via the SPAKE2 handshake.
	// A legacy app sending it gets no response → forced upgrade.
	case TypeCreateSession:
		if !d.checkSecCode() {
			return
		}
		atomic.StoreInt32(&d.kicked, 0) // new frontend message, clearing kicked
		d.handleCreateSession(msg)
	case TypeDestroySession:
		if !d.checkSecCode() {
			return
		}
		d.ptyMgr.Destroy(msg.SessionID)
		d.subMu.Lock()
		delete(d.subscribed, msg.SessionID)
		d.subMu.Unlock()
	case TypeInput:
		if !d.checkSecCode() {
			return
		}
		d.ptyMgr.Write(msg.SessionID, []byte(msg.Data))
	case TypeResize:
		if !d.checkSecCode() {
			return
		}
		if msg.Cols > 0 && msg.Rows > 0 {
			d.ptyMgr.Resize(msg.SessionID, msg.Cols, msg.Rows)
		}
	case TypeSessionList:
		atomic.StoreInt32(&d.kicked, 0) // new frontend message, clearing kicked
		d.handleSessionList()
	case TypeRequestHistory:
		d.handleHistory(msg)
	case TypePing:
		d.sendJSON(&Message{Type: TypePong})
	case TypeChannelSelect:
		d.handleChannelSelect(msg)
	case TypeFileSendCancel:
		d.handleFileSendCancel(msg)
	case TypeFileRequest:
		d.handleFileRequest(msg)
	case TypeFileListRequest:
		if d.fileTransfer != nil {
			d.fileTransfer.sendFileList()
		}
	case TypeFileDelete:
		d.handleFileDelete(msg)
	case TypeDirListRequest:
		if d.fileTransfer != nil {
			d.fileTransfer.HandleDirListRequest(msg.Data)
		}
	case TypeReqPending:
		if d.fileTransfer != nil {
			if err := d.fileTransfer.HandleReqPending(msg.Data); err != nil {
				d.sendJSON(&Message{
					Type:  TypeError,
					Error: err.Error(),
				})
			}
		}
	case TypeProxyConnect:
		if d.proxyManager != nil {
			d.proxyManager.HandleConnect(msg)
		}
	case TypeProxyClose:
		if d.proxyManager != nil {
			d.proxyManager.HandleClose(msg)
		}
	case TypeProxyHttpFetch:
		if d.proxyManager != nil {
			d.proxyManager.HandleHttpFetch(msg)
		}
	case TypeProxyWsConnect:
		if d.proxyManager != nil {
			d.proxyManager.HandleWsConnect(msg)
		}
	case TypeProxyWsMessage:
		if d.proxyManager != nil {
			d.proxyManager.HandleWsMessage(msg)
		}
	case TypeProxyWsClose:
		if d.proxyManager != nil {
			d.proxyManager.HandleWsClose(msg)
		}
	default:
	}
}

// handleBinary handle binary frames from frontend (routed by opcode)
func (d *Daemon) handleBinary(data []byte) {
	// E2E: unwrap encrypted binary frames (0x07) back to the original frame.
	plain, ok := d.unwrapIncomingBinary(data)
	if !ok {
		return
	}
	data = plain
	if len(data) == 0 {
		return
	}
	opcode := data[0]
	switch opcode {
	case OpcodeFileTransfer:
	case OpcodeProxyData:
		if len(data) < 5 {
			return
		}
		connID := binary.BigEndian.Uint32(data[1:5])
		payload := data[5:]
		if d.proxyManager != nil {
			d.proxyManager.HandleData(connID, payload)
		}
	default:
	}
}

// handleCreateSession handle create session request
func (d *Daemon) handleCreateSession(msg *Message) {
	// Subscribe BEFORE creating PTY to prevent losing initial shell output.
	// PTY readLoop starts inside Create and may produce output (shell prompt)
	// before this handler resumes — if subscribed is still false at that point,
	// sendOutput drops the data and the terminal shows blank until the next
	// user input triggers a redraw.
	d.subMu.Lock()
	d.subscribed[msg.SessionID] = true
	d.subMu.Unlock()

	// nil LoginShell defaults to true (preserve previous behavior) so legacy
	// clients that don't send the field still get a login shell.
	loginShell := true
	if msg.LoginShell != nil {
		loginShell = *msg.LoginShell
	}
	s, err := d.ptyMgr.Create(msg.SessionID, msg.Shell, d.cfg.DefaultCols, d.cfg.DefaultRows, loginShell)
	if err != nil {
		// Clean up subscription on failure
		d.subMu.Lock()
		delete(d.subscribed, msg.SessionID)
		d.subMu.Unlock()
		d.sendJSON(&Message{
			Type:      TypeError,
			SessionID: msg.SessionID,
			Error:     err.Error(),
		})
		return
	}

	d.sendJSON(&Message{
		Type:      TypeSessionCreated,
		SessionID: s.ID,
		PID:       s.PID,
		Name:      s.Name,
	})
}

// handleSessionList return current session list with system info
func (d *Daemon) handleSessionList() {
	sessions := d.ptyMgr.ListSessions()
	d.channelMu.RLock()
	mode := d.channelMode
	d.channelMu.RUnlock()
	d.logger.Infof("[SESSION] handleSessionList: %d sessions, channelMode=%s", len(sessions), mode)
	for i, s := range sessions {
		d.logger.Infof("[SESSION]   [%d] id=%s name=%s shell=%s", i, s.ID, s.Name, s.Shell)
	}
	d.sendJSON(&Message{
		Type:            TypeSessionInfo,
		SessionInfos:    sessions,
		SystemInfo:      getSystemInfo(),
		Shells:          DetectShells(),
		SecCodeRequired: atomic.LoadInt32(&d.secCodeEnabled) == 1,
	})
}

// getSystemInfo collect OS info for AI command translation
func getSystemInfo() string {
	if runtime.GOOS == "windows" {
		out, err := getWindowsVersion()
		if err == nil {
			return "Windows " + strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "Microsoft "))
		}
		return "Windows"
	}
	out, err := exec.Command("uname", "-sr").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return runtime.GOOS
}

// handleHistory return session history, re-serialize to client size, send in chunks
func (d *Daemon) handleHistory(msg *Message) {
	var data []byte
	var seq uint64

	if msg.Cols > 0 && msg.Rows > 0 {
		data, seq = d.ptyMgr.GetHistoryAt(msg.SessionID, msg.Cols, msg.Rows)
	} else {
		data, seq = d.ptyMgr.GetHistory(msg.SessionID)
	}

	d.logger.Infof("[SESSION] handleHistory: session=%s cols=%d rows=%d dataLen=%d seq=%d", msg.SessionID, msg.Cols, msg.Rows, len(data), seq)

	if len(data) <= 4096 {
		d.sendJSON(&Message{
			Type:      TypeHistoryData,
			SessionID: msg.SessionID,
			Data:      string(data),
			Seq:       seq,
		})
	} else {
		d.sendHistoryChunks(msg.SessionID, data, seq)
	}

	// history sent, subscribing to real-time output
	d.subMu.Lock()
	d.subscribed[msg.SessionID] = true
	d.subMu.Unlock()
}

const historyChunkSize = 4096 // 4KB raw data per chunk

// sendHistoryChunks send history data in chunks
func (d *Daemon) sendHistoryChunks(sessionID string, data []byte, seq uint64) {
	total := (len(data) + historyChunkSize - 1) / historyChunkSize

	// (1) send start first, indicating total chunks
	d.sendJSON(&Message{
		Type:        TypeHistoryStart,
		SessionID:   sessionID,
		Seq:         seq,
		TotalChunks: total,
	})

	// (2) send chunk by chunk
	for i := 0; i < total; i++ {
		start := i * historyChunkSize
		end := start + historyChunkSize
		if end > len(data) {
			end = len(data)
		}

		chunkMsg := &Message{
			Type:        TypeHistoryChunk,
			SessionID:   sessionID,
			Data:        string(data[start:end]),
			ChunkIndex:  i,
			TotalChunks: total,
		}

		d.sendJSONWithBackpressure(chunkMsg, 64*1024)
	}

	// (3) send end completion signal
	d.sendJSON(&Message{
		Type:        TypeHistoryEnd,
		SessionID:   sessionID,
		TotalChunks: total,
	})
}

// handlePeerOffline handle browser offline notification
func (d *Daemon) handlePeerOffline() {
	d.channelMu.RLock()
	mode := d.channelMode
	d.channelMu.RUnlock()

	if mode == "p2p" {
		// P2P connection is still active; only the TS relay dropped.
		// Keep the secure channel (it rides the P2P DataChannel).
		return
	}
	d.resetSecure("peer_offline")

	if d.fileTransfer != nil {
		d.fileTransfer.CancelAll()
	}
	if d.proxyManager != nil {
		d.proxyManager.CloseAll()
	}
	d.subMu.Lock()
	d.subscribed = make(map[string]bool)
	d.subMu.Unlock()
	d.channelMu.Lock()
	d.channelMode = ""
	d.channelMu.Unlock()
}

// checkSecCode returns true only if the current app connection has completed
// the SPAKE2 handshake. Forced encryption: every remote operation is gated on
// a finished handshake — the plaintext sec_code_verify path is removed, so a
// connection that has not handshaken cannot do anything. Pure atomic read, no
// file IO.
func (d *Daemon) checkSecCode() bool {
	if atomic.LoadInt32(&d.secCodeVerified) == 1 {
		return true
	}
	d.sendJSON(&Message{Type: TypeError, Error: "Security code required"})
	return false
}

// handleChannelSelect handle browser channel selection.
// Subscriptions are NOT cleared here — they are session-level and transport-independent.
// Local controllers are NOT kicked — channel switch does not affect local attach.
func (d *Daemon) handleChannelSelect(msg *Message) {
	channel := msg.Data // "p2p" or "ts"
	if channel != "p2p" && channel != "ts" {
		return
	}

	d.channelMu.Lock()
	d.channelMode = channel
	d.channelMu.Unlock()

	d.sendJSON(&Message{
		Type: TypeChannelSelected,
		Data: channel,
	})

	// When switching from TS to P2P, drain TS send buffer in background.
	// TS connection is kept open (not closed) to avoid TurnServer dropping
	// in-flight data in its internal relay channels.
	if channel == "p2p" {
		go func() {
			d.wsMu.RLock()
			relay := d.wsRelay
			d.wsMu.RUnlock()
			if relay != nil {
				relay.DrainSendCh()
			}
		}()
	}
}

// handleFileSendCancel handle frontend request to cancel file send
func (d *Daemon) handleFileSendCancel(msg *Message) {
	if d.fileTransfer != nil && msg.FileID > 0 {
		d.fileTransfer.Cancel(msg.FileID)
	}
}

// handleFileRequest handle frontend request to transfer a file
func (d *Daemon) handleFileRequest(msg *Message) {
	if d.fileTransfer == nil {
		return
	}
	fileID := msg.FileID
	if err := d.fileTransfer.HandleRequest(fileID); err != nil {
		d.sendJSON(&Message{
			Type:  TypeError,
			Error: err.Error(),
		})
	}
}

// handleFileDelete handle frontend file deletion
func (d *Daemon) handleFileDelete(msg *Message) {
	if d.fileTransfer == nil {
		return
	}
	fileID := msg.FileID
	d.fileTransfer.HandleDelete(fileID)
}

// replenishPool replenish session pool
func (d *Daemon) replenishPool() {
	current := len(d.ptyMgr.ListSessions())
	deficit := d.cfg.PoolSize - current
	if deficit <= 0 {
		return
	}
	for i := 0; i < deficit; i++ {
		id := d.ptyMgr.generateID()
		_, err := d.ptyMgr.Create(id, d.cfg.DefaultShell, d.cfg.DefaultCols, d.cfg.DefaultRows, true)
		if err != nil {
			continue
		}
	}
}

// AttachLocalSession for local WS call: register local controller to session (multi-client, no kick)
func (d *Daemon) AttachLocalSession(sessionID string, clientID string, ctrl io.WriteCloser) error {
	session := d.ptyMgr.Get(sessionID)
	if session == nil {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// register as additional controller (does NOT kick existing controllers or app)
	session.AddController(clientID, ctrl)
	return nil
}

// DetachLocalSession remove specific local controller by client ID
func (d *Daemon) DetachLocalSession(sessionID string, clientID string) {
	session := d.ptyMgr.Get(sessionID)
	if session != nil {
		session.RemoveController(clientID)
	}
}

// CreateSession create new session (for local WS call)
func (d *Daemon) CreateSession(shell string) (*Session, error) {
	if shell == "" {
		shell = d.cfg.DefaultShell
	}
	id := d.ptyMgr.generateID()
	return d.ptyMgr.Create(id, shell, d.cfg.DefaultCols, d.cfg.DefaultRows, true)
}

// DestroySession destroy session
func (d *Daemon) DestroySession(sessionID string) {
	if s := d.ptyMgr.Get(sessionID); s != nil {
		s.CloseAllControllers()
		d.ptyMgr.Destroy(sessionID)
	}
}

// SetLogger replace daemon logger (for entry points that create daemon before knowing logger type)
func (d *Daemon) SetLogger(logger Logger) {
	d.logger = logger
}

// GetMaskedAccessKey returns masked accesskey for display (first 8 chars + "...")
func (d *Daemon) GetMaskedAccessKey() string {
	if len(d.accessKey) <= 8 {
		return d.accessKey
	}
	return d.accessKey[:8] + "..."
}

// SetAccessKeyAndConnect validate, save and start remote connection with new accesskey
func (d *Daemon) SetAccessKeyAndConnect(key string) error {
	if err := saveAccessKey(key); err != nil {
		return fmt.Errorf("failed to save accesskey: %w", err)
	}
	d.accessKey = key
	d.StartRemote(key)
	return nil
}

// GetConfig returns daemon config (for LocalServer to access)
func (d *Daemon) GetConfig() *Config {
	return d.cfg
}

// LocalTakeover local takeover: clear all local controllers, unsubscribe app, notify app kicked
func (d *Daemon) LocalTakeover() {
	// close all local controllers for all sessions
	for _, info := range d.ptyMgr.ListSessions() {
		if s := d.ptyMgr.Get(info.ID); s != nil {
			s.CloseAllControllers()
		}
	}

	// clear client-session mappings in localserver
	if d.localServer != nil {
		d.localServer.clientSessionsMu.Lock()
		d.localServer.clientSessions = make(map[string]map[string]bool)
		d.localServer.clientSessionsMu.Unlock()
	}

	// unsubscribe app from all sessions
	d.subMu.Lock()
	d.subscribed = make(map[string]bool)
	d.subMu.Unlock()

	// notify app kicked
	d.sendJSON(&Message{
		Type: TypeKicked,
		Data: "taken over locally",
	})
}

// sendOutput send terminal output (with write sequence number, used by frontend for dedup)
// broadcast to all local controllers AND also to subscribed app (both paths)
func (d *Daemon) sendOutput(sessionID, data string, seq uint64) {
	// 1. broadcast to all local controllers
	session := d.ptyMgr.Get(sessionID)
	if session != nil {
		session.Broadcast([]byte(data))
	}

	// 2. send to subscribed app (independent of local controllers)
	d.subMu.RLock()
	sub := d.subscribed[sessionID]
	d.subMu.RUnlock()
	if !sub {
		return
	}
	d.sendJSON(&Message{
		Type:      TypeOutput,
		SessionID: sessionID,
		Data:      data,
		Seq:       seq,
	})
}

// sendJSON send via current selected channel (single-channel mode, no auto-switch)
func (d *Daemon) sendJSON(msg *Message) {
	// E2E: wrap into an encrypted envelope when the secure channel is active and
	// the type is not plaintext-exempt. On wrap failure the message is dropped
	// (never falls back to plaintext).
	if wrapped := d.wrapOutgoingJSON(msg); wrapped != nil {
		msg = wrapped
	} else {
		return
	}

	d.channelMu.RLock()
	mode := d.channelMode
	d.channelMu.RUnlock()

	switch mode {
	case "p2p":
		d.rtcMu.RLock()
		rtc := d.rtc
		rtcOK := rtc != nil && rtc.Connected()
		d.rtcMu.RUnlock()
		if rtcOK {
			rtc.SendJSON(msg)
			return
		}
		return

	case "ts":
		d.wsMu.RLock()
		relay := d.wsRelay
		d.wsMu.RUnlock()
		if relay != nil && relay.Connected() {
			relay.SendJSON(msg)
			return
		}

	default:
		d.wsMu.RLock()
		relay := d.wsRelay
		d.wsMu.RUnlock()
		if relay != nil && relay.Connected() {
			relay.SendJSON(msg)
		}
	}
}

// sendJSONWithBackpressure sends a JSON message, applying the E2E envelope,
// then hands it to the p2p path with backpressure (or the normal TS path).
// Used by history chunks which bypass sendJSON in p2p mode.
func (d *Daemon) sendJSONWithBackpressure(msg *Message, threshold uint64) {
	if wrapped := d.wrapOutgoingJSON(msg); wrapped != nil {
		msg = wrapped
	} else {
		return
	}

	d.channelMu.RLock()
	mode := d.channelMode
	d.channelMu.RUnlock()

	if mode == "p2p" {
		d.rtcMu.RLock()
		rtc := d.rtc
		rtcOK := rtc != nil && rtc.Connected()
		d.rtcMu.RUnlock()
		if rtcOK {
			rtc.SendJSONWithBackpressure(msg, threshold)
			return
		}
		return
	}

	d.wsMu.RLock()
	relay := d.wsRelay
	d.wsMu.RUnlock()
	if relay != nil && relay.Connected() {
		relay.SendJSON(msg)
	}
}

// sendBytes send binary data via current selected channel
func (d *Daemon) sendBytes(data []byte) {
	data = d.wrapOutgoingBinary(data)
	d.channelMu.RLock()
	mode := d.channelMode
	d.channelMu.RUnlock()

	switch mode {
	case "p2p":
		d.rtcMu.RLock()
		rtc := d.rtc
		rtcOK := rtc != nil && rtc.Connected()
		d.rtcMu.RUnlock()
		if rtcOK {
			rtc.SendBytes(data)
			return
		}
		return

	case "ts":
		d.wsMu.RLock()
		relay := d.wsRelay
		d.wsMu.RUnlock()
		if relay != nil && relay.Connected() {
			relay.SendBinary(data)
			return
		}

	default:
		d.wsMu.RLock()
		relay := d.wsRelay
		d.wsMu.RUnlock()
		if relay != nil && relay.Connected() {
			relay.SendBinary(data)
		}
	}
}

// sendBytesWithBackpressure send binary data via current selected channel (with backpressure)
func (d *Daemon) sendBytesWithBackpressure(data []byte, threshold uint64) {
	data = d.wrapOutgoingBinary(data)
	d.channelMu.RLock()
	mode := d.channelMode
	d.channelMu.RUnlock()

	switch mode {
	case "p2p":
		d.rtcMu.RLock()
		rtc := d.rtc
		rtcOK := rtc != nil && rtc.Connected()
		d.rtcMu.RUnlock()
		if rtcOK {
			rtc.SendBytesWithBackpressure(data, threshold)
			return
		}
		return

	default:
		d.wsMu.RLock()
		relay := d.wsRelay
		d.wsMu.RUnlock()
		if relay != nil && relay.Connected() {
			relay.SendBinaryBlocking(data)
		}
	}
}

// sendBytesCancelable blocking send with cancel (for file transfer, returns immediately when cancel is closed)
func (d *Daemon) sendBytesCancelable(data []byte, threshold uint64, cancel <-chan struct{}) bool {
	data = d.wrapOutgoingBinary(data)
	d.channelMu.RLock()
	mode := d.channelMode
	d.channelMu.RUnlock()

	switch mode {
	case "p2p":
		d.rtcMu.RLock()
		rtc := d.rtc
		rtcOK := rtc != nil && rtc.Connected()
		d.rtcMu.RUnlock()
		if rtcOK {
			for {
				select {
				case <-cancel:
					return false
				default:
				}
				rtc.mu.Lock()
				ba := rtc.dc.BufferedAmount()
				rtc.mu.Unlock()
				if ba < threshold {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			rtc.SendBytes(data)
			return true
		}
		return false

	default:
		d.wsMu.RLock()
		relay := d.wsRelay
		d.wsMu.RUnlock()
		if relay != nil && relay.Connected() {
			return relay.SendBinaryCancelable(data, cancel)
		}
		return false
	}
}

// hasActiveChannel check if there is an active client channel (P2P or TS)
func (d *Daemon) hasActiveChannel() bool {
	d.rtcMu.RLock()
	rtc := d.rtc
	rtcOK := rtc != nil && rtc.Connected()
	d.rtcMu.RUnlock()
	if rtcOK {
		return true
	}

	d.wsMu.RLock()
	relay := d.wsRelay
	wsOK := relay != nil && relay.Connected()
	d.wsMu.RUnlock()
	return wsOK
}

// startIPCServer start HTTP localhost IPC server (port range 56881-56981)
func (d *Daemon) startIPCServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/send", d.fileTransfer.handleIPCUpload)

	const portMin = 56881
	const portMax = 56981

	for port := portMin; port <= portMax; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		srv := &http.Server{Addr: addr, Handler: mux}

		ln, err := net.Listen("tcp", addr)
		if err != nil {
			continue // port in use, try next
		}

		d.ipcServer = srv
		d.cfg.IPCHTTPPort = port // record actual bound port

		go func() {
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			}
		}()

		return
	}

}

