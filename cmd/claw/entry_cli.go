//go:build cli

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

// daemonLock holds the flock for the process lifetime (prevents GC closing fd)
var daemonLock *os.File

func main() {
	// prevent running inside daemon PTY (e.g. app terminal)
	if os.Getenv("IS_CLIANYWHERE_PTY") == "1" {
		fmt.Fprintln(os.Stderr, "Error: cannot run claw inside CliAnyWhere terminal")
		os.Exit(1)
	}

	// read CLIANYWHERE_TS env: skip TS selection, use specified addr directly
	if tsAddr := os.Getenv("CLIANYWHERE_TS"); tsAddr != "" {
		SetForceTSAddr(tsAddr)
	}

	// subcommand dispatch
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "send":
			handleSend()
			return
		case "version":
			ensureConsole()
			fmt.Printf("daemon_go %s\n", Version)
			return
		case "status":
			ensureConsole()
			handleStatus()
			return
		case "stop":
			ensureConsole()
			handleStop()
			return
		default:
			ensureConsole()
			fmt.Printf("'%s' is not supported yet\n", os.Args[1])
			os.Exit(1)
		}
	}

	// no args: CLI mode startup
	ensureConsole()

	// Daemonized child process: skip lock/fork, go straight to daemon
	if isDaemonized() {
		runDaemonProcess()
		return
	}

	// ---- Parent / fresh process below ----

	// Check if another instance is already running
	if isLocked() {
		state, _ := queryDaemonStatus()
		runMainMenu(fmt.Sprintf("Daemon already running (%s)", state))
		return
	}

	// Ensure accesskey exists before forking
	// (forked child has no terminal for interactive input)
	accessKey, err := loadAccessKey()
	if err != nil {
		fatalExit("failed to read accesskey: %v", err)
	}
	if accessKey == "" {
		cfg := DefaultConfig()
		logger := NewStdLogger()
		accessKey, _ = GetAccessKey(cfg, logger)
		if accessKey == "" {
			fmt.Println("No AccessKey, exiting.")
			pressAnyKeyToExit()
			return
		}
		if err := saveAccessKey(accessKey); err != nil {
			fatalExit("failed to save accesskey: %v", err)
		}
		fmt.Println("Bind successful!")
	}

	// Fork to background: child runs daemon, parent shows CLI menu
	childPort := forkToBackground()
	if childPort > 0 {
		// Unix parent: wait for TS connection, show progress
		waitAndShowTSStatus(childPort)
		state, _ := queryDaemonStatus()
		menuTitle := "Daemon started"
		if state != "" {
			menuTitle = fmt.Sprintf("Daemon status: %s", state)
		}
		runMainMenu(menuTitle)
		return
	}

	// Windows (no fork): run daemon in-process, then show menu
	runDaemonProcess()
	state, _ := queryDaemonStatus()
	menuTitle := "Daemon started"
	if state != "" {
		menuTitle = fmt.Sprintf("Daemon status: %s", state)
	}
	runMainMenu(menuTitle)
}

// runDaemonProcess starts daemon, connects to TS, and (on Unix) blocks with waitForSignal.
// On Windows the caller shows the menu after this returns.
func runDaemonProcess() {
	// Acquire lock (child process on Unix, or fresh Windows process)
	lock := tryLock()
	if lock == nil {
		writeEarlyLog("runDaemonProcess: lock failed")
		return
	}
	// Hold lock for process lifetime, never close
	// Hold lock for process lifetime, keep reference to prevent GC
	 daemonLock = lock

	logger := NewStdLogger()
	cfg := DefaultConfig()

	accessKey, err := loadAccessKey()
	if err != nil {
		writeEarlyLog(fmt.Sprintf("failed to read accesskey: %v", err))
	}

	if accessKey == "" {
		if isDaemonized() {
			// Child process has no terminal for interaction
			writeEarlyLog("no accesskey, exiting child process")
			return
		}
		accessKey = runSetAccessKey(cfg, logger)
		if accessKey == "" {
			fmt.Println("No AccessKey, exiting.")
			pressAnyKeyToExit()
			return
		}
	}

	d := NewDaemon(accessKey, cfg, logger)
	d.Init()

	connectedCh := make(chan error, 1)
	d.OnStateChange = func(state string) {
		switch state {
		case "connected":
			select {
			case connectedCh <- nil:
			default:
			}
		case "stopped":
			select {
			case connectedCh <- fmt.Errorf("connection stopped"):
			default:
			}
		}
	}
	d.StartRemote(accessKey)
	writeEarlyLog(fmt.Sprintf("[ts] AccessKey: %s", truncateKey(accessKey)))

	// Notify parent of WS port (Unix only)
	if d.localServer != nil {
		notifyParentPort(d.localServer.port)
	}

	if err := <-connectedCh; err != nil {
		writeEarlyLog(fmt.Sprintf("[ts] connection failed: %v", err))
	}

	if isDaemonized() {
		// Unix forked child: run forever until signal
		waitForSignal(d, logger)
	}
	// Windows: return to caller for menu
}

// waitAndShowTSStatus polls daemon status via WS and prints connection progress.
// Waits up to 30s for connected/stopped state.
func waitAndShowTSStatus(port int) {
	lastState := ""
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		url := fmt.Sprintf("ws://127.0.0.1:%d", port)
		dialer := websocket.Dialer{HandshakeTimeout: 2 * time.Second}
		conn, _, err := dialer.Dial(url, nil)
		if err != nil {
			continue
		}
		conn.WriteJSON(Message{Type: TypeGetServerStatus})
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			conn.Close()
			continue
		}
		conn.Close()

		state := msg.Data
		if state != lastState && state != "" {
			switch state {
			case "connecting":
				fmt.Println("[ts] Connecting to TurnServer...")
			case "connected":
				fmt.Println("[ts] Connected successfully")
				return
			case "stopped":
				fmt.Println("[ts] Connection stopped")
				return
			}
			lastState = state
		}
	}
	fmt.Println("[ts] Connection timeout")
}

// runSetAccessKey runs the accesskey acquisition flow (manual input or QR), saves and returns the key.
// Returns "" if user cancelled.
func runSetAccessKey(cfg *Config, logger Logger) string {
	key, _ := GetAccessKey(cfg, logger)
	if key == "" {
		return ""
	}
	if err := saveAccessKey(key); err != nil {
		fatalExit("failed to save accesskey: %v", err)
	}
	fmt.Println("Bind successful!")
	return key
}

// runMainMenu shows the main menu in a loop.
// This runs in the parent CLI process, connecting to daemon via WS.
func runMainMenu(title string) {
	for {
		state, _ := queryDaemonStatus()
		menuTitle := title
		if state != "" {
			menuTitle = fmt.Sprintf("Daemon status: %s", state)
		}

		secCodeSet := HasSecurityCode()
		secCodeLabel := "Set Security Code"
		if secCodeSet {
			secCodeLabel = "Change Security Code"
		}
		menuItems := []string{
			"Attach to session",
			"Set AccessKey",
			secCodeLabel,
			"Stop Server",
			"Exit (server keeps running, connect via app)",
		}
		if secCodeSet {
			menuItems = []string{
				"Attach to session",
				"Set AccessKey",
				secCodeLabel,
				"Unset Security Code",
				"Stop Server",
				"Exit (server keeps running, connect via app)",
			}
		}

		choice := showArrowKeyMenu(menuTitle, menuItems)

		switch {
		case choice == 0: // Attach to session
			runAttachCLI()
		case choice == 1: // Set AccessKey
			cfg := DefaultConfig()
			logger := NewStdLogger()
			key := runSetAccessKey(cfg, logger)
			if key == "" {
				fmt.Println("Cancelled.")
				continue
			}
			port := findLocalWSPort()
			if port != -1 {
				sendSetAccessKeyViaWS(port, key)
				fmt.Printf("[ts] New AccessKey: %s\n", truncateKey(key))
				fmt.Println("[ts] Connecting to TurnServer...")
				for i := 0; i < 60; i++ {
					time.Sleep(500 * time.Millisecond)
					state, ok := queryDaemonStatus()
					if !ok {
						continue
					}
					if state == "connected" {
						fmt.Println("[ts] Connected successfully")
						break
					}
					if state == "stopped" {
						fmt.Println("[ts] Connection failed")
						break
					}
				}
			}
		case (choice == 2 && !secCodeSet) || (choice == 2 && secCodeSet): // Set/Change Security Code
			handleSetSecCodeFromMenu()
		case choice == 3 && secCodeSet: // Unset Security Code
			handleUnsetSecCodeFromMenu()
		case (choice == 3 && !secCodeSet) || (choice == 4 && secCodeSet): // Stop Server
			handleStop()
			return
		case (choice == 4 && !secCodeSet) || (choice == 5 && secCodeSet) || choice == -1: // Exit or Ctrl+C
			return
		}
	}
}

// handleSetSecCodeFromMenu prompts for a 6-digit security code and sends it to daemon via WS
func handleSetSecCodeFromMenu() {
	port := findLocalWSPort()
	if port == -1 {
		fmt.Println("Error: daemon not running.")
		return
	}

	for {
		fmt.Print("Enter 6-digit security code (or 'q' to cancel): ")
		var input string
		fmt.Scanln(&input)
		if input == "q" {
			fmt.Println("Cancelled.")
			return
		}
		if !isValidSecCode(input) {
			fmt.Println("Error: must be exactly 6 digits. Try again.")
			continue
		}

		url := fmt.Sprintf("ws://127.0.0.1:%d", port)
		dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
		conn, _, err := dialer.Dial(url, nil)
		if err != nil {
			fmt.Printf("Error: failed to connect to daemon: %v\n", err)
			return
		}
		defer conn.Close()

		conn.WriteJSON(Message{Type: TypeSetSecCode, Data: input})
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		if msg.Type == TypeSetSecCodeResult && msg.Success {
			fmt.Println("Security code set successfully.")
		} else {
			fmt.Printf("Error: %s\n", msg.Error)
		}
		return
	}
}

// handleUnsetSecCodeFromMenu clears the security code via WS
func handleUnsetSecCodeFromMenu() {
	port := findLocalWSPort()
	if port == -1 {
		fmt.Println("Error: daemon not running.")
		return
	}

	url := fmt.Sprintf("ws://127.0.0.1:%d", port)
	dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		fmt.Printf("Error: failed to connect to daemon: %v\n", err)
		return
	}
	defer conn.Close()

	conn.WriteJSON(Message{Type: TypeUnsetSecCode})
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var msg Message
	if err := conn.ReadJSON(&msg); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if msg.Type == TypeUnsetSecCodeResult && msg.Success {
		fmt.Println("Security code cleared.")
	} else {
		fmt.Printf("Error: %s\n", msg.Error)
	}
}
