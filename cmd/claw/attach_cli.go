
//go:build cli

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	xterm "github.com/CLIAnywhere/clianywhere_daemon/internal/xterm"

	"golang.org/x/term"
)

// ============================================================
// daemon attach subcommand entry
// ============================================================

// runAttachCLI is the daemon attach subcommand implementation
// 1. discover local WS port → 2. show session list menu → 3. select and attach → 4. raw passthrough mode
// intentional detach (Ctrl+J K) returns to session menu, kicked exits process
func runAttachCLI() {
	port := findLocalWSPort()
	if port == -1 {
		fmt.Println("Error: daemon not running or local WebSocket unavailable")
		fmt.Println("Make sure 'daemon run' is active first")
		os.Exit(1)
	}

	url := fmt.Sprintf("ws://127.0.0.1:%d", port)

	for {
		dialer := *websocket.DefaultDialer
		dialer.NetDial = func(network, addr string) (net.Conn, error) {
			c, err := net.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetNoDelay(true)
			}
			return c, nil
		}
		conn, _, err := dialer.Dial(url, nil)
		if err != nil {
			fmt.Printf("Error: connect failed: %v\n", err)
			return
		}

		selectedID, sessionName := selectSession(conn)
		if selectedID == "" {
			conn.Close()
			return
		}

		kicked := attachToSession(conn, selectedID, sessionName)
		if kicked {
			return
		}
		// intentional detach, connection closed, reconnecting to menu
	}
}

// ============================================================
// port discovery
// ============================================================

// ============================================================
// session list menu
// ============================================================

// selectSession enter raw mode to show menu, return selected sessionID, empty string means exit
func selectSession(conn *websocket.Conn) (string, string) {
	// request session list
	conn.WriteJSON(Message{Type: TypeSessionList})

	// receive response
	var sessions []SessionInfo
	var availShells []ShellInfo
	_, msgBytes, err := conn.ReadMessage()
	if err == nil {
		var msg Message
		if json.Unmarshal(msgBytes, &msg) == nil {
			sessions = msg.SessionInfos
			availShells = msg.Shells
		}
	}

	// enter raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Printf("Error: failed to enter raw mode: %v\n", err)
		return "", ""
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	selected := 0
	maxIdx := len(sessions) // +0 New shell
	// submenu state for shell selection
	shellMenuOpen := false
	shellSelected := 0

	for {
		if shellMenuOpen {
			drawShellMenu(availShells, shellSelected)
		} else {
			drawMenu(sessions, selected)
		}

		buf := make([]byte, 3)
		n, _ := os.Stdin.Read(buf)

		if shellMenuOpen {
			// shell selection submenu
			if n == 1 {
				switch buf[0] {
				case 'q', 0x03:
					shellMenuOpen = false
				case 'j', 0x0A:
					shellSelected++
					if shellSelected >= len(availShells) {
						shellSelected = 0
					}
				case 'k':
					shellSelected--
					if shellSelected < 0 {
						shellSelected = len(availShells) - 1
					}
				case 0x1B: // Escape → back to main menu
					shellMenuOpen = false
				case 0x0D: // Enter → create session with selected shell
					shell := availShells[shellSelected].Name
					id := addNewShell(conn, shell)
					if id != "" {
						return id, "Shell"
					}
					shellMenuOpen = false // creation failed, back to main menu
				}
			} else if n == 3 && buf[0] == 0x1B && buf[1] == '[' {
				switch buf[2] {
				case 'A':
					shellSelected--
					if shellSelected < 0 {
						shellSelected = len(availShells) - 1
					}
				case 'B':
					shellSelected++
					if shellSelected >= len(availShells) {
						shellSelected = 0
					}
				}
			}
			continue
		}

		// main menu
		if n == 1 {
			switch buf[0] {
			case 'q', 0x03: // q or Ctrl+C → exit
				return "", ""
			case 'j', 0x0A: // j or ↓
				selected++
				if selected > maxIdx {
					selected = 0
				}
			case 'k':
				selected--
				if selected < 0 {
					selected = maxIdx
				}
			case 0x0D: // Enter → confirm selection
				if selected == len(sessions) {
					// + New shell → open shell selection submenu
					if len(availShells) == 1 {
						// only one shell, create directly
						id := addNewShell(conn, availShells[0].Name)
						if id != "" {
							return id, "Shell"
						}
					} else if len(availShells) > 1 {
						shellMenuOpen = true
						shellSelected = 0
					}
				} else if selected < len(sessions) {
					return sessions[selected].ID, sessions[selected].Name
				}
			}
		} else if n == 3 && buf[0] == 0x1B && buf[1] == '[' {
			switch buf[2] {
			case 'A': // ↑
				selected--
				if selected < 0 {
					selected = maxIdx
				}
			case 'B': // ↓
				selected++
				if selected > maxIdx {
					selected = 0
				}
			}
		}
	}
}

// drawMenu draw session selection menu using ANSI escape sequences
func drawMenu(sessions []SessionInfo, selected int) {
	// clear screen
	fmt.Print("\033[H\033[2J")
	// title
	fmt.Print("\033[1;36m=== Daemon Shells ===\033[0m\r\n")
	fmt.Print("═══════════════════════════════════\r\n")

	for i, s := range sessions {
		prefix := "  "
		if i == selected {
			prefix = " \033[7m> " // selected item inverse highlight
		}
		// truncate ID for display
		fmt.Printf("%s%s\033[0m\r\n", prefix, s.Name)
	}

	// Add new shell
	prefix := "  "
	if selected == len(sessions) {
		prefix = " \033[7m> "
	}
	fmt.Printf("%s+ New shell\033[0m\r\n", prefix)

	fmt.Print("═══════════════════════════════════\r\n")
	fmt.Print("\033[2m" + menuHint + "\033[0m\r\n")
}

// drawShellMenu draw shell type selection submenu
func drawShellMenu(shells []ShellInfo, selected int) {
	fmt.Print("\033[H\033[2J")
	fmt.Print("\033[1;36m=== Select Shell ===\033[0m\r\n")
	fmt.Print("═══════════════════════════════════\r\n")

	for i, s := range shells {
		prefix := "  "
		if i == selected {
			prefix = " \033[7m> "
		}
		fmt.Printf("%s%-12s %s\033[0m\r\n", prefix, s.Name, s.Path)
	}

	fmt.Print("═══════════════════════════════════\r\n")
	fmt.Print("\033[2mESC:back  ↑↓:select  Enter:confirm\033[0m\r\n")
}

// addNewShell request daemon to create new session with specified shell
func addNewShell(conn *websocket.Conn, shell string) string {
	conn.WriteJSON(Message{Type: TypeCreateSession, Shell: shell})

	// read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msgBytes, err := conn.ReadMessage()
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return ""
	}

	var msg Message
	if json.Unmarshal(msgBytes, &msg) != nil {
		return ""
	}
	if msg.Type == TypeError {
		return ""
	}
	if msg.Type == TypeSessionCreated {
		return msg.SessionID
	}
	return ""
}


// ============================================================
// Attach to session — raw terminal passthrough mode
// ============================================================

// attachToSession connect to specified session, enter raw terminal passthrough mode
// return true means kicked (caller should exit), false means intentional detach
func attachToSession(conn *websocket.Conn, sessionID string, sessionName string) bool {

	// enter raw mode early, prevent Ctrl+C from killing process during WS handshake
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err == nil {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}

	// send attach request
	conn.WriteJSON(Message{Type: TypeAttach, SessionID: sessionID})

	// wait for attach_ok
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("\r\nError: attach failed: %v\r\n", err)
			return false
		}

		var msg Message
		if json.Unmarshal(msgBytes, &msg) != nil {
			continue
		}

		switch msg.Type {
		case TypeAttachOK:
			// enter passthrough mode after success (rawTerminalPassthrough will MakeRaw again, restore then set)
			conn.SetReadDeadline(time.Time{})
			if rawTerminalPassthrough(conn, sessionID, sessionName) {
				fmt.Print("\r\nkicked\r\n")
				return true
			}
			return false

		case TypeError:
			fmt.Printf("\r\nError: %s\r\n", msg.Error)
			return false

		case TypeHistoryData:
			// may receive history data before attach_ok, output directly
			os.Stdout.Write([]byte(msg.Data))

		default:
		}
	}
}

// sgrCode generate SGR escape sequence, set non-default attributes after each \033[0m reset
func sgrCode(cell *xterm.CellData) string {
	if cell.IsAttributeDefault() {
		return "\033[0m"
	}

	var p []string
	p = append(p, "0") // reset first

	if cell.IsBold() != 0 { p = append(p, "1") }
	if cell.IsDim() != 0 { p = append(p, "2") }
	if cell.IsItalic() != 0 { p = append(p, "3") }
	if cell.IsUnderline() != 0 { p = append(p, "4") }
	if cell.IsBlink() != 0 { p = append(p, "5") }
	if cell.IsInverse() != 0 { p = append(p, "7") }
	if cell.IsInvisible() != 0 { p = append(p, "8") }
	if cell.IsStrikethrough() != 0 { p = append(p, "9") }

	// foreground color
	if !cell.IsFgDefault() {
		if cell.IsFgPalette() {
			c := cell.GetFgColor()
			if c < 8 {
				p = append(p, fmt.Sprintf("%d", 30+c))
			} else if c < 16 {
				p = append(p, fmt.Sprintf("%d", 90+c-8))
			} else {
				p = append(p, "38", "5", fmt.Sprintf("%d", c))
			}
		} else if cell.IsFgRGB() {
			rgb := xterm.ToColorRGB(uint32(cell.GetFgColor()))
			p = append(p, "38", "2", fmt.Sprintf("%d", rgb[0]), fmt.Sprintf("%d", rgb[1]), fmt.Sprintf("%d", rgb[2]))
		}
	}

	// background color
	if !cell.IsBgDefault() {
		if cell.IsBgPalette() {
			c := cell.GetBgColor()
			if c < 8 {
				p = append(p, fmt.Sprintf("%d", 40+c))
			} else if c < 16 {
				p = append(p, fmt.Sprintf("%d", 100+c-8))
			} else {
				p = append(p, "48", "5", fmt.Sprintf("%d", c))
			}
		} else if cell.IsBgRGB() {
			rgb := xterm.ToColorRGB(uint32(cell.GetBgColor()))
			p = append(p, "48", "2", fmt.Sprintf("%d", rgb[0]), fmt.Sprintf("%d", rgb[1]), fmt.Sprintf("%d", rgb[2]))
		}
	}

	return "\033[" + strings.Join(p, ";") + "m"
}

// getTerminalSize get terminal size, try stdin/stdout/stderr in order
// on Windows some terminal emulators (Windows Terminal) have stdin fd that is not a console handle,
// causing term.GetSize(stdin) to fail returning 0. Try three fds in order for compatibility.
func getTerminalSize() (int, int) {
	for _, fd := range []int{int(os.Stdin.Fd()), int(os.Stdout.Fd()), int(os.Stderr.Fd())} {
		if cols, rows, err := term.GetSize(fd); err == nil && cols > 0 && rows > 0 {
			return cols, rows
		}
	}
	return 80, 24
}

// rawTerminalPassthrough enter raw mode, passthrough stdin/stdout with WebSocket
// Ctrl+J enters command mode: ↑↓ scroll, K detach returns to menu, other keys exit command mode
// return true means kicked (caller should exit process)
func rawTerminalPassthrough(conn *websocket.Conn, sessionID string, sessionName string) bool {
	// ignore SIGTSTP (Ctrl+Z), prevent process stop in edge cases, ensure byte passthrough
	defer ignoreStopSignals()()

	// enter raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Printf("\r\nError: failed to enter raw mode: %v\r\n", err)
		return false
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)
	defer conn.Close() // close connection, let WS reader goroutine exit
	defer restoreAlternateScreen()

	initAlternateScreen()

	done := make(chan struct{})
	kicked := make(chan struct{}) // closed when kicked
	var intentionalDetach atomic.Bool // set to true on intentional Ctrl+J K detach, prevent WS disconnect from being misinterpreted as kick
	var inCommandMode atomic.Bool     // Ctrl+J enters command mode, status bar shows different hints based on this flag
	var closeOnce sync.Once
	safeClose := func() {
		closeOnce.Do(func() {
			close(done)
		})
	}

	// sync terminal size to PTY, ensure TUI apps (e.g. claude) use correct rows/cols layout
	cols, rows := getTerminalSize()
	termRows := rows - 1 // reserve top row for status bar
	if termRows < 1 {
		termRows = 1
	}
	conn.WriteJSON(Message{
		Type:      TypeResize,
		SessionID: sessionID,
		Cols:      cols,
		Rows:      termRows,
	})

	// ============================================================
	// local xterm-go terminal emulation — maintain screen state for rendering + local echo
	// ============================================================
	var termMu sync.Mutex
	localTerm := xterm.New(
		xterm.WithCols(cols),
		xterm.WithRows(termRows),
		xterm.WithScrollback(1000),
	)
	// dirty row tracking — single channel collects all dirty row signals, capacity 128 for burst output
	type renderSignal struct {
		allDirty bool // true = full redraw
		rowStart int  // [rowStart, rowEnd) dirty row range, ignored when allDirty
		rowEnd   int
	}
	var renderOverflow atomic.Bool
	renderCh := make(chan renderSignal, 128)
	sendRender := func(sig renderSignal) {
		select {
		case renderCh <- sig:
		default:
			renderOverflow.Store(true)
		}
	}
	stdoutCh := make(chan string, 4)

	// previous cursor position, for clearing cursor ghost
	prevCursorY := -1
	prevCursorX := -1

	// renderScreen render xterm-go viewport to user terminal
	// dirtySet: whether each row is dirty (index 0..nRows-1); ignored when allDirty=true, full render
	renderScreen := func(dirtySet []bool, allDirty bool) {
		// skip when no dirty rows (allDirty or resize may change to true inside lock)
		if !allDirty {
			hasDirty := false
			for _, d := range dirtySet {
				if d {
					hasDirty = true
					break
				}
			}
			if !hasDirty {
				return
			}
		}

		termMu.Lock()

		// detect terminal size change
		if newCols, newRows := getTerminalSize(); newCols > 0 && newRows > 0 {
			if newCols != cols || newRows != rows {
				cols, rows = newCols, newRows
				termRows = rows - 1
				if termRows < 1 {
					termRows = 1
				}
				localTerm.Resize(cols, termRows)
				allDirty = true
			}
		}

		buf := localTerm.Buffer()
		nRows := localTerm.Rows()
		nCols := localTerm.Cols()
		cell := xterm.NewCellData()
		var sb strings.Builder

		if allDirty {
			// ═══ full render: status bar + all rows ═══
			sb.Grow((nRows + 1) * (nCols*2 + 32))
			// disable auto-wrap: prevent terminal scroll when writing nCols chars on last row
			sb.WriteString("\033[?7l")
			// cursor home to first row
			sb.Write([]byte{'\033', '[', 'H'})

			// ══════════ top status bar (shows different hints based on command mode)══════════
			var statusText string
			if inCommandMode.Load() {
				sb.WriteString("\033[48;2;180;100;0m\033[38;2;255;255;255m")
				statusText = " " + sessionName + " CMD | ↑↓:scroll K:back other:resume "
			} else {
				sb.WriteString("\033[48;2;0;135;68m\033[38;2;255;255;255m")
				statusText = " " + sessionName + " | Ctrl+J:Enter Command Mode "
			}
			sb.WriteString(statusText)
			if pad := nCols - len(statusText); pad > 0 {
				sb.WriteString(strings.Repeat(" ", pad))
			}
			sb.WriteString("\033[0m")
			lastFg := uint32(0)
			lastBg := uint32(0)

			for row := 0; row < nRows; row++ {
				line := buf.Lines.Get(buf.YDisp + row)
				sb.WriteString(fmt.Sprintf("\033[%d;1H", row+2))
				lineLen := 0
				if line != nil {
					lineLen = line.Len
					if lineLen > nCols {
						lineLen = nCols
					}
				}
				for col := 0; col < nCols; col++ {
					if col < lineLen {
						line.LoadCell(col, cell)
					} else {
						cell.Fg = 0
						cell.Bg = 0
						cell.Content = 0
					}
					if cell.Fg != lastFg || cell.Bg != lastBg {
						sb.WriteString(sgrCode(cell))
						lastFg = cell.Fg
						lastBg = cell.Bg
					}
					ch := cell.GetChars()
					width := cell.GetWidth()
					if ch == "" {
						ch = " "
						width = 1
					}
					sb.WriteString(ch)
					if width > 1 && col+1 < nCols {
						col++
					}
				}
			}
		} else {
			// ═══ incremental render: only render dirty rows ═══
			sb.Grow(nCols*2 + 64) // at least one line
			sb.WriteString("\033[?7l")
			lastFg := uint32(0)
			lastBg := uint32(0)

			for row := 0; row < nRows; row++ {
				if row < len(dirtySet) && !dirtySet[row] {
					continue
				}
				line := buf.Lines.Get(buf.YDisp + row)
				// independently position each dirty row + reset SGR
				sb.WriteString(fmt.Sprintf("\033[%d;1H", row+2))
				sb.WriteString("\033[0m")
				lastFg = 0
				lastBg = 0
				lineLen := 0
				if line != nil {
					lineLen = line.Len
					if lineLen > nCols {
						lineLen = nCols
					}
				}
				for col := 0; col < nCols; col++ {
					if col < lineLen {
						line.LoadCell(col, cell)
					} else {
						cell.Fg = 0
						cell.Bg = 0
						cell.Content = 0
					}
					if cell.Fg != lastFg || cell.Bg != lastBg {
						sb.WriteString(sgrCode(cell))
						lastFg = cell.Fg
						lastBg = cell.Bg
					}
					ch := cell.GetChars()
					width := cell.GetWidth()
					if ch == "" {
						ch = " "
						width = 1
					}
					sb.WriteString(ch)
					if width > 1 && col+1 < nCols {
						col++
					}
				}
			}
		}

		// cursor rendering
		if !localTerm.IsCursorHidden() && localTerm.Buffer().YDisp == localTerm.Buffer().YBase {
			cy := localTerm.CursorY()
			cx := localTerm.CursorX()

			if useSystemCursor {
				// system cursor mode: just position the native terminal cursor,
				// terminal handles blinking natively — no custom rendering needed
				sb.WriteString(fmt.Sprintf("\033[%d;%dH", cy+2, cx+1))
			} else {
				// clear old cursor ghost: when cursor moves to different row, redraw the old cell position
				if prevCursorY >= 0 && (prevCursorY != cy || prevCursorX != cx) && prevCursorY < nRows && !allDirty {
					oldLine := buf.Lines.Get(buf.YDisp + prevCursorY)
					if oldLine != nil && prevCursorX < oldLine.Len && prevCursorX < nCols {
						oldCell := xterm.NewCellData()
						oldLine.LoadCell(prevCursorX, oldCell)
						sb.WriteString(fmt.Sprintf("\033[%d;%dH", prevCursorY+2, prevCursorX+1))
						sb.WriteString(sgrCode(oldCell))
						ch := oldCell.GetChars()
						if ch == "" {
							ch = " "
						}
						sb.WriteString(ch)
					}
				}

				// current cursor row dirty or full render → draw cursor
				if allDirty || (cy < len(dirtySet) && dirtySet[cy]) {
					sb.WriteString(fmt.Sprintf("\033[%d;%dH", cy+2, cx+1))
					if time.Now().UnixMilli()/500%2 == 0 {
						sb.WriteString("\033[48;2;255;255;255m\033[38;2;0;0;0m \033[0m")
						sb.WriteString(fmt.Sprintf("\033[%d;%dH", cy+2, cx+1))
					}
				}
				prevCursorY = cy
				prevCursorX = cx
			}
		}

		// restore auto-wrap
		sb.WriteString("\033[?7h")
		termMu.Unlock()
		if sb.Len() > 0 {
			select {
			case stdoutCh <- sb.String():
			default:
			}
		}
	}

	// OnRender → send dirty row range to renderCh
	localTerm.OnRender(func(r xterm.RowRange) {
		if r.Start == 0 && r.End == 0 {
			// CSI handler directly fires RowRange{} = full refresh (alt buffer etc.)
			sendRender(renderSignal{allDirty: true})
		} else {
			// DirtyRowTracker range [Start, End] inclusive
			sendRender(renderSignal{rowStart: r.Start, rowEnd: r.End + 1})
		}
		// always mark cursor row dirty, ensure cursor position is correct
		cy := localTerm.CursorY()
		sendRender(renderSignal{rowStart: cy, rowEnd: cy + 1})
	})

	// OnScroll → full redraw on scroll
	localTerm.OnScrollEmitter.Event(func(pos int) {
		sendRender(renderSignal{allDirty: true})
	})

	// stdout writer goroutine: async write to terminal, prevent renderScreen from blocking on slow terminal output
	go func() {
		for {
			select {
			case s := <-stdoutCh:
				os.Stdout.WriteString(s)
			case <-done:
				// after done closes, drain stdoutCh and discard residual frames
				// note: discard only, do not write, because kick/disconnect messages were written to os.Stdout directly, writing residual frames would overwrite
				for {
					select {
					case <-stdoutCh:
					default:
						return
					}
				}
			}
		}
	}()

	// render goroutine: drain renderCh then merge dirty rows, render in one frame
	renderDone := make(chan struct{})
	blinkTick := time.NewTicker(500 * time.Millisecond)
	defer blinkTick.Stop()
	go func() {
		defer close(renderDone)
		for {
			select {
			case <-blinkTick.C:
				if !useSystemCursor {
					// cursor blink → mark cursor row dirty
					cy := func() int {
						termMu.Lock()
						defer termMu.Unlock()
						return localTerm.CursorY()
					}()
					sendRender(renderSignal{rowStart: cy, rowEnd: cy + 1})
				}
			case sig := <-renderCh:
				// initialize with first signal + overflow flag
				allDirty := sig.allDirty || renderOverflow.Swap(false)
				dirtySet := make([]bool, localTerm.Rows())
				if !sig.allDirty {
					for row := sig.rowStart; row < sig.rowEnd && row < len(dirtySet); row++ {
						if row >= 0 {
							dirtySet[row] = true
						}
					}
				}
				// drain remaining renderCh signals, merge dirty row sets
			drain:
				for {
					select {
					case sig := <-renderCh:
						if sig.allDirty {
							allDirty = true
						} else {
							for row := sig.rowStart; row < sig.rowEnd && row < len(dirtySet); row++ {
								if row >= 0 {
									dirtySet[row] = true
								}
							}
						}
					default:
						break drain
					}
				}
				func() {
					defer func() { recover() }()
					renderScreen(dirtySet, allDirty)
				}()
			case <-done:
				return
			}
		}
	}()

	// initial render (full)
	renderScreen(nil, true)

	// SIGWINCH listener + 500ms poll fallback: immediately resize localTerm + notify daemon
	// Windows has no SIGWINCH, relies on polling to detect terminal size changes
	// on Unix both SIGWINCH and polling exist, polling is only a fallback
	{
		sigCh, cleanup := makeSigWinchListener()
		defer cleanup()
		pollTick := time.NewTicker(500 * time.Millisecond)
		defer pollTick.Stop()
		go func() {
			for {
				select {
				case <-sigCh:
					newCols, newRows := getTerminalSize()
					if newCols <= 0 || newRows <= 0 {
						continue
					}
					termMu.Lock()
					if newCols != cols || newRows != rows {
						cols, rows = newCols, newRows
						termRows = rows - 1
						if termRows < 1 {
							termRows = 1
						}
						localTerm.Resize(cols, termRows)
					}
					termMu.Unlock()
					// notify daemon PTY resize
					conn.WriteJSON(Message{
						Type:      TypeResize,
						SessionID: sessionID,
						Cols:      cols,
						Rows:      termRows,
					})
					// trigger full redraw
					sendRender(renderSignal{allDirty: true})
				case <-pollTick.C:
					newCols, newRows := getTerminalSize()
					if newCols <= 0 || newRows <= 0 {
						continue
					}
					if newCols != cols || newRows != rows {
						termMu.Lock()
						cols, rows = newCols, newRows
						termRows = rows - 1
						if termRows < 1 {
							termRows = 1
						}
						localTerm.Resize(cols, termRows)
						termMu.Unlock()
						// notify daemon PTY resize
						conn.WriteJSON(Message{
							Type:      TypeResize,
							SessionID: sessionID,
							Cols:      cols,
							Rows:      termRows,
						})
							// trigger full redraw
						sendRender(renderSignal{allDirty: true})
					}
				case <-done:
					return
				}
			}
		}()
	}

	// WS → xterm-go：read output and history data, write to local xterm-go
	go func() {
		defer func() {
			if r := recover(); r != nil {
				safeClose()
			}
		}()
		for {
			_, msgBytes, err := conn.ReadMessage()
			if err != nil {
				// connection closed (server close = kicked, intentional detach already flagged, not considered kicked)
				if !intentionalDetach.Load() {
					os.Stdout.Write([]byte("\r\n\033[31m*** connection lost ***\033[0m\r\n"))
					close(kicked)
				}
				safeClose()
				return
			}

			var msg Message
			if json.Unmarshal(msgBytes, &msg) != nil {
				continue
			}

			switch msg.Type {
			case TypeOutput, TypeHistoryData, TypeHistoryChunk:
				if len(msg.Data) > 0 {
					termMu.Lock()
					localTerm.Write([]byte(msg.Data))
					termMu.Unlock()
				}
			default:
				// ignore other types
			}
		}
	}()

	// stdin → WS：read keyboard input, Ctrl+J enters command mode, ↑↓ scroll, K detach
	go func() {
		buf := make([]byte, 4096)
		commandMode := false

		// scroll acceleration state
		var lastScrollTime time.Time
		var scrollAccel int     // current acceleration multiplier
		var scrollDir int       // last scroll direction: 1=down, -1=up

		for {
			n, err := readStdin(buf)
			if err != nil {
				safeClose()
				return
			}

			data := buf[:n]
			processed := make([]byte, 0, len(data))
			scrollHandled := false

			for i := 0; i < len(data); i++ {
				b := data[i]

				if commandMode {
					// ═══ command mode: ↑↓ scroll, K detach, other keys exit command mode ═══
					switch b {
					case 'k', 'K':
						// detach returns to menu
						intentionalDetach.Store(true)
						conn.WriteJSON(Message{Type: TypeDetach, SessionID: sessionID})
						safeClose()
						return
					case 0x1B:
						// detect ↑ (ESC [ A) or ↓ (ESC [ B)
						if i+2 < len(data) && data[i+1] == '[' {
							dir := 0
							switch data[i+2] {
							case 'A':
								dir = -1 // ↑ scroll up
							case 'B':
								dir = 1  // ↓ scroll down
							}
							if dir != 0 {
								i += 2

								// scroll acceleration: consecutive same direction gradually increases scroll lines
								now := time.Now()
								if dir == scrollDir && now.Sub(lastScrollTime) < 500*time.Millisecond {
									scrollAccel++
								} else {
									scrollAccel = 0
								}
								lastScrollTime = now
								scrollDir = dir

								// lines: 1 → 1 → 2 → 4 → 8 → 16 → 32 ...
								lines := 1
								if scrollAccel > 1 {
									lines = 1 << uint(min(scrollAccel-1, 5)) // max 32
								}

								termMu.Lock()
								localTerm.ScrollLines(dir * lines)
								termMu.Unlock()
								scrollHandled = true
								continue
							}
						}
						// ESC [ but not ↑↓, skip entire ESC sequence, exit command mode
						i += 2
					}
					// other keys: exit command mode, return to normal input
					commandMode = false
					inCommandMode.Store(false)
					sendRender(renderSignal{allDirty: true})
					continue

				}

				// ═══ normal mode ═══
				if b == 0x0A {
					// Ctrl+J → enter command mode
					commandMode = true
					inCommandMode.Store(true)
					scrollAccel = 0
					sendRender(renderSignal{allDirty: true})
					continue
				}


					// DECCKM translation: when program enables Application Cursor Keys (ESC[?1h),
					// it expects ESC O A/B/C/D for arrow keys instead of ESC [ A/B/C/D.
					// The user's terminal always sends normal-mode sequences (ESC [ X),
					// so we translate them when xterm-go's DECCKM is active.
					if b == 0x1B && i+2 < len(data) && data[i+1] == '[' {
						c := data[i+2]
						if c == 'A' || c == 'B' || c == 'C' || c == 'D' {
							termMu.Lock()
							appCursor := localTerm.DecPrivateModes().ApplicationCursorKeys
							termMu.Unlock()
							if appCursor {
								// Translate ESC [ X → ESC O X (application mode)
								processed = append(processed, 0x1B, 'O', c)
							} else {
								processed = append(processed, b, data[i+1], c)
							}
							i += 2
							continue
						}
					}
				// if scrolling, any input resets to bottom
				if localTerm.Buffer().YDisp < localTerm.Buffer().YBase {
					termMu.Lock()
					localTerm.ScrollReset()
					termMu.Unlock()
					sendRender(renderSignal{allDirty: true})
				}

				processed = append(processed, b)
			}

			if len(processed) > 0 {
				conn.WriteJSON(Message{
					Type:      TypeInput,
					SessionID: sessionID,
					Data:      string(processed),
				})
			}

				if scrollHandled {
					// scroll operation triggers full redraw
					sendRender(renderSignal{allDirty: true})
				}
			}
	}()

	<-done
	close(stdoutCh)

	select {
	case <-kicked:
		return true
	default:
		return false
	}
}
