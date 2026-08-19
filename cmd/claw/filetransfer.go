package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const transFilesDir = ".clianywhere/transfiles"

// StagedFileEntry internal staged file entry (includes local path)
type StagedFileEntry struct {
	Info       StagedFile // protocol struct
	FilePath   string     // ~/.clianywhere/transfiles/ full path under
}

// FileTransferManager manage file staging list and send tasks
type FileTransferManager struct {
	mu     sync.Mutex
	active map[uint32]*FileSendTask // active transfer tasks
	staged []StagedFileEntry       // staged file list
	daemon *Daemon
	logger Logger
	nextID uint32
	stagedDir string // ~/.clianywhere/transfiles
}

// FileSendTask single file send task
type FileSendTask struct {
	ID          uint32
	FileName    string
	FilePath    string
	FileSize    int64
	TotalChunks int
	SentChunks  int
	StartTime   time.Time
	cancel      chan struct{}
}

// NewFileTransferManager create file transfer manager
func NewFileTransferManager(d *Daemon, logger Logger) *FileTransferManager {
	ftm := &FileTransferManager{
		daemon:    d,
		logger:   logger,
		active:   make(map[uint32]*FileSendTask),
		staged:   make([]StagedFileEntry, 0),
	}

	// initialize staging directory, clear old files
	home, err := os.UserHomeDir()
	if err != nil {
		fatalExit("failed to get HOME directory: %v", err)
	}
	ftm.stagedDir = filepath.Join(home, transFilesDir)

	// clear staging directory
	os.RemoveAll(ftm.stagedDir)
	if err := os.MkdirAll(ftm.stagedDir, 0755); err != nil {
		fatalExit("failed to create staging directory %s: %v", ftm.stagedDir, err)
	}

	return ftm
}

// StageFile copy file to staging directory, add to list, notify frontend
func (ftm *FileTransferManager) StageFile(srcPath string) error {
	absPath, err := filepath.Abs(srcPath)
	if err != nil {
		return fmt.Errorf("path resolution failed: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("file does not exist: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("sending directories is not yet supported")
	}

	origName := filepath.Base(absPath)
	ext := filepath.Ext(origName)
	nameWithoutExt := origName[:len(origName)-len(ext)]
	timeStr := time.Now().Format("20060102150405")
	stagedName := nameWithoutExt + "_" + timeStr + ext

	// allocate ID
	fileID := atomic.AddUint32(&ftm.nextID, 1)

	dstPath := filepath.Join(ftm.stagedDir, stagedName)

	// copy file
	src, err := os.Open(absPath)
	if err != nil {
		return fmt.Errorf("open source file failed: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("create staged file failed: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		os.Remove(dstPath)
		return fmt.Errorf("copy file failed: %w", err)
	}

	entry := StagedFileEntry{
		Info: StagedFile{
			ID:           fileID,
			FileName:     stagedName,
			OriginalName: origName,
			Size:         info.Size(),
			Time:         timeStr,
		},
		FilePath: dstPath,
	}

	ftm.mu.Lock()
	ftm.staged = append(ftm.staged, entry)
	ftm.mu.Unlock()


	// notify frontend file list
	ftm.sendFileList()

	return nil
}

// sendFileList send current staged list to frontend
func (ftm *FileTransferManager) sendFileList() {
	ftm.mu.Lock()
	files := make([]StagedFile, 0, len(ftm.staged))
	for _, entry := range ftm.staged {
		files = append(files, entry.Info)
	}
	ftm.mu.Unlock()

	ftm.daemon.sendJSON(&Message{
		Type:  TypeFileList,
		Files: files,
	})
}

// HandleRequest handle frontend request to transfer a file
func (ftm *FileTransferManager) HandleRequest(fileID uint32) error {
	ftm.mu.Lock()
	var entry *StagedFileEntry
	for i, e := range ftm.staged {
		if e.Info.ID == fileID {
			entry = &ftm.staged[i]
			break
		}
	}
	if entry == nil {
		ftm.mu.Unlock()
		return fmt.Errorf("file does not exist (id=%d)", fileID)
	}
	ftm.mu.Unlock()


	// use original send logic
	if err := ftm.startSendFromStaged(entry.FilePath); err != nil {
		return err
	}

	// keep in staged list, only HandleDelete removes it

	return nil
}

// HandleDelete handle frontend delete file request
func (ftm *FileTransferManager) HandleDelete(fileID uint32) {
	ftm.mu.Lock()
	defer ftm.mu.Unlock()

	idx := -1
	for i, e := range ftm.staged {
		if e.Info.ID == fileID {
			idx = i
			break
		}
	}

	if idx >= 0 {
		entry := ftm.staged[idx]
		// delete staged file
		os.Remove(entry.FilePath)
		ftm.staged = append(ftm.staged[:idx], ftm.staged[idx+1:]...)
	}

	// if transferring, also cancel
	if task, ok := ftm.active[fileID]; ok {
		close(task.cancel)
	}
}

// startSendFromStaged start sending file from staging directory
func (ftm *FileTransferManager) startSendFromStaged(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("file does not exist: %w", err)
	}

	fileSize := info.Size()
	fileName := filepath.Base(filePath)
	chunkSize := ftm.daemon.cfg.ChunkSize
	secureOverhead := 0
	if ftm.daemon.secureActive() {
		secureOverhead = SecureBinaryOverhead // encrypted binary envelope
	}
	if chunkSize <= 0 || chunkSize > MaxFrameSize-9-secureOverhead {
		chunkSize = MaxFrameSize - 9 - secureOverhead // 9-byte file transfer header
	}
	totalChunks := int((fileSize + int64(chunkSize) - 1) / int64(chunkSize))
	if totalChunks == 0 {
		totalChunks = 1
	}

	fileID := atomic.AddUint32(&ftm.nextID, 1)
	task := &FileSendTask{
		ID:          fileID,
		FileName:    fileName,
		FilePath:    filePath,
		FileSize:    fileSize,
		TotalChunks: totalChunks,
		StartTime:   time.Now(),
		cancel:      make(chan struct{}),
	}

	ftm.mu.Lock()
	ftm.active[fileID] = task
	ftm.mu.Unlock()


	ftm.daemon.sendJSON(&Message{
		Type:        TypeFileSendBegin,
		FileID:      fileID,
		FileName:    fileName,
		FileSize:    fileSize,
		TotalChunks: totalChunks,
	})

	go ftm.sendFile(task, chunkSize)

	return nil
}

// StartSend compat with old interface (IPC send command changed to stage)
func (ftm *FileTransferManager) StartSend(filePath string) error {
	return ftm.StageFile(filePath)
}

// sendFile background read file and send binary chunks
func (ftm *FileTransferManager) sendFile(task *FileSendTask, chunkSize int) {
	defer func() {
		ftm.mu.Lock()
		delete(ftm.active, task.ID)
		ftm.mu.Unlock()
	}()

	f, err := os.Open(task.FilePath)
	if err != nil {
		ftm.daemon.sendJSON(&Message{
			Type:   TypeFileSendError,
			FileID: task.ID,
			Error:  fmt.Sprintf("open file failed: %v", err),
		})
		return
	}
	defer f.Close()

	hash := sha256.New()
	buf := make([]byte, chunkSize)
	header := make([]byte, 9)

	for chunkIdx := 0; chunkIdx < task.TotalChunks; chunkIdx++ {
		select {
		case <-task.cancel:
			ftm.daemon.sendJSON(&Message{
				Type:   TypeFileSendCancel,
				FileID: task.ID,
			})
			return
		default:
		}

		n, err := io.ReadFull(f, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			ftm.daemon.sendJSON(&Message{
				Type:   TypeFileSendError,
				FileID: task.ID,
				Error:  fmt.Sprintf("read failed: %v", err),
			})
			return
		}
		if n == 0 {
			break
		}

		hash.Write(buf[:n])

		header[0] = OpcodeFileTransfer
		binary.BigEndian.PutUint32(header[1:5], task.ID)
		binary.BigEndian.PutUint32(header[5:9], uint32(chunkIdx))

		frame := make([]byte, 9+n)
		copy(frame[0:9], header)
		copy(frame[9:], buf[:n])

		if len(frame) > 31*1024 {
		}
		sent := ftm.daemon.sendBytesCancelable(frame, 256*1024, task.cancel)
		if !sent {
			return
		}

		task.SentChunks = chunkIdx + 1

	}
	checksum := fmt.Sprintf("%x", hash.Sum(nil))

	endJSON, _ := json.Marshal(&Message{
		Type:     TypeFileSendEnd,
		FileID:   task.ID,
		Checksum: checksum,
	})
	ctrlFrame := make([]byte, 9+len(endJSON))
	ctrlFrame[0] = OpcodeFileTransfer
	copy(ctrlFrame[9:], endJSON)
	ftm.daemon.sendBytesCancelable(ctrlFrame, 256*1024, task.cancel)
}

// Cancel cancel sending of specific file
func (ftm *FileTransferManager) Cancel(fileID uint32) {
	ftm.mu.Lock()
	task, ok := ftm.active[fileID]
	ftm.mu.Unlock()

	if ok {
		close(task.cancel)
	}
}

// CancelAll cancel all file sends
func (ftm *FileTransferManager) CancelAll() {
	ftm.mu.Lock()
	defer ftm.mu.Unlock()

	for _, task := range ftm.active {
		close(task.cancel)
	}
	ftm.active = make(map[uint32]*FileSendTask)
}

// handleIPCUpload handle HTTP IPC file send request (daemon send command)
func (ftm *FileTransferManager) handleIPCUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}

	if err := ftm.StageFile(req.Path); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"msg":    "file added to transfer list",
	})
}

// HandleDirListRequest handle directory list request
func (ftm *FileTransferManager) HandleDirListRequest(reqPath string) {
	targetPath := reqPath
	if targetPath == "" {
		// Windows: show all drive letters
		if runtime.GOOS == "windows" {
			ftm.sendDriveList()
			return
		}
		// non-Windows: default open home
		home, err := os.UserHomeDir()
		if err != nil {
			ftm.daemon.sendJSON(&Message{
				Type:  TypeDirList,
				Path:  "",
				Error: err.Error(),
			})
			return
		}
		targetPath = home
	}

	// frontend uses / as separator uniformly, convert to system separator for local file operations
	targetPath = filepath.Clean(strings.ReplaceAll(targetPath, "/", string(filepath.Separator)))

	// Windows: "C:" is current directory not root, need to append separator
	// Windows: "C:" and "C:." are not root, need to append separator
	// filepath.Clean("C:") returns "C:." on Windows, need to handle both
	if len(targetPath) >= 2 && targetPath[1] == ':' {
		rest := targetPath[2:]
		if rest == "" || rest == "." {
			targetPath = targetPath[:2] + string(filepath.Separator)
		}
	}

	entries, err := os.ReadDir(targetPath)
	if err != nil {
		ftm.daemon.sendJSON(&Message{
			Type:  TypeDirList,
			Path:  toForwardSlash(targetPath),
			Error: err.Error(),
		})
		return
	}

	var dirs, files []DirEntry
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		entry := DirEntry{
			Name:    e.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime().UnixMilli(),
		}
		if e.IsDir() {
			dirs = append(dirs, entry)
		} else {
			files = append(files, entry)
		}
	}

	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name < dirs[j].Name })
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	ftm.daemon.sendJSON(&Message{
		Type: TypeDirList,
		Path: toForwardSlash(targetPath),
		Entries: &DirEntries{
			Dirs:  dirs,
			Files: files,
		},
	})
}

// HandleReqPending handle remote file add-to-pending request
func (ftm *FileTransferManager) HandleReqPending(filePath string) error {
	// frontend uses / separator, convert to system separator
	localPath := filepath.Clean(strings.ReplaceAll(filePath, "/", string(filepath.Separator)))
	return ftm.StageFile(localPath)
}

// toForwardSlash convert system path to / separator (for frontend), ensure drive letter has trailing slash
func toForwardSlash(path string) string {
	p := strings.ReplaceAll(path, "\\", "/")
	if len(p) >= 2 && p[1] == ':' {
		rest := p[2:]
		if rest == "" || rest == "." {
			p = p[:2] + "/"
		}
	}
	return p
}

// sendDriveList list all available drives concurrently, 1s timeout per drive (Windows only)
func (ftm *FileTransferManager) sendDriveList() {
	type result struct {
		name string
		ok   bool
	}
	ch := make(chan result, 26)

	for _, letter := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		go func(l rune) {
			drivePath := string(l) + ":" + string(filepath.Separator)
			ok := false
			done := make(chan struct{})
			go func() {
				fi, err := os.Stat(drivePath)
				ok = err == nil && fi.IsDir()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			ch <- result{name: string(l) + ":", ok: ok}
		}(letter)
	}

	var dirs []DirEntry
	for i := 0; i < 26; i++ {
		r := <-ch
		if r.ok {
			dirs = append(dirs, DirEntry{Name: r.name, Size: 0})
		}
	}

	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name < dirs[j].Name })
	ftm.daemon.sendJSON(&Message{
		Type: TypeDirList,
		Path: "",
		Entries: &DirEntries{
			Dirs:  dirs,
			Files: []DirEntry{},
		},
	})
}
