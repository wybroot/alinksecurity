package tamper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/crypto"
	"alinksec/pkg/logger"
	"github.com/fsnotify/fsnotify"
)

type TamperEventHandler func(event TamperEvent)

// Watcher 实时文件系统篡改监控器
type Watcher struct {
	mu           sync.RWMutex
	fsWatcher    *fsnotify.Watcher
	vault        *BaselineVault
	watchDir     string
	autoRevert   bool
	maintenance  bool
	onTamper     TamperEventHandler
	extFilter    map[string]bool
	debounceMap  map[string]time.Time
	debounceLock sync.Mutex
}

// NewWatcher 创建防篡改监听器
func NewWatcher(vault *BaselineVault, watchDir string, autoRevert bool, exts []string, onTamper TamperEventHandler) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	absWatch, err := filepath.Abs(watchDir)
	if err != nil {
		return nil, err
	}

	filter := make(map[string]bool)
	for _, ext := range exts {
		filter[strings.ToLower(ext)] = true
	}

	w := &Watcher{
		fsWatcher:   fsw,
		vault:       vault,
		watchDir:    absWatch,
		autoRevert:  autoRevert,
		onTamper:    onTamper,
		extFilter:   filter,
		debounceMap: make(map[string]time.Time),
	}

	return w, nil
}

// SetMaintenanceMode 切换维护模式 (处于维护模式时不触发告警与自愈)
func (w *Watcher) SetMaintenanceMode(enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.maintenance = enabled
	logger.Info("Tamper protection maintenance mode changed", "enabled", enabled)
}

// Start 开始监听文件系统事件
func (w *Watcher) Start(ctx context.Context) error {
	// 递归为 watchDir 及其所有子目录挂载监听
	err := filepath.Walk(w.watchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if path != w.watchDir {
				base := filepath.Base(path)
				if strings.HasPrefix(base, ".") {
					return filepath.SkipDir
				}
			}
			return w.fsWatcher.Add(path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	go w.eventLoop(ctx)
	return nil
}

// Stop 停止监控
func (w *Watcher) Stop() error {
	return w.fsWatcher.Close()
}

func (w *Watcher) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-w.fsWatcher.Errors:
			if !ok {
				return
			}
			logger.Error("Watcher filesystem error", "err", err)
		case event, ok := <-w.fsWatcher.Events:
			if !ok {
				return
			}
			w.handleFSEvent(event)
		}
	}
}

func (w *Watcher) handleFSEvent(event fsnotify.Event) {
	w.mu.RLock()
	inMaintenance := w.maintenance
	w.mu.RUnlock()

	if inMaintenance {
		return
	}

	relPath, err := filepath.Rel(w.watchDir, event.Name)
	if err != nil || strings.HasPrefix(filepath.Base(event.Name), ".") {
		return
	}
	relPath = filepath.ToSlash(filepath.Clean(relPath))

	// 过滤文件后缀
	ext := strings.ToLower(filepath.Ext(event.Name))
	// 如果是新创建目录，自动加入监听
	if event.Has(fsnotify.Create) {
		fi, err := os.Stat(event.Name)
		if err == nil && fi.IsDir() {
			_ = w.fsWatcher.Add(event.Name)
			return
		}
	}

	if len(w.extFilter) > 0 && !w.extFilter[ext] {
		return
	}

	baseRecord, existsInBaseline := w.vault.GetRecord(relPath)

	// 1. 处理文件删除 (Remove / Rename)
	if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
		if existsInBaseline {
			w.triggerTamper(TamperEvent{
				FilePath:    relPath,
				Action:      ActionDeleted,
				Level:       pb.EventLevel_LEVEL_CRITICAL,
				OldHash:     baseRecord.SHA256,
				Description: "Protected web file was deleted or renamed without authorization",
			})
		}
		return
	}

	// 2. 处理文件非法修改 (Write)
	if event.Has(fsnotify.Write) {
		if existsInBaseline {
			currHash, err := computeFileHash(event.Name)
			if err == nil && currHash != baseRecord.SHA256 {
				w.triggerTamper(TamperEvent{
					FilePath:    relPath,
					Action:      ActionModified,
					Level:       pb.EventLevel_LEVEL_CRITICAL,
					OldHash:     baseRecord.SHA256,
					NewHash:     currHash,
					Description: "Protected web file content was illegally tampered with",
				})
			}
		}
		return
	}

	// 3. 处理新增文件 (Create)
	if event.Has(fsnotify.Create) {
		if !existsInBaseline {
			currHash, _ := computeFileHash(event.Name)
			w.triggerTamper(TamperEvent{
				FilePath:    relPath,
				Action:      ActionCreated,
				Level:       pb.EventLevel_LEVEL_CRITICAL,
				NewHash:     currHash,
				Description: "Unauthorized suspicious web file/WebShell created in publish tree",
			})
		}
	}
}

func (w *Watcher) triggerTamper(evt TamperEvent) {
	evt.Timestamp = time.Now().Unix()
	evt.EventID, _ = crypto.GenerateSecureToken(16)

	// 若开启自愈恢复，毫秒级执行复原或隔离
	if w.autoRevert {
		switch evt.Action {
		case ActionModified, ActionDeleted:
			if err := w.vault.RestoreFile(evt.FilePath); err != nil {
				logger.Error("Failed to auto-revert tampered file", "file", evt.FilePath, "err", err)
			} else {
				evt.Reverted = true
				logger.Info("Instant Auto-Reversion Succeeded! File restored from baseline vault",
					"file", evt.FilePath,
					"action", evt.Action,
				)
			}
		case ActionCreated:
			if err := w.vault.QuarantineUnauthorizedFile(evt.FilePath); err != nil {
				logger.Error("Failed to quarantine unauthorized file", "file", evt.FilePath, "err", err)
			} else {
				evt.Reverted = true
				logger.Info("Quarantined unauthorized file immediately!", "file", evt.FilePath)
			}
		}
	}

	if w.onTamper != nil {
		w.onTamper(evt)
	}
}
