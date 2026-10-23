package tamper

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// BaselineVault 安全基线备份库
type BaselineVault struct {
	mu        sync.RWMutex
	watchDir  string
	backupDir string
	records   map[string]FileRecord // key: relPath
	extFilter map[string]bool
}

// NewBaselineVault 初始化安全基线库
func NewBaselineVault(watchDir, backupDir string, exts []string) (*BaselineVault, error) {
	absWatch, err := filepath.Abs(watchDir)
	if err != nil {
		return nil, err
	}
	absBackup, err := filepath.Abs(backupDir)
	if err != nil {
		return nil, err
	}

	filter := make(map[string]bool)
	for _, ext := range exts {
		filter[strings.ToLower(ext)] = true
	}

	vault := &BaselineVault{
		watchDir:  absWatch,
		backupDir: absBackup,
		records:   make(map[string]FileRecord),
		extFilter: filter,
	}

	if err := os.MkdirAll(absBackup, 0700); err != nil {
		return nil, fmt.Errorf("create backup dir failed: %w", err)
	}

	return vault, nil
}

// BuildBaseline 遍历扫描 watchDir 生成基线并将文件安全同步到隔离备份目录
func (v *BaselineVault) BuildBaseline() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.records = make(map[string]FileRecord)

	err := filepath.Walk(v.watchDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(v.watchDir, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(filepath.Clean(relPath))

		// 忽略备份目录自身或临时文件
		if strings.HasPrefix(relPath, ".") || strings.Contains(relPath, string(filepath.Separator)+".") {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if len(v.extFilter) > 0 && !v.extFilter[ext] {
			return nil
		}

		hash, err := computeFileHash(path)
		if err != nil {
			return err
		}

		rec := FileRecord{
			RelPath:  relPath,
			FullPath: path,
			SHA256:   hash,
			Size:     info.Size(),
			Mode:     uint32(info.Mode()),
		}

		v.records[relPath] = rec

		// 备份至安全隔离库
		backupPath := filepath.Join(v.backupDir, relPath)
		if err := copyFile(path, backupPath); err != nil {
			return fmt.Errorf("backup file %s failed: %w", relPath, err)
		}

		return nil
	})

	return err
}

// GetRecord 查询指定相对路径的基线
func (v *BaselineVault) GetRecord(relPath string) (FileRecord, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	rec, ok := v.records[relPath]
	return rec, ok
}

// RestoreFile 从基线安全库恢复被篡改或删除的文件 (自愈核心)
func (v *BaselineVault) RestoreFile(relPath string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	backupPath := filepath.Join(v.backupDir, relPath)
	targetPath := filepath.Join(v.watchDir, relPath)

	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("backup file %s not found in vault: %w", relPath, err)
	}

	return copyFile(backupPath, targetPath)
}

// QuarantineUnauthorizedFile 隔离/清除未经授权新增的后门文件 (如非法上传的 webshell)
func (v *BaselineVault) QuarantineUnauthorizedFile(relPath string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	targetPath := filepath.Join(v.watchDir, relPath)
	return os.Remove(targetPath)
}

func computeFileHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
