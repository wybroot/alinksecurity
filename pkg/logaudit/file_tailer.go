package logaudit

import (
	"bufio"
	"context"
	"io"
	"os"
	"time"

	"alinksec/pkg/logger"
)

// FileTailer 生产级本地日志文件增量追随器
type FileTailer struct {
	filePath string
	source   LogSourceType
	coll     *Collector
}

// NewFileTailer 创建文件增量追踪器
func NewFileTailer(filePath string, source LogSourceType, coll *Collector) *FileTailer {
	return &FileTailer{
		filePath: filePath,
		source:   source,
		coll:     coll,
	}
}

// Start 启动增量追踪
func (t *FileTailer) Start(ctx context.Context) {
	file, err := os.Open(t.filePath)
	if err != nil {
		logger.Warn("Cannot open log file for tailing, will retry periodically", "file", t.filePath, "err", err)
		t.retryLoop(ctx)
		return
	}
	defer file.Close()

	// 移动至文件末尾 (增量模式)
	_, _ = file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				time.Sleep(500 * time.Millisecond)
				continue
			}

			if len(line) > 0 {
				t.coll.PushLog(t.source, t.filePath, line)
			}
		}
	}
}

func (t *FileTailer) retryLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := os.Stat(t.filePath); err == nil {
				go t.Start(ctx)
				return
			}
		}
	}
}
