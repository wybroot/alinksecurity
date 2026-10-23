package logaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// CollectorConfig 采集器参数
type CollectorConfig struct {
	AgentID       string        `json:"agent_id"`
	Host          string        `json:"host"`
	BatchSize     int           `json:"batch_size"`     // 默认 100 条批量打包
	FlushInterval time.Duration `json:"flush_interval"` // 默认 2 秒强制刷盘
}

// Collector 日志收集与防篡改批次组装器
type Collector struct {
	cfg       *CollectorConfig
	mu        sync.Mutex
	buffer    []*LogEntry
	lastFlush time.Time
	onBatch   func(batch *LogBatch)
}

// NewCollector 创建日志采集器
func NewCollector(cfg *CollectorConfig, onBatch func(batch *LogBatch)) *Collector {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 2 * time.Second
	}
	return &Collector{
		cfg:       cfg,
		buffer:    make([]*LogEntry, 0, cfg.BatchSize),
		lastFlush: time.Now(),
		onBatch:   onBatch,
	}
}

// PushLog 推入单条采集日志
func (c *Collector) PushLog(source LogSourceType, filePath, message string) {
	msgHash := sha256.Sum256([]byte(message))
	entry := &LogEntry{
		ID:        fmt.Sprintf("log-%d", time.Now().UnixNano()%10000000),
		Timestamp: time.Now(),
		Source:    source,
		Host:      c.cfg.Host,
		FilePath:  filePath,
		Message:   strings.TrimRight(message, "\r\n"),
		Sha256:    hex.EncodeToString(msgHash[:]),
	}

	c.mu.Lock()
	c.buffer = append(c.buffer, entry)
	shouldFlush := len(c.buffer) >= c.cfg.BatchSize || time.Since(c.lastFlush) >= c.cfg.FlushInterval
	c.mu.Unlock()

	if shouldFlush {
		c.Flush()
	}
}

// Flush 强制将当前缓冲池的日志组装为防篡改批次并提交
func (c *Collector) Flush() *LogBatch {
	c.mu.Lock()
	if len(c.buffer) == 0 {
		c.mu.Unlock()
		return nil
	}

	entries := c.buffer
	c.buffer = make([]*LogEntry, 0, c.cfg.BatchSize)
	c.lastFlush = time.Now()
	c.mu.Unlock()

	// 计算批次哈希: SHA256(所有 entry.Sha256 拼接)
	var sb strings.Builder
	for _, e := range entries {
		sb.WriteString(e.Sha256)
	}
	batchHash := sha256.Sum256([]byte(sb.String()))

	batch := &LogBatch{
		BatchID:     fmt.Sprintf("batch-%s-%d", c.cfg.AgentID, time.Now().UnixNano()),
		CreatedAt:   time.Now(),
		AgentID:     c.cfg.AgentID,
		Count:       len(entries),
		Entries:     entries,
		BatchSha256: hex.EncodeToString(batchHash[:]),
	}

	if c.onBatch != nil {
		c.onBatch(batch)
	}

	return batch
}
