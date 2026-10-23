package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"alinksec/pkg/logger"
)

// ClickHouseWriter 基于 HTTP 批量接口的高性能 ClickHouse 日志写入器
type ClickHouseWriter struct {
	endpoint      string
	database      string
	httpClient    *http.Client
	eventBatchCh  chan *SecurityEventRecord
	auditBatchCh  chan *AdminAuditRecord
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	flushInterval time.Duration
	batchSize     int
}

// NewClickHouseWriter 初始化 ClickHouse 高性能批处理写入管道
func NewClickHouseWriter(endpoint, database string, batchSize int, flushInterval time.Duration) *ClickHouseWriter {
	if batchSize <= 0 {
		batchSize = 200
	}
	if flushInterval <= 0 {
		flushInterval = 1 * time.Second
	}
	if database == "" {
		database = "alinksec"
	}

	ctx, cancel := context.WithCancel(context.Background())
	cw := &ClickHouseWriter{
		endpoint:      endpoint,
		database:      database,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		eventBatchCh:  make(chan *SecurityEventRecord, 50000),
		auditBatchCh:  make(chan *AdminAuditRecord, 10000),
		ctx:           ctx,
		cancel:        cancel,
		flushInterval: flushInterval,
		batchSize:     batchSize,
	}

	cw.wg.Add(2)
	go cw.eventWorker()
	go cw.auditWorker()

	logger.Info("ClickHouse production batch writer initialized", "endpoint", endpoint, "batch_size", batchSize)
	return cw
}

// WriteSecurityEvent 异步向写入队列推送安全威胁事件
func (cw *ClickHouseWriter) WriteSecurityEvent(event *SecurityEventRecord) {
	select {
	case cw.eventBatchCh <- event:
	default:
		logger.Warn("ClickHouse event channel full, dropping event to prevent backpressure blocking", "event_id", event.EventID)
	}
}

// WriteAdminAudit 异步向写入队列推送管理员审计记录
func (cw *ClickHouseWriter) WriteAdminAudit(audit *AdminAuditRecord) {
	select {
	case cw.auditBatchCh <- audit:
	default:
		logger.Warn("ClickHouse audit channel full, dropping audit record", "log_id", audit.LogID)
	}
}

func (cw *ClickHouseWriter) eventWorker() {
	defer cw.wg.Done()
	ticker := time.NewTicker(cw.flushInterval)
	defer ticker.Stop()

	batch := make([]*SecurityEventRecord, 0, cw.batchSize)

	for {
		select {
		case <-cw.ctx.Done():
			// Flush remaining
			for len(cw.eventBatchCh) > 0 {
				batch = append(batch, <-cw.eventBatchCh)
			}
			if len(batch) > 0 {
				_ = cw.flushEvents(batch)
			}
			return

		case ev := <-cw.eventBatchCh:
			batch = append(batch, ev)
			if len(batch) >= cw.batchSize {
				_ = cw.flushEvents(batch)
				batch = make([]*SecurityEventRecord, 0, cw.batchSize)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				_ = cw.flushEvents(batch)
				batch = make([]*SecurityEventRecord, 0, cw.batchSize)
			}
		}
	}
}

func (cw *ClickHouseWriter) auditWorker() {
	defer cw.wg.Done()
	ticker := time.NewTicker(cw.flushInterval)
	defer ticker.Stop()

	batch := make([]*AdminAuditRecord, 0, cw.batchSize)

	for {
		select {
		case <-cw.ctx.Done():
			for len(cw.auditBatchCh) > 0 {
				batch = append(batch, <-cw.auditBatchCh)
			}
			if len(batch) > 0 {
				_ = cw.flushAudits(batch)
			}
			return

		case aud := <-cw.auditBatchCh:
			batch = append(batch, aud)
			if len(batch) >= cw.batchSize {
				_ = cw.flushAudits(batch)
				batch = make([]*AdminAuditRecord, 0, cw.batchSize)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				_ = cw.flushAudits(batch)
				batch = make([]*AdminAuditRecord, 0, cw.batchSize)
			}
		}
	}
}

func (cw *ClickHouseWriter) flushEvents(batch []*SecurityEventRecord) error {
	var buf bytes.Buffer
	for _, item := range batch {
		data, err := json.Marshal(item)
		if err != nil {
			continue
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	query := fmt.Sprintf("INSERT INTO %s.security_events FORMAT JSONEachRow", cw.database)
	endpoint := fmt.Sprintf("%s/?query=%s", cw.endpoint, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(cw.ctx, "POST", endpoint, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cw.httpClient.Do(req)
	if err != nil {
		logger.Warn("Failed to flush events to ClickHouse (running in offline/disconnected mode)", "count", len(batch), "err", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		logger.Error("ClickHouse rejected event batch insert", "status", resp.StatusCode, "body", string(body))
		return fmt.Errorf("clickhouse error %d: %s", resp.StatusCode, string(body))
	}

	logger.Debug("Flushed security events batch to ClickHouse successfully", "count", len(batch))
	return nil
}

func (cw *ClickHouseWriter) flushAudits(batch []*AdminAuditRecord) error {
	var buf bytes.Buffer
	for _, item := range batch {
		data, err := json.Marshal(item)
		if err != nil {
			continue
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	query := fmt.Sprintf("INSERT INTO %s.admin_audit_logs FORMAT JSONEachRow", cw.database)
	endpoint := fmt.Sprintf("%s/?query=%s", cw.endpoint, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(cw.ctx, "POST", endpoint, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cw.httpClient.Do(req)
	if err != nil {
		logger.Warn("Failed to flush admin audits to ClickHouse (offline/disconnected mode)", "count", len(batch), "err", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		logger.Error("ClickHouse rejected audit batch insert", "status", resp.StatusCode, "body", string(body))
		return fmt.Errorf("clickhouse audit error %d: %s", resp.StatusCode, string(body))
	}

	logger.Debug("Flushed admin audit batch to ClickHouse successfully", "count", len(batch))
	return nil
}

// Close 安全平滑退出 ClickHouse 写入管道
func (cw *ClickHouseWriter) Close() error {
	cw.cancel()
	cw.wg.Wait()
	logger.Info("ClickHouse batch writer closed")
	return nil
}
