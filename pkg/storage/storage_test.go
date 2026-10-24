package storage

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestClickHouseBatchWriter(t *testing.T) {
	var receivedRows int64

	// 模拟 ClickHouse HTTP 服务
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&receivedRows, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	writer := NewClickHouseWriter(mockServer.URL, "alinksec", 5, 50*time.Millisecond)
	defer writer.Close()

	// 推送 12 条安全事件
	for i := 0; i < 12; i++ {
		writer.WriteSecurityEvent(&SecurityEventRecord{
			EventID:    "evt-test",
			SourceType: "AGENT_WAF",
			AgentID:    "agent-01",
			HostIP:     "192.168.1.1",
			Hostname:   "web-01",
			EventTime:  time.Now(),
			Level:      "LEVEL_HIGH",
			Category:   "SQLI",
			Message:    "test injection",
		})
	}

	// 等待自动分批刷盘
	time.Sleep(150 * time.Millisecond)

	if atomic.LoadInt64(&receivedRows) == 0 {
		t.Fatal("expected at least one batch to be flushed to ClickHouse")
	}
}

func TestStorageEngineInterface(t *testing.T) {
	// 验证 StorageEngine 接口定义完整性
	var _ StorageEngine = (*PostgresEngine)(nil)
}
