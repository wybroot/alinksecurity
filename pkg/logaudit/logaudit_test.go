package logaudit

import (
	"testing"
	"time"
)

func TestCollectorBatchingAndSha256(t *testing.T) {
	var batches []*LogBatch
	cfg := &CollectorConfig{
		AgentID:       "test-agent",
		Host:          "node-01",
		BatchSize:     3,
		FlushInterval: 10 * time.Second,
	}

	collector := NewCollector(cfg, func(batch *LogBatch) {
		batches = append(batches, batch)
	})

	// 写入 2 条日志，未达 batchSize
	collector.PushLog(SourceSyslog, "/var/log/auth.log", "Failed password for root from 1.2.3.4")
	collector.PushLog(SourceSyslog, "/var/log/auth.log", "Failed password for admin from 1.2.3.4")
	if len(batches) != 0 {
		t.Fatalf("expected 0 batches before batchSize reached, got %d", len(batches))
	}

	// 写入第 3 条，达到 batchSize 自动 Flush
	collector.PushLog(SourceSyslog, "/var/log/auth.log", "Failed password for user1 from 1.2.3.4")
	if len(batches) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(batches))
	}

	b := batches[0]
	if b.Count != 3 {
		t.Errorf("expected 3 entries, got %d", b.Count)
	}
	if b.BatchSha256 == "" || len(b.BatchSha256) != 64 {
		t.Errorf("invalid batch sha256: %s", b.BatchSha256)
	}
}

func TestRetentionProofComplianceCheck(t *testing.T) {
	now := time.Now()

	// 1. 合规测试: 留存 185 天且哈希链完整
	oldestCompliant := now.AddDate(0, 0, -185)
	proof := GenerateRetentionProof(oldestCompliant, now, 500000, true)
	if !proof.IsCompliant {
		t.Errorf("expected proof to be compliant for 185 days, got non-compliant: %s", proof.AuditorNotes)
	}
	if proof.TotalRetainedDays != 185 {
		t.Errorf("expected 185 days, got %d", proof.TotalRetainedDays)
	}

	// 2. 不合规测试: 仅留存 90 天
	oldestNonCompliant := now.AddDate(0, 0, -90)
	proofFail1 := GenerateRetentionProof(oldestNonCompliant, now, 200000, true)
	if proofFail1.IsCompliant {
		t.Errorf("expected proof to FAIL for 90 days, but it passed")
	}

	// 3. 不合规测试: 留存 200 天但哈希链断裂
	proofFail2 := GenerateRetentionProof(now.AddDate(0, 0, -200), now, 200000, false)
	if proofFail2.IsCompliant {
		t.Errorf("expected proof to FAIL when integrityChainValid is false")
	}
}

func TestLogAgentIngestAndFlush(t *testing.T) {
	cfg := &AgentConfig{
		AgentID:    "test-log-agent",
		Hostname:   "test-host",
		Standalone: true,
	}

	agent := NewLogAgent(cfg)

	var receivedBatches []*LogBatch
	agent.SetBatchCallback(func(batch *LogBatch) {
		receivedBatches = append(receivedBatches, batch)
	})

	if err := agent.Start(); err != nil {
		t.Fatalf("failed to start LogAgent: %v", err)
	}

	for i := 0; i < 5; i++ {
		agent.IngestLog(SourceNginx, "/var/log/nginx/access.log", "GET /api/v1/health 200")
	}

	agent.Stop()

	collected, _ := agent.GetMetrics()
	if collected != 5 {
		t.Errorf("expected 5 collected logs, got %d", collected)
	}

	if len(receivedBatches) == 0 {
		t.Errorf("expected at least 1 flushed batch upon Stop()")
	}
}
