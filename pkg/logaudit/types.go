package logaudit

import "time"

// LogSourceType 日志数据源类型
type LogSourceType string

const (
	SourceSyslog   LogSourceType = "SYSLOG"   // 系统登录鉴权日志 (/var/log/secure, /var/log/auth.log)
	SourceNginx    LogSourceType = "NGINX"    // Web 反代与访问日志
	SourceWAF      LogSourceType = "WAF"      // WAF 拦截日志
	SourceDB       LogSourceType = "DATABASE" // 数据库操作审计日志
	SourceApp      LogSourceType = "APP"      // 业务应用关键日志
)

// LogEntry 采集的单条日志记录
type LogEntry struct {
	ID        string        `json:"id"`
	Timestamp time.Time     `json:"timestamp"`
	Source    LogSourceType `json:"source"`
	Host      string        `json:"host"`
	FilePath  string        `json:"file_path,omitempty"`
	Message   string        `json:"message"`
	Sha256    string        `json:"sha256"` // 单条日志内容哈希
}

// LogBatch 日志防篡改校验块 (用于批量落盘与 ClickHouse 存储)
type LogBatch struct {
	BatchID     string      `json:"batch_id"`
	CreatedAt   time.Time   `json:"created_at"`
	AgentID     string      `json:"agent_id"`
	Count       int         `json:"count"`
	Entries     []*LogEntry `json:"entries"`
	BatchSha256 string      `json:"batch_sha256"` // 批次汇总 Merkle/链式哈希
}

// RetentionProof 等保 2.0 三级 180 天日志留存合规凭证
type RetentionProof struct {
	ReportID            string    `json:"report_id"`
	GeneratedAt         time.Time `json:"generated_at"`
	ComplianceClause    string    `json:"compliance_clause"` // GB/T 22239-2019 8.1.4.2 b
	TotalRetainedDays   int       `json:"total_retained_days"`
	TargetRetentionDays int       `json:"target_retention_days"` // 180 天
	OldestLogTimestamp  time.Time `json:"oldest_log_timestamp"`
	NewestLogTimestamp  time.Time `json:"newest_log_timestamp"`
	TotalLogRecords     uint64    `json:"total_log_records"`
	IntegrityChainValid bool      `json:"integrity_chain_valid"`
	IsCompliant         bool      `json:"is_compliant"`
	AuditorNotes        string    `json:"auditor_notes"`
}
