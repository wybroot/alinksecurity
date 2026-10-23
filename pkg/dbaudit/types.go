package dbaudit

import "time"

// DBProtocol 定义数据库协议类型
type DBProtocol string

const (
	ProtoMySQL      DBProtocol = "MySQL"
	ProtoPostgreSQL DBProtocol = "PostgreSQL"
	ProtoUnknown    DBProtocol = "Unknown"
)

// SQLOperation 定义 SQL 操作类型
type SQLOperation string

const (
	OpSelect  SQLOperation = "SELECT"
	OpInsert  SQLOperation = "INSERT"
	OpUpdate  SQLOperation = "UPDATE"
	OpDelete  SQLOperation = "DELETE"
	OpDDL     SQLOperation = "DDL"   // CREATE, DROP, ALTER, TRUNCATE
	OpAdmin   SQLOperation = "ADMIN" // GRANT, REVOKE, SHOW, SET, KILL
	OpUnknown SQLOperation = "UNKNOWN"
)

// RiskLevel 风险等级 (等保三级划分)
type RiskLevel string

const (
	RiskInfo     RiskLevel = "INFO"     // 常规只读或授权写操作
	RiskLow      RiskLevel = "LOW"      // 批量常规查询或 DML
	RiskMedium   RiskLevel = "MEDIUM"   // 结构变更、大表全表扫描无索引
	RiskHigh     RiskLevel = "HIGH"     // 跨库访问、读取字典表、权限变更
	RiskCritical RiskLevel = "CRITICAL" // DROP 数据库/表、无 WHERE 全表更新/删除、拖库导出
)

// AuditRecord 数据库审计记录
type AuditRecord struct {
	ID           string       `json:"id"`
	Timestamp    time.Time    `json:"timestamp"`
	Protocol     DBProtocol   `json:"protocol"`
	ClientAddr   string       `json:"client_addr"`
	ServerAddr   string       `json:"server_addr"`
	DBUser       string       `json:"db_user"`
	Database     string       `json:"database"`
	Operation    SQLOperation `json:"operation"`
	SQL          string       `json:"sql"`
	LatencyMs    int64        `json:"latency_ms"`
	RiskLevel    RiskLevel    `json:"risk_level"`
	IsThreat     bool         `json:"is_threat"`
	ThreatType   string       `json:"threat_type,omitempty"`
	ThreatReason string       `json:"threat_reason,omitempty"`
	RuleID       string       `json:"rule_id,omitempty"`
}
