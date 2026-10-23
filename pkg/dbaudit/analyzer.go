package dbaudit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SQLAnalyzer 数据库审计规则分析器
type SQLAnalyzer struct {
	dropRegex       *regexp.Regexp
	truncateRegex   *regexp.Regexp
	deleteNoWhere   *regexp.Regexp
	updateNoWhere   *regexp.Regexp
	privilegeRegex  *regexp.Regexp
	dataExfilRegex  *regexp.Regexp
	schemaLeakRegex *regexp.Regexp
}

// NewSQLAnalyzer 构造分析器
func NewSQLAnalyzer() *SQLAnalyzer {
	return &SQLAnalyzer{
		dropRegex:       regexp.MustCompile(`(?i)^\s*DROP\s+(DATABASE|SCHEMA|TABLE)\s+`),
		truncateRegex:   regexp.MustCompile(`(?i)^\s*TRUNCATE\s+(TABLE\s+)?`),
		deleteNoWhere:   regexp.MustCompile(`(?i)^\s*DELETE\s+FROM\s+[\w\."` + "`" + `]+(?:\s*;|\s*$|\s+LIMIT\b)`),
		updateNoWhere:   regexp.MustCompile(`(?i)^\s*UPDATE\s+[\w\."` + "`" + `]+\s+SET\s+[^;]+$`),
		privilegeRegex:  regexp.MustCompile(`(?i)\b(GRANT\s+ALL|CREATE\s+USER|ALTER\s+USER|mysql\.user|pg_shadow|pg_authid)\b`),
		dataExfilRegex:  regexp.MustCompile(`(?i)\b(INTO\s+OUTFILE|INTO\s+DUMPFILE|LOAD_FILE\b)`),
		schemaLeakRegex: regexp.MustCompile(`(?i)\b(UNION\s+SELECT\b.*?\bFROM\s+information_schema\b)`),
	}
}

// Analyze 解析并评估一条 SQL 的操作类型与风险合规等级
func (a *SQLAnalyzer) Analyze(clientAddr, serverAddr, dbUser, database, sql string, protocol DBProtocol, latencyMs int64) *AuditRecord {
	trimmed := strings.TrimSpace(sql)
	record := &AuditRecord{
		ID:         generateAuditID(),
		Timestamp:  time.Now(),
		Protocol:   protocol,
		ClientAddr: clientAddr,
		ServerAddr: serverAddr,
		DBUser:     dbUser,
		Database:   database,
		Operation:  a.detectOperation(trimmed),
		SQL:        trimmed,
		LatencyMs:  latencyMs,
		RiskLevel:  RiskInfo,
		IsThreat:   false,
	}

	if trimmed == "" {
		return record
	}

	upperSQL := strings.ToUpper(trimmed)

	// 规则 DBA-101: 恶意删库/删表破坏 (GB/T 22239-2019 8.1.4.4 数据完整性/恶意破坏)
	if a.dropRegex.MatchString(trimmed) || a.truncateRegex.MatchString(trimmed) {
		record.RiskLevel = RiskCritical
		record.IsThreat = true
		record.ThreatType = "DDL_DESTRUCTIVE_COMMAND"
		record.ThreatReason = "检测到破坏性 DDL 语句 (DROP/TRUNCATE 库表)，存在严重数据灭失风险"
		record.RuleID = "DBA-101"
		return record
	}

	// 规则 DBA-102: 全表无条件删除清空
	if strings.HasPrefix(upperSQL, "DELETE") && !strings.Contains(upperSQL, "WHERE") {
		record.RiskLevel = RiskCritical
		record.IsThreat = true
		record.ThreatType = "UNCONSTRAINED_BULK_DELETE"
		record.ThreatReason = "检测到无 WHERE 过滤条件的批量删除语句，存在全表清空风险"
		record.RuleID = "DBA-102"
		return record
	}

	// 规则 DBA-103: 全表无条件批量覆写
	if strings.HasPrefix(upperSQL, "UPDATE") && !strings.Contains(upperSQL, "WHERE") {
		record.RiskLevel = RiskCritical
		record.IsThreat = true
		record.ThreatType = "UNCONSTRAINED_BULK_UPDATE"
		record.ThreatReason = "检测到无 WHERE 过滤条件的批量更新语句，存在全表覆写风险"
		record.RuleID = "DBA-103"
		return record
	}

	// 规则 DBA-104: 数据库越权提权与系统账户操作 (GB/T 22239-2019 8.1.4.3 访问控制/特权管理)
	if a.privilegeRegex.MatchString(trimmed) {
		record.RiskLevel = RiskHigh
		record.IsThreat = true
		record.ThreatType = "PRIVILEGE_ESCALATION_ATTEMPT"
		record.ThreatReason = "检测到高危权限变更或尝试访问系统安全敏感账户字典表"
		record.RuleID = "DBA-104"
		return record
	}

	// 规则 DBA-105: 敏感文件写入与非法拖库导出
	if a.dataExfilRegex.MatchString(trimmed) {
		record.RiskLevel = RiskHigh
		record.IsThreat = true
		record.ThreatType = "DATA_EXFILTRATION_OUTFILE"
		record.ThreatReason = "检测到 INTO OUTFILE/DUMPFILE 或 LOAD_FILE 跨界存取行为"
		record.RuleID = "DBA-105"
		return record
	}

	// 规则 DBA-106: 元数据探测注入拖库
	if a.schemaLeakRegex.MatchString(trimmed) {
		record.RiskLevel = RiskHigh
		record.IsThreat = true
		record.ThreatType = "METADATA_INJECTION_RECON"
		record.ThreatReason = "检测到针对 information_schema 结构字典的联合查询渗透特征"
		record.RuleID = "DBA-106"
		return record
	}

	// 规则 DBA-107: 常规 DDL 变更 (ALTER / CREATE)
	if record.Operation == OpDDL {
		record.RiskLevel = RiskMedium
		return record
	}

	// 规则 DBA-108: 管理操作 (GRANT, FLUSH, KILL)
	if record.Operation == OpAdmin {
		record.RiskLevel = RiskMedium
		return record
	}

	// 常规写操作 (INSERT, UPDATE with WHERE, DELETE with WHERE)
	if record.Operation == OpInsert || record.Operation == OpUpdate || record.Operation == OpDelete {
		record.RiskLevel = RiskLow
		return record
	}

	// 其余正常只读查询
	record.RiskLevel = RiskInfo
	return record
}

func (a *SQLAnalyzer) detectOperation(sql string) SQLOperation {
	if sql == "" {
		return OpUnknown
	}
	firstWord := strings.ToUpper(strings.Fields(sql)[0])
	switch firstWord {
	case "SELECT":
		return OpSelect
	case "INSERT":
		return OpInsert
	case "UPDATE":
		return OpUpdate
	case "DELETE":
		return OpDelete
	case "CREATE", "DROP", "ALTER", "TRUNCATE":
		return OpDDL
	case "GRANT", "REVOKE", "SHOW", "SET", "KILL", "FLUSH", "USE":
		return OpAdmin
	default:
		return OpUnknown
	}
}

func generateAuditID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("dba-%d-%s", time.Now().UnixNano()%1000000, hex.EncodeToString(b))
}
