package edr

import (
	pb "alinksec/api/proto/v1"
)

// ThreatType EDR 威胁类型
type ThreatType string

const (
	ThreatReverseShell   ThreatType = "REVERSE_SHELL"
	ThreatPrivEscalation ThreatType = "PRIVILEGE_ESCALATION"
	ThreatMaliciousTool  ThreatType = "MALICIOUS_TOOL"
	ThreatBruteForce     ThreatType = "BRUTE_FORCE_ATTACK"
	ThreatBaselineFailed ThreatType = "BASELINE_COMPLIANCE_FAILED"
)

// BaselineItem 基线检查项
type BaselineItem struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Standard    string        `json:"standard"` // GB/T 22239-2019 等保条款
	Description string        `json:"description"`
	Passed      bool          `json:"passed"`
	Level       pb.EventLevel `json:"level"`
	Detail      string        `json:"detail"`
	Remediation string        `json:"remediation"`
}

// ProcessInfo 进程行为快照
type ProcessInfo struct {
	PID         int32    `json:"pid"`
	PPID        int32    `json:"ppid"`
	Name        string   `json:"name"`
	CommandLine string   `json:"command_line"`
	Executable  string   `json:"executable"`
	Username    string   `json:"username"`
	Args        []string `json:"args"`
}

// DetectionResult 威胁检测判定结果
type DetectionResult struct {
	Matched     bool
	ThreatType  ThreatType
	Level       pb.EventLevel
	RuleID      string
	Title       string
	Description string
	Process     ProcessInfo
	Payload     string
}

// HostTelemetry 主机系统遥测指标
type HostTelemetry struct {
	CPUPercent    float32 `json:"cpu_percent"`
	MemoryPercent float32 `json:"memory_percent"`
	DiskPercent   float32 `json:"disk_percent"`
	ProcessCount  int32   `json:"process_count"`
	AgentVersion  string  `json:"agent_version"`
}
