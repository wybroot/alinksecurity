package storage

import (
	"context"
	"time"

	pb "alinksec/api/proto/v1"
)

// AgentRecord 数据库中持久化的探针资产
type AgentRecord struct {
	AgentID           string       `json:"agent_id"`
	AgentType         pb.AgentType `json:"agent_type"`
	AgentTypeStr      string       `json:"agent_type_str"`
	Version           string       `json:"version"`
	Hostname          string       `json:"hostname"`
	IP                string       `json:"ip"`
	MAC               string       `json:"mac"`
	OS                string       `json:"os"`
	Arch              string       `json:"arch"`
	SessionToken      string       `json:"session_token,omitempty"`
	Status            string       `json:"status"` // "online", "offline", "revoked"
	LastHeartbeatTime time.Time    `json:"last_heartbeat_time"`
	CPUUsage          float32      `json:"cpu_usage"`
	MemoryUsedBytes   int64        `json:"memory_used_bytes"`
	DiskUsedBytes     int64        `json:"disk_used_bytes"`
	ActiveRulesCount  int32        `json:"active_rules_count"`
	CurrentPolicyVer  string       `json:"current_policy_ver"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

// UserRecord 数据库中持久化的三权分立管理员账号
type UserRecord struct {
	ID               int64     `json:"id"`
	Username         string    `json:"username"`
	PasswordHash     string    `json:"-"`
	Role             string    `json:"role"` // "sys_admin", "sec_admin", "audit_admin"
	TOTPSecret       string    `json:"-"`
	TOTPEnabled      bool      `json:"totp_enabled"`
	Status           string    `json:"status"` // "active", "disabled", "locked"
	FailedLoginCount int       `json:"failed_login_count"`
	LockedUntil      *time.Time `json:"locked_until,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// PolicyRecord 数据库中持久化的安全策略
type PolicyRecord struct {
	ID        int64     `json:"id"`
	PolicyID  string    `json:"policy_id"`
	Version   string    `json:"version"`
	AgentType string    `json:"agent_type"`
	Content   string    `json:"content"` // JSON 格式策略内容
	Signature string    `json:"signature"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// SecurityEventRecord ClickHouse 中持久化的等保安全事件 (留存 >= 180 天)
type SecurityEventRecord struct {
	EventID    string    `json:"event_id"`
	SourceType string    `json:"source_type"`
	AgentID    string    `json:"agent_id"`
	HostIP     string    `json:"host_ip"`
	Hostname   string    `json:"hostname"`
	EventTime  time.Time `json:"event_time"`
	Level      string    `json:"level"`
	Category   string    `json:"category"`
	RuleID     string    `json:"rule_id"`
	Message    string    `json:"message"`
	RawPayload string    `json:"raw_payload"`
	Signature  string    `json:"signature"`
	ChainHash  string    `json:"chain_hash"`
}

// AdminAuditRecord ClickHouse 中持久化的管理员操作审计记录 (留存 >= 365 天)
type AdminAuditRecord struct {
	LogID          string    `json:"log_id"`
	AdminUser      string    `json:"admin_user"`
	Role           string    `json:"role"`
	ClientIP       string    `json:"client_ip"`
	Action         string    `json:"action"`
	TargetResource string    `json:"target_resource"`
	RequestBody    string    `json:"request_body"`
	ResponseCode   int       `json:"response_code"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	PrevHash       string    `json:"prev_hash"`
	LogHash        string    `json:"log_hash"`
}

// StorageEngine 统一持久化存储接口
type StorageEngine interface {
	// 探针纳管
	SaveAgent(ctx context.Context, agent *AgentRecord) error
	UpdateAgentHeartbeat(ctx context.Context, agentID string, cpu float32, mem, disk int64, rules int32, policyVer string) error
	GetAgent(ctx context.Context, agentID string) (*AgentRecord, error)
	ListAgents(ctx context.Context) ([]*AgentRecord, error)
	MarkOfflineAgents(ctx context.Context, timeoutThreshold time.Duration) (int64, error)

	// 用户与三权分立
	GetUserByUsername(ctx context.Context, username string) (*UserRecord, error)
	CreateUser(ctx context.Context, user *UserRecord) error
	UpdateUser(ctx context.Context, user *UserRecord) error
	ListUsers(ctx context.Context) ([]*UserRecord, error)

	// 策略持久化
	SavePolicy(ctx context.Context, policy *PolicyRecord) error
	GetPolicy(ctx context.Context, agentType string) (*PolicyRecord, error)
	ListPolicies(ctx context.Context) ([]*PolicyRecord, error)

	// 关闭连接
	Close() error
}
