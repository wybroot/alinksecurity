package manager

import (
	"errors"
	"fmt"
	"sync"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/auth"
	"alinksec/pkg/crypto"
)

// SecurityPolicyPackage 安全策略实体
type SecurityPolicyPackage struct {
	Version      string            `json:"version"`
	AgentType    string            `json:"agent_type"`
	FileRules    []*pb.FileRule    `json:"file_rules"`
	ProcessRules []*pb.ProcessRule `json:"process_rules"`
	NetworkRules []*pb.NetworkRule `json:"network_rules"`
	Signature    string            `json:"signature"`
	UpdatedAt    time.Time         `json:"updated_at"`
	UpdatedBy    string            `json:"updated_by"`
}

// PolicyStore 策略存储
type PolicyStore struct {
	mu       sync.RWMutex
	policies map[string]*SecurityPolicyPackage
}

// NewPolicyStore 创建策略存储
func NewPolicyStore() *PolicyStore {
	ps := &PolicyStore{
		policies: make(map[string]*SecurityPolicyPackage),
	}

	// 预设默认策略
	ps.policies["EDR"] = &SecurityPolicyPackage{
		Version:   "v1.0.0",
		AgentType: "EDR",
		FileRules: []*pb.FileRule{
			{RuleId: "rf-1", PathPattern: "/etc/shadow", IsProtected: true, BackupOnModify: true},
			{RuleId: "rf-2", PathPattern: "/etc/passwd", IsProtected: true, BackupOnModify: true},
		},
		ProcessRules: []*pb.ProcessRule{
			{RuleId: "rp-1", ProcessName: "ncat", BlockIfMismatch: true},
			{RuleId: "rp-2", ProcessName: "bash -i", BlockIfMismatch: true},
		},
		NetworkRules: []*pb.NetworkRule{
			{RuleId: "rn-1", Direction: "IN", Protocol: "TCP", DstPort: "22", Action: "LOG"},
		},
		Signature: crypto.SHA256String("policy-edr-v1.0.0"),
		UpdatedAt: time.Now(),
		UpdatedBy: "secadmin",
	}

	ps.policies["WAF"] = &SecurityPolicyPackage{
		Version:   "v1.2.0",
		AgentType: "WAF",
		ProcessRules: []*pb.ProcessRule{
			{RuleId: "waf-sqli", ProcessName: "OWASP-SQLi-Engine", BlockIfMismatch: true},
			{RuleId: "waf-xss", ProcessName: "OWASP-XSS-Engine", BlockIfMismatch: true},
			{RuleId: "waf-rce", ProcessName: "Command-Injection-Engine", BlockIfMismatch: true},
		},
		NetworkRules: []*pb.NetworkRule{
			{RuleId: "waf-cc-limit", Direction: "IN", Protocol: "HTTP", DstPort: "80,443", Action: "RATE_LIMIT_60_100"},
		},
		Signature: crypto.SHA256String("policy-waf-v1.2.0"),
		UpdatedAt: time.Now(),
		UpdatedBy: "secadmin",
	}

	ps.policies["CFW"] = &SecurityPolicyPackage{
		Version:   "v1.1.0",
		AgentType: "CFW",
		NetworkRules: []*pb.NetworkRule{
			{RuleId: "cfw-dmz-app", Direction: "FORWARD", Protocol: "TCP", DstPort: "8080", Action: "ALLOW"},
			{RuleId: "cfw-app-db", Direction: "FORWARD", Protocol: "TCP", DstPort: "3306", Action: "ALLOW"},
			{RuleId: "cfw-dmz-db-deny", Direction: "FORWARD", Protocol: "TCP", DstPort: "3306", Action: "DENY_CROSS_ZONE"},
		},
		Signature: crypto.SHA256String("policy-cfw-v1.1.0"),
		UpdatedAt: time.Now(),
		UpdatedBy: "secadmin",
	}

	ps.policies["TAMPER"] = &SecurityPolicyPackage{
		Version:   "v1.0.4",
		AgentType: "TAMPER",
		FileRules: []*pb.FileRule{
			{RuleId: "tmp-www", PathPattern: "/var/www/html", IsProtected: true, BackupOnModify: true},
			{RuleId: "tmp-conf", PathPattern: "/etc/nginx/conf.d", IsProtected: true, BackupOnModify: true},
		},
		Signature: crypto.SHA256String("policy-tamper-v1.0.4"),
		UpdatedAt: time.Now(),
		UpdatedBy: "secadmin",
	}

	ps.policies["DBAUDIT"] = &SecurityPolicyPackage{
		Version:   "v1.0.2",
		AgentType: "DBAUDIT",
		ProcessRules: []*pb.ProcessRule{
			{RuleId: "dba-ddl", ProcessName: "BLOCK_DROP_TRUNCATE_TABLE", BlockIfMismatch: true},
			{RuleId: "dba-grant", ProcessName: "BLOCK_PRIVILEGE_ESCALATION", BlockIfMismatch: true},
		},
		Signature: crypto.SHA256String("policy-dbaudit-v1.0.2"),
		UpdatedAt: time.Now(),
		UpdatedBy: "secadmin",
	}

	ps.policies["LOGAUDIT"] = &SecurityPolicyPackage{
		Version:   "v1.0.0",
		AgentType: "LOGAUDIT",
		FileRules: []*pb.FileRule{
			{RuleId: "log-retention", PathPattern: "/var/log/secure", IsProtected: true, BackupOnModify: false},
		},
		Signature: crypto.SHA256String("policy-logaudit-v1.0.0"),
		UpdatedAt: time.Now(),
		UpdatedBy: "secadmin",
	}

	return ps
}

// ListAllPolicies 获取全部组件策略清单
func (ps *PolicyStore) ListAllPolicies() map[string]*SecurityPolicyPackage {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	res := make(map[string]*SecurityPolicyPackage, len(ps.policies))
	for k, v := range ps.policies {
		cp := *v
		res[k] = &cp
	}
	return res
}

// GetPolicy 查询指定产品策略
func (ps *PolicyStore) GetPolicy(agentType string) (*SecurityPolicyPackage, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	p, ok := ps.policies[agentType]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

// UpdatePolicy 更新防御策略 (仅安全管理员 sec_admin 有权配置)
func (ps *PolicyStore) UpdatePolicy(updaterRole auth.Role, updaterName, agentType string, pkg SecurityPolicyPackage) (*SecurityPolicyPackage, error) {
	if updaterRole != auth.RoleSecAdmin {
		return nil, errors.New("MLPS3 violation: only sec_admin can configure defense policies")
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	pkg.UpdatedAt = time.Now()
	pkg.UpdatedBy = updaterName
	pkg.Signature = crypto.SHA256String(fmt.Sprintf("%s|%s|%d", agentType, pkg.Version, pkg.UpdatedAt.Unix()))

	ps.policies[agentType] = &pkg
	cp := pkg
	return &cp, nil
}
