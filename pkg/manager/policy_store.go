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
		},
		ProcessRules: []*pb.ProcessRule{
			{RuleId: "rp-1", ProcessName: "ncat", BlockIfMismatch: true},
		},
		NetworkRules: []*pb.NetworkRule{
			{RuleId: "rn-1", Direction: "IN", Protocol: "TCP", DstPort: "22", Action: "LOG"},
		},
		Signature: crypto.SHA256String("policy-edr-v1.0.0"),
		UpdatedAt: time.Now(),
		UpdatedBy: "secadmin",
	}

	return ps
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
