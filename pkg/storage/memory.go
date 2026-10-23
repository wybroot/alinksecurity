package storage

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryStorage 内存型存储引擎实现，用于开发测试或脱机独立部署
type MemoryStorage struct {
	mu       sync.RWMutex
	agents   map[string]*AgentRecord
	users    map[string]*UserRecord
	policies map[string]*PolicyRecord
}

// NewMemoryStorage 创建内存存储引擎
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		agents:   make(map[string]*AgentRecord),
		users:    make(map[string]*UserRecord),
		policies: make(map[string]*PolicyRecord),
	}
}

func (m *MemoryStorage) Close() error {
	return nil
}

func (m *MemoryStorage) SaveAgent(ctx context.Context, agent *AgentRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.agents[agent.AgentID] = agent
	return nil
}

func (m *MemoryStorage) UpdateAgentHeartbeat(ctx context.Context, agentID string, cpu float32, mem, disk int64, rules int32, policyVer string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ag, ok := m.agents[agentID]; ok {
		ag.LastHeartbeatTime = time.Now()
		ag.CPUUsage = cpu
		ag.MemoryUsedBytes = mem
		ag.DiskUsedBytes = disk
		ag.ActiveRulesCount = rules
		ag.CurrentPolicyVer = policyVer
		ag.Status = "online"
	}
	return nil
}

func (m *MemoryStorage) GetAgent(ctx context.Context, agentID string) (*AgentRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ag, ok := m.agents[agentID]; ok {
		return ag, nil
	}
	return nil, fmt.Errorf("agent not found: %s", agentID)
}

func (m *MemoryStorage) ListAgents(ctx context.Context) ([]*AgentRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []*AgentRecord
	for _, ag := range m.agents {
		list = append(list, ag)
	}
	return list, nil
}

func (m *MemoryStorage) MarkOfflineAgents(ctx context.Context, timeout time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	threshold := time.Now().Add(-timeout)
	var count int64
	for _, ag := range m.agents {
		if ag.Status == "online" && ag.LastHeartbeatTime.Before(threshold) {
			ag.Status = "offline"
			count++
		}
	}
	return count, nil
}

func (m *MemoryStorage) GetUserByUsername(ctx context.Context, username string) (*UserRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if u, ok := m.users[username]; ok {
		return u, nil
	}
	return nil, fmt.Errorf("user not found: %s", username)
}

func (m *MemoryStorage) CreateUser(ctx context.Context, user *UserRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.Username] = user
	return nil
}

func (m *MemoryStorage) UpdateUser(ctx context.Context, user *UserRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.Username] = user
	return nil
}

func (m *MemoryStorage) ListUsers(ctx context.Context) ([]*UserRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []*UserRecord
	for _, u := range m.users {
		list = append(list, u)
	}
	return list, nil
}

func (m *MemoryStorage) SavePolicy(ctx context.Context, policy *PolicyRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[policy.AgentType] = policy
	return nil
}

func (m *MemoryStorage) GetPolicy(ctx context.Context, agentType string) (*PolicyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if p, ok := m.policies[agentType]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("policy not found: %s", agentType)
}

func (m *MemoryStorage) ListPolicies(ctx context.Context) ([]*PolicyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []*PolicyRecord
	for _, p := range m.policies {
		list = append(list, p)
	}
	return list, nil
}
