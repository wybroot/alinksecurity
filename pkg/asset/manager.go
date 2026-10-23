package asset

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// CriticalityLevel 资产重要性等级（等保2.0三级要求明确资产定级）
type CriticalityLevel string

const (
	Tier1Critical  CriticalityLevel = "TIER_1_CRITICAL"  // 核心资产 (影响业务连续性)
	Tier2Important CriticalityLevel = "TIER_2_IMPORTANT" // 重要资产 (承载关键业务逻辑)
	Tier3General   CriticalityLevel = "TIER_3_GENERAL"   // 一般资产 (普通办公/辅助节点)
)

// SecurityZone 安全域
type SecurityZone string

const (
	ZoneDMZ  SecurityZone = "DMZ"
	ZoneAPP  SecurityZone = "APP"
	ZoneDATA SecurityZone = "DATA"
	ZoneMGMT SecurityZone = "MGMT"
)

// Asset 代表一台被保护的计算资产实体
type Asset struct {
	ID               string           `json:"id"`
	Hostname         string           `json:"hostname"`
	IP               string           `json:"ip"`
	MAC              string           `json:"mac"`
	OS               string           `json:"os"`
	Zone             SecurityZone     `json:"zone"`
	Criticality      CriticalityLevel `json:"criticality"`
	Owner            string           `json:"owner"`
	ProbesInstalled  []string         `json:"probes_installed"` // e.g. ["WAF", "EDR", "TAMPER"]
	ComplianceScore  float64          `json:"compliance_score"` // 0.0 - 100.0
	VulnerabilityCnt int              `json:"vulnerability_cnt"`
	Status           string           `json:"status"` // "ONLINE", "WARNING", "OFFLINE"
	CreatedAt        time.Time        `json:"created_at"`
	LastSeen         time.Time        `json:"last_seen"`
}

// Manager 资产台账管理器
type Manager struct {
	mu     sync.RWMutex
	assets map[string]*Asset
}

// NewManager 初始化资产管理器并预置符合等保三级拓扑的基线资产
func NewManager() *Manager {
	m := &Manager{
		assets: make(map[string]*Asset),
	}
	m.initDefaults()
	return m
}

func (m *Manager) initDefaults() {
	now := time.Now()
	defaults := []*Asset{
		{
			ID:               "AST-001",
			Hostname:         "sec-gateway-01.alinksec.local",
			IP:               "192.168.1.10",
			MAC:              "52:54:00:12:34:01",
			OS:               "Linux (Alpine 3.19 x86_64)",
			Zone:             ZoneDMZ,
			Criticality:      Tier1Critical,
			Owner:            "网络安全组 (sec_admin)",
			ProbesInstalled:  []string{"WAF", "CFW", "EDR"},
			ComplianceScore:  99.4,
			VulnerabilityCnt: 0,
			Status:           "ONLINE",
			CreatedAt:        now.Add(-720 * time.Hour),
			LastSeen:         now,
		},
		{
			ID:               "AST-002",
			Hostname:         "app-cluster-node1.alinksec.local",
			IP:               "192.168.2.20",
			MAC:              "52:54:00:12:34:02",
			OS:               "Linux (Ubuntu 22.04 LTS)",
			Zone:             ZoneAPP,
			Criticality:      Tier2Important,
			Owner:            "应用研发运维部 (sys_admin)",
			ProbesInstalled:  []string{"EDR", "TAMPER", "LOGAUDIT"},
			ComplianceScore:  98.8,
			VulnerabilityCnt: 0,
			Status:           "ONLINE",
			CreatedAt:        now.Add(-600 * time.Hour),
			LastSeen:         now,
		},
		{
			ID:               "AST-003",
			Hostname:         "core-mysql-cluster.alinksec.local",
			IP:               "192.168.3.30",
			MAC:              "52:54:00:12:34:03",
			OS:               "Linux (RHEL 9.2 x86_64)",
			Zone:             ZoneDATA,
			Criticality:      Tier1Critical,
			Owner:            "核心DBA团队",
			ProbesInstalled:  []string{"DBAUDIT", "EDR", "LOGAUDIT"},
			ComplianceScore:  100.0,
			VulnerabilityCnt: 0,
			Status:           "ONLINE",
			CreatedAt:        now.Add(-800 * time.Hour),
			LastSeen:         now,
		},
		{
			ID:               "AST-004",
			Hostname:         "mgmt-bastion-host.alinksec.local",
			IP:               "192.168.4.40",
			MAC:              "52:54:00:12:34:04",
			OS:               "Linux (Debian 12 Bookworm)",
			Zone:             ZoneMGMT,
			Criticality:      Tier1Critical,
			Owner:            "安全审计中心 (audit_admin)",
			ProbesInstalled:  []string{"BASTION", "EDR", "LOGAUDIT"},
			ComplianceScore:  99.8,
			VulnerabilityCnt: 0,
			Status:           "ONLINE",
			CreatedAt:        now.Add(-900 * time.Hour),
			LastSeen:         now,
		},
		{
			ID:               "AST-005",
			Hostname:         "corp-dev-test01.alinksec.local",
			IP:               "192.168.2.88",
			MAC:              "52:54:00:12:34:05",
			OS:               "Linux (CentOS Stream 9)",
			Zone:             ZoneAPP,
			Criticality:      Tier3General,
			Owner:            "测试开发组",
			ProbesInstalled:  []string{"EDR"},
			ComplianceScore:  95.0,
			VulnerabilityCnt: 1,
			Status:           "WARNING",
			CreatedAt:        now.Add(-300 * time.Hour),
			LastSeen:         now,
		},
	}

	for _, a := range defaults {
		m.assets[a.ID] = a
	}
}

// ListAssets 获取所有资产列表
func (m *Manager) ListAssets(zoneFilter string, criticalityFilter string) []*Asset {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var list []*Asset
	for _, a := range m.assets {
		if zoneFilter != "" && string(a.Zone) != zoneFilter {
			continue
		}
		if criticalityFilter != "" && string(a.Criticality) != criticalityFilter {
			continue
		}
		list = append(list, a)
	}
	return list
}

// GetAssetByID 获取指定资产
func (m *Manager) GetAssetByID(id string) (*Asset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	a, ok := m.assets[id]
	if !ok {
		return nil, fmt.Errorf("asset with id '%s' not found", id)
	}
	return a, nil
}

// RegisterOrUpdate 注册或更新资产信息
func (m *Manager) RegisterOrUpdate(a *Asset) error {
	if a == nil || a.ID == "" {
		return errors.New("invalid asset payload")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.assets[a.ID]; ok {
		// Update
		existing.Hostname = a.Hostname
		existing.IP = a.IP
		existing.MAC = a.MAC
		existing.OS = a.OS
		if a.Zone != "" {
			existing.Zone = a.Zone
		}
		if a.Criticality != "" {
			existing.Criticality = a.Criticality
		}
		if a.Owner != "" {
			existing.Owner = a.Owner
		}
		if len(a.ProbesInstalled) > 0 {
			existing.ProbesInstalled = a.ProbesInstalled
		}
		if a.ComplianceScore > 0 {
			existing.ComplianceScore = a.ComplianceScore
		}
		existing.Status = a.Status
		existing.LastSeen = time.Now()
	} else {
		// Create
		if a.CreatedAt.IsZero() {
			a.CreatedAt = time.Now()
		}
		a.LastSeen = time.Now()
		if a.ComplianceScore == 0 {
			a.ComplianceScore = 98.0
		}
		if a.Status == "" {
			a.Status = "ONLINE"
		}
		m.assets[a.ID] = a
	}
	return nil
}

// UpdateClassification 更新资产定级与归属
func (m *Manager) UpdateClassification(id string, zone SecurityZone, crit CriticalityLevel, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	a, ok := m.assets[id]
	if !ok {
		return fmt.Errorf("asset with id '%s' not found", id)
	}
	if zone != "" {
		a.Zone = zone
	}
	if crit != "" {
		a.Criticality = crit
	}
	if owner != "" {
		a.Owner = owner
	}
	a.LastSeen = time.Now()
	return nil
}

// Stats 资产统计概览
type Stats struct {
	TotalAssets        int            `json:"total_assets"`
	Tier1CriticalCount int            `json:"tier1_critical_count"`
	Tier2ImportantCount int           `json:"tier2_important_count"`
	Tier3GeneralCount   int           `json:"tier3_general_count"`
	ZoneDistribution   map[string]int `json:"zone_distribution"`
	AvgComplianceScore float64        `json:"avg_compliance_score"`
	OnlineCount        int            `json:"online_count"`
}

// GetStats 计算资产统计数据
func (m *Manager) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s := Stats{
		TotalAssets:      len(m.assets),
		ZoneDistribution: make(map[string]int),
	}

	var scoreSum float64
	for _, a := range m.assets {
		switch a.Criticality {
		case Tier1Critical:
			s.Tier1CriticalCount++
		case Tier2Important:
			s.Tier2ImportantCount++
		case Tier3General:
			s.Tier3GeneralCount++
		}
		s.ZoneDistribution[string(a.Zone)]++
		scoreSum += a.ComplianceScore
		if a.Status == "ONLINE" {
			s.OnlineCount++
		}
	}

	if s.TotalAssets > 0 {
		s.AvgComplianceScore = scoreSum / float64(s.TotalAssets)
	}
	return s
}
