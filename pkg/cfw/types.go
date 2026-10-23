package cfw

import "time"

// NetworkZone 定义网络安全域 (等保 2.0 区域边界)
type NetworkZone string

const (
	ZoneDMZ        NetworkZone = "DMZ"        // 边界外联区 (WAF、公网暴露反代)
	ZoneApp        NetworkZone = "APP"        // 内部业务服务区
	ZoneData       NetworkZone = "DATA"       // 核心数据存储区 (MySQL, Redis, ClickHouse)
	ZoneManagement NetworkZone = "MANAGEMENT" // 管理与审计区 (SOC, 堡垒机)
	ZoneUnknown    NetworkZone = "UNKNOWN"
)

// FirewallAction 规则动作
type FirewallAction string

const (
	ActionAllow FirewallAction = "ALLOW"
	ActionDrop  FirewallAction = "DROP"
	ActionLog   FirewallAction = "LOG"
)

// SecurityRule 微隔离防火墙规则
type SecurityRule struct {
	ID          string         `json:"id"`
	Priority    int            `json:"priority"` // 优先级 (数值越小优先级越高)
	SrcZone     NetworkZone    `json:"src_zone"`
	SrcCIDR     string         `json:"src_cidr"` // 例如 "10.0.1.0/24" 或 "192.168.1.10"
	DstZone     NetworkZone    `json:"dst_zone"`
	DstCIDR     string         `json:"dst_cidr"`
	Protocol    string         `json:"protocol"` // "TCP", "UDP", "ICMP", "ANY"
	DstPort     int            `json:"dst_port"` // 0 表示所有端口
	Action      FirewallAction `json:"action"`
	Description string         `json:"description"`
}

// PacketEvent 网络包评估上下文
type PacketContext struct {
	SrcIP    string      `json:"src_ip"`
	DstIP    string      `json:"dst_ip"`
	Protocol string      `json:"protocol"`
	DstPort  int         `json:"dst_port"`
	SrcZone  NetworkZone `json:"src_zone"`
	DstZone  NetworkZone `json:"dst_zone"`
}

// FirewallEvent 拦截告警事件
type FirewallEvent struct {
	EventID        string         `json:"event_id"`
	Timestamp      time.Time      `json:"timestamp"`
	Context        PacketContext  `json:"context"`
	MatchedRuleID  string         `json:"matched_rule_id"`
	Action         FirewallAction `json:"action"`
	IsViolation    bool           `json:"is_violation"`
	ViolationType  string         `json:"violation_type,omitempty"`
	Reason         string         `json:"reason,omitempty"`
}
