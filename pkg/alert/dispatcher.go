package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ChannelType 通知渠道类型
type ChannelType string

const (
	ChannelDingTalk ChannelType = "DINGTALK" // 钉钉自定义机器人
	ChannelWeCom    ChannelType = "WECOM"    // 企业微信群机器人
	ChannelFeishu   ChannelType = "FEISHU"   // 飞书自定义机器人
	ChannelSyslog   ChannelType = "SYSLOG"   // 统一 Syslog (RFC 5424)
)

// ChannelConfig 通知渠道配置
type ChannelConfig struct {
	ID                string      `json:"id"`
	Name              string      `json:"name"`
	Type              ChannelType `json:"type"`
	WebhookURL        string      `json:"webhook_url"`
	SeverityThreshold string      `json:"severity_threshold"` // "HIGH", "CRITICAL"
	Enabled           bool        `json:"enabled"`
	SuccessCount      int         `json:"success_count"`
	LastDispatched    time.Time   `json:"last_dispatched"`
}

// AggregatedAlert 聚合降噪后的告警
type AggregatedAlert struct {
	GroupKey       string    `json:"group_key"`
	SourceIP       string    `json:"source_ip"`
	Component      string    `json:"component"`
	ThreatType     string    `json:"threat_type"`
	Severity       string    `json:"severity"`
	Message        string    `json:"message"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	Occurrences    int       `json:"occurrences"`    // 累计触发次数
	SuppressedCnt  int       `json:"suppressed_cnt"` // 被静默降噪次数
	Status         string    `json:"status"`         // "AGGREGATING", "DISPATCHED"
	DispatchedTo   []string  `json:"dispatched_to"`  // 成功分发渠道
}

// Dispatcher 告警聚合降噪与多渠道分发器
type Dispatcher struct {
	mu           sync.RWMutex
	window       time.Duration
	channels     map[string]*ChannelConfig
	aggregations map[string]*AggregatedAlert
	history      []*AggregatedAlert
}

// NewDispatcher 初始化告警分发器
func NewDispatcher(window time.Duration) *Dispatcher {
	if window <= 0 {
		window = 5 * time.Minute // 默认 5 分钟滑动收敛窗口
	}

	d := &Dispatcher{
		window:       window,
		channels:     make(map[string]*ChannelConfig),
		aggregations: make(map[string]*AggregatedAlert),
		history:      make([]*AggregatedAlert, 0),
	}
	d.initDefaultChannels()
	d.seedDemoAggregations()
	return d
}

func (d *Dispatcher) initDefaultChannels() {
	defaults := []*ChannelConfig{
		{
			ID:                "CH-DINGTALK",
			Name:              "钉钉-安全应急响应大群",
			Type:              ChannelDingTalk,
			WebhookURL:        "https://oapi.dingtalk.com/robot/send?access_token=alinksec_emergency_token",
			SeverityThreshold: "HIGH",
			Enabled:           true,
			SuccessCount:      42,
			LastDispatched:    time.Now().Add(-10 * time.Minute),
		},
		{
			ID:                "CH-WECOM",
			Name:              "企业微信-等保S3运维告警",
			Type:              ChannelWeCom,
			WebhookURL:        "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=alinksec_wecom_key",
			SeverityThreshold: "CRITICAL",
			Enabled:           true,
			SuccessCount:      18,
			LastDispatched:    time.Now().Add(-25 * time.Minute),
		},
		{
			ID:                "CH-FEISHU",
			Name:              "飞书-SOC安全运营中心",
			Type:              ChannelFeishu,
			WebhookURL:        "https://open.feishu.cn/open-apis/bot/v2/hook/alinksec_feishu_token",
			SeverityThreshold: "HIGH",
			Enabled:           false,
			SuccessCount:      0,
		},
		{
			ID:                "CH-SYSLOG",
			Name:              "SIEM 集中 Syslog (RFC 5424)",
			Type:              ChannelSyslog,
			WebhookURL:        "udp://192.168.1.200:514",
			SeverityThreshold: "INFO",
			Enabled:           true,
			SuccessCount:      156,
			LastDispatched:    time.Now().Add(-2 * time.Minute),
		},
	}
	for _, c := range defaults {
		d.channels[c.ID] = c
	}
}

func (d *Dispatcher) seedDemoAggregations() {
	now := time.Now()
	// 预置已收敛高频攻击：模拟黑客使用 sqlmap 发起 142 次扫描，被自动聚合成 1 条告警
	d.aggregations["WAF_198.51.100.23_SQLI"] = &AggregatedAlert{
		GroupKey:      "WAF_198.51.100.23_SQLI",
		SourceIP:      "198.51.100.23",
		Component:     "WAF",
		ThreatType:    "SQL_INJECTION",
		Severity:      "CRITICAL",
		Message:       "高频联合注入与布尔盲注自动化渗透",
		FirstSeen:     now.Add(-12 * time.Minute),
		LastSeen:      now.Add(-2 * time.Minute),
		Occurrences:   142,
		SuppressedCnt: 141, // 成功过滤降噪 141 条重复轰炸
		Status:        "DISPATCHED",
		DispatchedTo:  []string{"CH-DINGTALK", "CH-SYSLOG"},
	}

	d.aggregations["EDR_10.0.8.12_REVERSE_SHELL"] = &AggregatedAlert{
		GroupKey:      "EDR_10.0.8.12_REVERSE_SHELL",
		SourceIP:      "10.0.8.12",
		Component:     "EDR",
		ThreatType:    "REVERSE_SHELL",
		Severity:      "CRITICAL",
		Message:       "检测到 /dev/tcp/4444 远程反弹 Shell 提权",
		FirstSeen:     now.Add(-8 * time.Minute),
		LastSeen:      now.Add(-1 * time.Minute),
		Occurrences:   5,
		SuppressedCnt: 4,
		Status:        "DISPATCHED",
		DispatchedTo:  []string{"CH-DINGTALK", "CH-WECOM", "CH-SYSLOG"},
	}
}

// IngestEvent 摄入安全事件并执行滑动窗口降噪聚合
func (d *Dispatcher) IngestEvent(sourceIP, component, threatType, severity, message string) (*AggregatedAlert, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	rawKey := fmt.Sprintf("%s_%s_%s", component, sourceIP, threatType)
	sum := sha256.Sum256([]byte(rawKey))
	groupKey := hex.EncodeToString(sum[:8])

	now := time.Now()
	agg, exists := d.aggregations[groupKey]

	if exists && now.Sub(agg.FirstSeen) < d.window {
		// 在收敛滑动窗口内，累加降噪次数
		agg.LastSeen = now
		agg.Occurrences++
		agg.SuppressedCnt++
		// 不重复向渠道推送，防止告警风暴
		return agg, false
	}

	// 开启新的聚合周期
	newAgg := &AggregatedAlert{
		GroupKey:      groupKey,
		SourceIP:      sourceIP,
		Component:     component,
		ThreatType:    threatType,
		Severity:      severity,
		Message:       message,
		FirstSeen:     now,
		LastSeen:      now,
		Occurrences:   1,
		SuppressedCnt: 0,
		Status:        "DISPATCHED",
		DispatchedTo:  make([]string, 0),
	}

	// 分发到匹配的已启用渠道
	for _, ch := range d.channels {
		if !ch.Enabled {
			continue
		}
		if ch.SeverityThreshold == "CRITICAL" && severity != "CRITICAL" {
			continue
		}
		ch.SuccessCount++
		ch.LastDispatched = now
		newAgg.DispatchedTo = append(newAgg.DispatchedTo, ch.ID)
	}

	d.aggregations[groupKey] = newAgg
	d.history = append(d.history, newAgg)
	return newAgg, true
}

// ListAggregations 获取当前聚合告警列表
func (d *Dispatcher) ListAggregations() []*AggregatedAlert {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var list []*AggregatedAlert
	for _, a := range d.aggregations {
		list = append(list, a)
	}
	return list
}

// ListChannels 获取配置渠道
func (d *Dispatcher) ListChannels() []*ChannelConfig {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var list []*ChannelConfig
	for _, c := range d.channels {
		list = append(list, c)
	}
	return list
}

// ToggleChannel 启用/停用通知渠道
func (d *Dispatcher) ToggleChannel(channelID string, enabled bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ch, ok := d.channels[channelID]
	if !ok {
		return fmt.Errorf("channel '%s' not found", channelID)
	}
	ch.Enabled = enabled
	return nil
}

// TestChannel 模拟向指定渠道推送测试告警
func (d *Dispatcher) TestChannel(channelID string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	ch, ok := d.channels[channelID]
	if !ok {
		return "", fmt.Errorf("channel '%s' not found", channelID)
	}
	ch.SuccessCount++
	ch.LastDispatched = time.Now()
	return fmt.Sprintf("已成功向【%s (%s)】投递等保三级测试告警报文，响应码: 200 OK", ch.Name, ch.Type), nil
}

// Stats 告警与降噪统计
type Stats struct {
	TotalEventsReceived int     `json:"total_events_received"`
	SuppressedCount     int     `json:"suppressed_count"`
	DispatchedAlerts    int     `json:"dispatched_alerts"`
	NoiseReductionRate  float64 `json:"noise_reduction_rate"` // 降噪率 %
	ActiveChannels      int     `json:"active_channels"`
}

// GetStats 计算降噪效能
func (d *Dispatcher) GetStats() Stats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var totalOccurrences int
	var totalSuppressed int

	for _, a := range d.aggregations {
		totalOccurrences += a.Occurrences
		totalSuppressed += a.SuppressedCnt
	}

	activeCount := 0
	for _, c := range d.channels {
		if c.Enabled {
			activeCount++
		}
	}

	rate := 0.0
	if totalOccurrences > 0 {
		rate = (float64(totalSuppressed) / float64(totalOccurrences)) * 100.0
	}

	return Stats{
		TotalEventsReceived: totalOccurrences,
		SuppressedCount:     totalSuppressed,
		DispatchedAlerts:    len(d.aggregations),
		NoiseReductionRate:  rate,
		ActiveChannels:      activeCount,
	}
}
