package bastion

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// CommandRiskLevel 指令风险等级
type CommandRiskLevel string

const (
	RiskSafe     CommandRiskLevel = "SAFE"
	RiskLow      CommandRiskLevel = "LOW"
	RiskMedium   CommandRiskLevel = "MEDIUM"
	RiskHigh     CommandRiskLevel = "HIGH"
	RiskCritical CommandRiskLevel = "CRITICAL"
)

// BlockAction 处置动作
type BlockAction string

const (
	ActionAllow BlockAction = "ALLOW"
	ActionWarn  BlockAction = "WARN"
	ActionBlock BlockAction = "BLOCK"
)

// CommandRule 高危指令防御规则
type CommandRule struct {
	RuleID      string           `json:"rule_id"`
	Name        string           `json:"name"`
	Pattern     string           `json:"pattern"`
	Compiled    *regexp.Regexp   `json:"-"`
	RiskLevel   CommandRiskLevel `json:"risk_level"`
	Action      BlockAction      `json:"action"`
	Description string           `json:"description"`
	MLPSClause  string           `json:"mlps_clause"` // 等保 2.0 对应条款 (如 8.1.4.3 a)
}

// CommandCheckResult 检查结果
type CommandCheckResult struct {
	Allowed     bool             `json:"allowed"`
	Action      BlockAction      `json:"action"`
	RiskLevel   CommandRiskLevel `json:"risk_level"`
	MatchedRule *CommandRule     `json:"matched_rule,omitempty"`
	Reason      string           `json:"reason"`
	Timestamp   int64            `json:"timestamp"`
}

// Engine 4A 堡垒机高危指令防御引擎
type Engine struct {
	rules []*CommandRule
}

// NewEngine 初始化高危指令过滤引擎
func NewEngine() *Engine {
	e := &Engine{
		rules: make([]*CommandRule, 0),
	}
	e.loadDefaultRules()
	return e
}

func (e *Engine) loadDefaultRules() {
	defaultRules := []CommandRule{
		{
			RuleID:      "CMD-101",
			Name:        "全盘与根目录递归删除阻断",
			Pattern:     `(?i)\brm\s+.*(-[a-zA-Z]*[rf][a-zA-Z]*).*(\/|\/\*|~\/|\*|\/root|\/etc)($|\s)`,
			RiskLevel:   RiskCritical,
			Action:      ActionBlock,
			Description: "拦截针对系统根目录、主目录或全局通配符的递归物理删除",
			MLPSClause:  "GB/T 22239-2019 8.1.4.3 (安全计算环境/访问控制)",
		},
		{
			RuleID:      "CMD-102",
			Name:        "根目录不当全开特权提权阻断",
			Pattern:     `(?i)\bchmod\s+(-R\s+)?(777|666)\s+(\/|\/etc|\/root|\/bin)($|\s)`,
			RiskLevel:   RiskCritical,
			Action:      ActionBlock,
			Description: "拦截将系统关键根目录权限设置为全局可读写执行 777 的违规操作",
			MLPSClause:  "GB/T 22239-2019 8.1.4.3 (安全计算环境/最小授权原则)",
		},
		{
			RuleID:      "CMD-103",
			Name:        "底层磁盘物理格式化与覆写阻断",
			Pattern:     `(?i)\b(mkfs\.[a-z0-9]+|fdisk\s+\/dev\/|dd\s+if=\/dev\/(zero|urandom)\s+of=\/dev\/[shv]d[a-z])`,
			RiskLevel:   RiskCritical,
			Action:      ActionBlock,
			Description: "拦截通过 mkfs、dd、fdisk 对底层块设备的直接格式化与物理擦除破坏",
			MLPSClause:  "GB/T 22239-2019 8.1.4.3 (安全计算环境/安全破坏防范)",
		},
		{
			RuleID:      "CMD-104",
			Name:        "敏感核心凭据文件非法访问阻断",
			Pattern:     `(?i)\b(cat|more|less|tail|head|vi|vim|nano)\s+(\/etc\/shadow|\/etc\/gshadow|\/etc\/security\/opasswd)($|\s)`,
			RiskLevel:   RiskHigh,
			Action:      ActionBlock,
			Description: "拦截直接打印或读取 Linux /etc/shadow 用户口令哈希敏感文件",
			MLPSClause:  "GB/T 22239-2019 8.1.4.1 (身份鉴别/鉴别信息防泄露)",
		},
		{
			RuleID:      "CMD-105",
			Name:        "未授权清空网络防火墙策略阻断",
			Pattern:     `(?i)\b(iptables\s+-F|ip6tables\s+-F|nft\s+flush\s+ruleset|ufw\s+disable)($|\s)`,
			RiskLevel:   RiskHigh,
			Action:      ActionBlock,
			Description: "拦截运维人员单方面直接关闭或清空 Linux 宿主机网络防火墙规则集",
			MLPSClause:  "GB/T 22239-2019 8.1.3.1 (安全区域边界/访问控制规则保护)",
		},
		{
			RuleID:      "CMD-106",
			Name:        "非法新建 UID=0 超级特权后门账号阻断",
			Pattern:     `(?i)\buseradd\s+.*(-o\s+-u\s+0|-u\s+0\s+-o)`,
			RiskLevel:   RiskCritical,
			Action:      ActionBlock,
			Description: "拦截在 Linux 系统中隐秘创建 UID 为 0 的 root 特权镜像后门用户",
			MLPSClause:  "GB/T 22239-2019 8.1.4.3 (安全计算环境/特权用户独立与禁用后门)",
		},
		{
			RuleID:      "CMD-107",
			Name:        "生产服务器非计划紧急关机/下电拦截",
			Pattern:     `(?i)\b(shutdown\s+(-h|-P|now)|poweroff|init\s+0|halt\s+-p)($|\s)`,
			RiskLevel:   RiskHigh,
			Action:      ActionBlock,
			Description: "拦截直接在远程终端执行紧急停机或下电操作，需走工单审批流程",
			MLPSClause:  "GB/T 22239-2019 8.1.5.1 (安全管理中心/运维操作规范)",
		},
	}

	for _, r := range defaultRules {
		rCopy := r
		compiled, err := regexp.Compile(rCopy.Pattern)
		if err == nil {
			rCopy.Compiled = compiled
			e.rules = append(e.rules, &rCopy)
		}
	}
}

// CheckCommand 检查运维指令
func (e *Engine) CheckCommand(rawCmd string) *CommandCheckResult {
	trimmed := strings.TrimSpace(rawCmd)
	now := time.Now().Unix()

	if trimmed == "" {
		return &CommandCheckResult{
			Allowed:   true,
			Action:    ActionAllow,
			RiskLevel: RiskSafe,
			Reason:    "Empty command",
			Timestamp: now,
		}
	}

	for _, rule := range e.rules {
		if rule.Compiled != nil && rule.Compiled.MatchString(trimmed) {
			return &CommandCheckResult{
				Allowed:     rule.Action != ActionBlock,
				Action:      rule.Action,
				RiskLevel:   rule.RiskLevel,
				MatchedRule: rule,
				Reason:      fmt.Sprintf("[等保4A阻断] 触发高危规则 %s (%s): %s", rule.RuleID, rule.Name, rule.Description),
				Timestamp:   now,
			}
		}
	}

	return &CommandCheckResult{
		Allowed:   true,
		Action:    ActionAllow,
		RiskLevel: RiskSafe,
		Reason:    "Command passed safety verification",
		Timestamp: now,
	}
}

// GetRules 获取当前激活的所有高危指令规则
func (e *Engine) GetRules() []*CommandRule {
	return e.rules
}
