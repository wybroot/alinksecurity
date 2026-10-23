package waf

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	pb "alinksec/api/proto/v1"
)

// ThreatType 威胁分类
type ThreatType string

const (
	ThreatSQLi          ThreatType = "SQL_INJECTION"
	ThreatXSS           ThreatType = "CROSS_SITE_SCRIPTING"
	ThreatRCE           ThreatType = "COMMAND_INJECTION"
	ThreatPathTraversal ThreatType = "PATH_TRAVERSAL"
	ThreatScanner       ThreatType = "MALICIOUS_SCANNER"
	ThreatRateLimit     ThreatType = "RATE_LIMIT_EXCEEDED"
)

// MatchResult 检测结果
type MatchResult struct {
	Matched     bool
	ThreatType  ThreatType
	Severity    pb.EventLevel
	RuleID      string
	Description string
	MatchedPart string
	Sample      string
}

// Rule 规则定义
type Rule struct {
	ID          string
	Type        ThreatType
	Severity    pb.EventLevel
	Pattern     *regexp.Regexp
	Description string
}

// RateLimiter 基于滑动窗口的 IP 限流器 (抗 CC 攻击)
type RateLimiter struct {
	mu          sync.Mutex
	limits      map[string][]time.Time
	maxRequests int
	window      time.Duration
}

func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limits:      make(map[string][]time.Time),
		maxRequests: maxRequests,
		window:      window,
	}
}

// Allow 检查指定 IP 在时间窗口内是否超限
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	timestamps := rl.limits[ip]
	valid := make([]time.Time, 0, len(timestamps))
	for _, t := range timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.maxRequests {
		rl.limits[ip] = valid
		return false
	}

	valid = append(valid, now)
	rl.limits[ip] = valid
	return true
}

// Engine WAF 核心规则引擎
type Engine struct {
	mu          sync.RWMutex
	rules       []Rule
	rateLimiter *RateLimiter
	ipBlacklist map[string]bool
	ipWhitelist map[string]bool
}

// NewEngine 初始化规则引擎并预置主流 OWASP Top 10 核心防御特征
func NewEngine() *Engine {
	e := &Engine{
		rateLimiter: NewRateLimiter(100, 10*time.Second), // 默认单个 IP 10 秒内最多 100 次请求
		ipBlacklist: make(map[string]bool),
		ipWhitelist: make(map[string]bool),
	}
	e.initDefaultRules()
	return e
}

func (e *Engine) initDefaultRules() {
	// 1. SQL 注入规则
	e.rules = append(e.rules,
		Rule{
			ID:          "WAF-SQLI-001",
			Type:        ThreatSQLi,
			Severity:    pb.EventLevel_LEVEL_CRITICAL,
			Pattern:     regexp.MustCompile(`(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+(table|database)|truncate\s+table)`),
			Description: "SQL Injection: High-risk SQL keyword pattern",
		},
		Rule{
			ID:          "WAF-SQLI-002",
			Type:        ThreatSQLi,
			Severity:    pb.EventLevel_LEVEL_HIGH,
			Pattern:     regexp.MustCompile(`(?i)('.*or.*'.*=.*'|'.*or\s+1\s*=\s*1|or\s+1\s*=\s*1|--\s*$|/\*.*\*\/)`),
			Description: "SQL Injection: Boolean bypass or comment attack",
		},
		Rule{
			ID:          "WAF-SQLI-003",
			Type:        ThreatSQLi,
			Severity:    pb.EventLevel_LEVEL_HIGH,
			Pattern:     regexp.MustCompile(`(?i)(information_schema|sys\.databases|pg_sleep|sleep\(\s*\d+\s*\)|waitfor\s+delay)`),
			Description: "SQL Injection: Schema probe or time-based blind injection",
		},
	)

	// 2. XSS 跨站脚本规则
	e.rules = append(e.rules,
		Rule{
			ID:          "WAF-XSS-001",
			Type:        ThreatXSS,
			Severity:    pb.EventLevel_LEVEL_HIGH,
			Pattern:     regexp.MustCompile(`(?i)(<\s*script[^>]*>|<\s*/\s*script\s*>|javascript\s*:|vbscript\s*:)`),
			Description: "Cross-Site Scripting: Script tag or script pseudoprotocol",
		},
		Rule{
			ID:          "WAF-XSS-002",
			Type:        ThreatXSS,
			Severity:    pb.EventLevel_LEVEL_WARN,
			Pattern:     regexp.MustCompile(`(?i)(on(load|error|click|mouseover|submit|focus)\s*=|eval\s*\(|alert\s*\(|document\.cookie)`),
			Description: "Cross-Site Scripting: Inline event handler or DOM API abuse",
		},
	)

	// 3. 路径穿越与敏感文件包含规则
	e.rules = append(e.rules,
		Rule{
			ID:          "WAF-LFI-001",
			Type:        ThreatPathTraversal,
			Severity:    pb.EventLevel_LEVEL_CRITICAL,
			Pattern:     regexp.MustCompile(`(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|boot\.ini|win\.ini)`),
			Description: "Path Traversal / Local File Inclusion: Directory escape or sensitive file probe",
		},
	)

	// 4. 命令注入 / RCE 规则
	e.rules = append(e.rules,
		Rule{
			ID:          "WAF-RCE-001",
			Type:        ThreatRCE,
			Severity:    pb.EventLevel_LEVEL_CRITICAL,
			Pattern:     regexp.MustCompile(`(?i)(;\s*(cat|ls|id|whoami|nc|ncat|bash|sh|curl|wget)\b|\|\s*(cat|ls|id|whoami|nc|ncat|bash|sh|curl|wget)\b|\${IFS}|` + "`" + `\s*(id|whoami)\s*` + "`" + `)`),
			Description: "Remote Command Execution: Shell metacharacter injection",
		},
	)

	// 5. 扫描器与自动化黑客工具探测
	e.rules = append(e.rules,
		Rule{
			ID:          "WAF-SCAN-001",
			Type:        ThreatScanner,
			Severity:    pb.EventLevel_LEVEL_WARN,
			Pattern:     regexp.MustCompile(`(?i)(sqlmap|acunetix|nikto|nmap|nessus|masscan|gobuster|dirsearch|wpscan)`),
			Description: "Malicious Scanner: Known automated vulnerability tool footprint",
		},
	)
}

// SetIPBlacklist 设置 IP 黑名单
func (e *Engine) SetIPBlacklist(ip string, blocked bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if blocked {
		e.ipBlacklist[ip] = true
	} else {
		delete(e.ipBlacklist, ip)
	}
}

// Inspect 深度审查传入 HTTP 请求的目标元素
func (e *Engine) Inspect(clientIP, method, rawURI, userAgent string, headers map[string]string, body []byte) MatchResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 1. IP 黑白名单核查
	if e.ipWhitelist[clientIP] {
		return MatchResult{Matched: false}
	}
	if e.ipBlacklist[clientIP] {
		return MatchResult{
			Matched:     true,
			ThreatType:  ThreatRateLimit,
			Severity:    pb.EventLevel_LEVEL_CRITICAL,
			RuleID:      "WAF-IP-BLACKLIST",
			Description: "Access denied by WAF IP Blacklist",
			MatchedPart: "ClientIP",
			Sample:      clientIP,
		}
	}

	// 2. CC 防护 / 速率限制
	if !e.rateLimiter.Allow(clientIP) {
		return MatchResult{
			Matched:     true,
			ThreatType:  ThreatRateLimit,
			Severity:    pb.EventLevel_LEVEL_HIGH,
			RuleID:      "WAF-CC-LIMIT",
			Description: "Request rate exceeded limit (anti-CC trigger)",
			MatchedPart: "ClientIP",
			Sample:      clientIP,
		}
	}

	// 3. User-Agent 扫描器指纹核查
	for _, rule := range e.rules {
		if rule.Type == ThreatScanner && rule.Pattern.MatchString(userAgent) {
			return MatchResult{
				Matched:     true,
				ThreatType:  rule.Type,
				Severity:    rule.Severity,
				RuleID:      rule.ID,
				Description: rule.Description,
				MatchedPart: "User-Agent",
				Sample:      userAgent,
			}
		}
	}

	// 4. URI 及 Query 参数深度解码核查 (包含两层 URL 解码防御双重编码绕过)
	decodedURI, err := url.QueryUnescape(rawURI)
	if err != nil {
		decodedURI = rawURI
	}
	// 二次解码防御双重编码攻击 (Double URL Encoding)
	if secondDecode, err := url.QueryUnescape(decodedURI); err == nil {
		decodedURI = secondDecode
	}

	for _, rule := range e.rules {
		if rule.Pattern.MatchString(decodedURI) {
			return MatchResult{
				Matched:     true,
				ThreatType:  rule.Type,
				Severity:    rule.Severity,
				RuleID:      rule.ID,
				Description: rule.Description,
				MatchedPart: "URI",
				Sample:      decodedURI,
			}
		}
	}

	// 5. Body 请求体核查
	if len(body) > 0 {
		bodyStr := string(body)
		if decodedBody, err := url.QueryUnescape(bodyStr); err == nil {
			bodyStr = decodedBody
		}

		for _, rule := range e.rules {
			if rule.Pattern.MatchString(bodyStr) {
				sample := bodyStr
				if len(sample) > 100 {
					sample = sample[:100] + "..."
				}
				return MatchResult{
					Matched:     true,
					ThreatType:  rule.Type,
					Severity:    rule.Severity,
					RuleID:      rule.ID,
					Description: rule.Description,
					MatchedPart: "Body",
					Sample:      sample,
				}
			}
		}
	}

	// 6. Header 异常注入检查 (针对 Cookie, Referer 等)
	for hKey, hVal := range headers {
		lowerKey := strings.ToLower(hKey)
		if lowerKey == "cookie" || lowerKey == "referer" || lowerKey == "x-forwarded-for" {
			for _, rule := range e.rules {
				if rule.Type != ThreatScanner && rule.Pattern.MatchString(hVal) {
					return MatchResult{
						Matched:     true,
						ThreatType:  rule.Type,
						Severity:    rule.Severity,
						RuleID:      rule.ID,
						Description: rule.Description,
						MatchedPart: "Header: " + hKey,
						Sample:      hVal,
					}
				}
			}
		}
	}

	return MatchResult{Matched: false}
}
