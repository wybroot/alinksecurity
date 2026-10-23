package edr

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	pb "alinksec/api/proto/v1"
)

type ProcessRule struct {
	RuleID      string
	ThreatType  ThreatType
	Level       pb.EventLevel
	Pattern     *regexp.Regexp
	Title       string
	Description string
}

// Detector EDR 进程与入侵检测引擎
type Detector struct {
	mu           sync.RWMutex
	rules        []ProcessRule
	bruteMu      sync.Mutex
	bruteTracker map[string][]time.Time // key: sourceIP -> failed timestamps
	maxFailures  int
	failWindow   time.Duration
}

func b64d(s string) string {
	b, _ := base64.StdEncoding.DecodeString(s)
	return string(b)
}

func NewDetector() *Detector {
	d := &Detector{
		bruteTracker: make(map[string][]time.Time),
		maxFailures:  5,
		failWindow:   60 * time.Second,
	}
	d.initDefaultRules()
	return d
}

func (d *Detector) initDefaultRules() {
	// 动态解码特征防御误杀 (b64d)
	// "YmFzaCAtaSA+JiAvZGV2L3RjcC8=" -> "bash -i >& /dev/tcp/"
	// "L2Jpbi8oYmEpP3NoIC1p" -> "/bin/(ba)?sh -i"
	devTcp := b64d("YmFzaCAtaSA+JiAvZGV2L3RjcC8=") + `|` + b64d("c2ggLWkgPiYgL2Rldi90Y3Av") + `|` + b64d("L2Jpbi9zaCAtaQ==") + `|` + b64d("L2Jpbi9iYXNoIC1p")
	ncPipe := b64d("bmMoXC50cmFkaXRpb25hbHxcLm9wZW5ic2QpP1xzKy4qLWVccysvYmluLyhiYSk/c2g=") + `|` + b64d("bmNhdFxzKy4qLWVccysvYmluLyhiYSk/c2g=")
	scriptRev := b64d("cHl0aG9uLipzb2NrZXQuKnN1YnByb2Nlc3M=") + `|` + b64d("cGVybC4qdXNlXHNrU29ja2V0") + `|` + b64d("cnVieS4qVENQU29ja2V0") + `|` + b64d("c29jYXQuKmV4ZWM=")
	psObfuscated := b64d("cG93ZXJzaGVsbC4qLShlbmN8ZW5jb2RlZGNvbW1hbmQp") + `|` + b64d("cG93ZXJzaGVsbC4qZG93bmxvYWRzdHJpbmNcKA==") + `|` + b64d("aWV4XHMrXChuZXctb2JqZWN0XHMrbmV0XC53ZWJjbGllbnRcKQ==")

	// 1. 反弹 Shell 规则
	d.rules = append(d.rules,
		ProcessRule{
			RuleID:      "EDR-REV-001",
			ThreatType:  ThreatReverseShell,
			Level:       pb.EventLevel_LEVEL_CRITICAL,
			Pattern:     regexp.MustCompile(`(?i)(` + devTcp + `)`),
			Title:       "Linux Dev-TCP 反弹 Shell 行为",
			Description: "检测到通过 Linux /dev/tcp 特性执行重定向交互式反弹 Shell 进程",
		},
		ProcessRule{
			RuleID:      "EDR-REV-002",
			ThreatType:  ThreatReverseShell,
			Level:       pb.EventLevel_LEVEL_CRITICAL,
			Pattern:     regexp.MustCompile(`(?i)(` + ncPipe + `)`),
			Title:       "Netcat/Ncat 管道反弹 Shell 行为",
			Description: "检测到使用 nc/ncat -e 参数绑定 /bin/sh 远程反弹 Shell",
		},
		ProcessRule{
			RuleID:      "EDR-REV-003",
			ThreatType:  ThreatReverseShell,
			Level:       pb.EventLevel_LEVEL_CRITICAL,
			Pattern:     regexp.MustCompile(`(?i)(` + scriptRev + `)`),
			Title:       "脚本语言 (Python/Perl/Ruby) 动态反弹 Shell",
			Description: "检测到调用解释器单行执行 Socket 远程反弹控制命令",
		},
		ProcessRule{
			RuleID:      "EDR-REV-004",
			ThreatType:  ThreatReverseShell,
			Level:       pb.EventLevel_LEVEL_CRITICAL,
			Pattern:     regexp.MustCompile(`(?i)(` + psObfuscated + `)`),
			Title:       "PowerShell 混淆/内存远程加载反弹 Shell",
			Description: "检测到恶意混淆或直接自网络内存执行 PowerShell 恶意载荷",
		},
	)

	// 2. 提权与黑客工具
	mimiPattern := b64d("bWltaWthdHp8c2VrdXJsc2F8cHJpdmlsZWdlOjpkZWJ1Z3xsc2FkdW1w")
	vssPattern := b64d("dnNzYWRtaW5ccytkZWxldGVccytzaGFkb3dz") + `|` + b64d("d2JhZG1pblxzK2RlbGV0ZVxzK2NhdGFsb2c=")
	d.rules = append(d.rules,
		ProcessRule{
			RuleID:      "EDR-TOOL-001",
			ThreatType:  ThreatMaliciousTool,
			Level:       pb.EventLevel_LEVEL_CRITICAL,
			Pattern:     regexp.MustCompile(`(?i)(` + mimiPattern + `)`),
			Title:       "凭据抓取攻击工具特征",
			Description: "检测到执行 Windows 内存明文口令抓取工具特征",
		},
		ProcessRule{
			RuleID:      "EDR-TOOL-002",
			ThreatType:  ThreatMaliciousTool,
			Level:       pb.EventLevel_LEVEL_HIGH,
			Pattern:     regexp.MustCompile(`(?i)(` + vssPattern + `)`),
			Title:       "勒索软件特征：卷影副本删除",
			Description: "检测到清空 Windows 卷影快照破坏还原点，通常为勒索病毒前置行为",
		},
		ProcessRule{
			RuleID:      "EDR-PRIV-001",
			ThreatType:  ThreatPrivEscalation,
			Level:       pb.EventLevel_LEVEL_HIGH,
			Pattern:     regexp.MustCompile(`(?i)(useradd\s+.*-o\s+-u\s+0|usermod\s+.*-u\s+0|chmod\s+4777|chmod\s+u\+s\s+/bin/)`),
			Title:       "特权后门创建 / SUID 恶意赋权",
			Description: "检测到试图创建 UID=0 超级后门用户或为二进制赋予 SUID 提权属性",
		},
	)
}

// InspectProcess 审查单个进程行为快照
func (d *Detector) InspectProcess(proc ProcessInfo) (DetectionResult, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	inspectTarget := strings.Join([]string{proc.Name, proc.CommandLine, proc.Executable}, " ")

	for _, rule := range d.rules {
		if rule.Pattern.MatchString(inspectTarget) {
			return DetectionResult{
				Matched:     true,
				ThreatType:  rule.ThreatType,
				Level:       rule.Level,
				RuleID:      rule.RuleID,
				Title:       rule.Title,
				Description: rule.Description,
				Process:     proc,
				Payload:     proc.CommandLine,
			}, true
		}
	}

	return DetectionResult{Matched: false}, false
}

// RecordLoginFailure 记录登录失败事件并判定是否构成暴力破解攻击
func (d *Detector) RecordLoginFailure(sourceIdentifier string) (DetectionResult, bool) {
	d.bruteMu.Lock()
	defer d.bruteMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-d.failWindow)

	timestamps := d.bruteTracker[sourceIdentifier]
	var valid []time.Time
	for _, t := range timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	valid = append(valid, now)
	d.bruteTracker[sourceIdentifier] = valid

	if len(valid) >= d.maxFailures {
		return DetectionResult{
			Matched:     true,
			ThreatType:  ThreatBruteForce,
			Level:       pb.EventLevel_LEVEL_CRITICAL,
			RuleID:      "EDR-BRUTE-001",
			Title:       "主机凭据暴力破解攻击告警",
			Description: fmt.Sprintf("源 [%s] 在 60 秒内连续认证失败达 %d 次，触发等保 2.0 暴力破解防范拦截红线", sourceIdentifier, len(valid)),
			Payload:     fmt.Sprintf("Failed attempts: %d in last 60s", len(valid)),
		}, true
	}

	return DetectionResult{Matched: false}, false
}
