package bastion

import (
	"testing"
)

func TestBastionEngineRuleBlocking(t *testing.T) {
	engine := NewEngine()

	cases := []struct {
		cmd        string
		wantBlock  bool
		wantRuleID string
	}{
		{"ls -la /var/log", false, ""},
		{"systemctl status nginx", false, ""},
		{"rm -rf /", true, "CMD-101"},
		{"rm -rf /*", true, "CMD-101"},
		{"chmod -R 777 /", true, "CMD-102"},
		{"mkfs.ext4 /dev/sdb1", true, "CMD-103"},
		{"cat /etc/shadow", true, "CMD-104"},
		{"iptables -F", true, "CMD-105"},
		{"useradd -o -u 0 -g 0 backdoor", true, "CMD-106"},
		{"shutdown -h now", true, "CMD-107"},
	}

	for _, tc := range cases {
		res := engine.CheckCommand(tc.cmd)
		if tc.wantBlock {
			if res.Allowed {
				t.Errorf("Expected command '%s' to be BLOCKED, but was ALLOWED", tc.cmd)
			}
			if res.MatchedRule == nil || res.MatchedRule.RuleID != tc.wantRuleID {
				t.Errorf("Command '%s': expected rule %s, got %v", tc.cmd, tc.wantRuleID, res.MatchedRule)
			}
		} else {
			if !res.Allowed {
				t.Errorf("Expected safe command '%s' to be ALLOWED, but was BLOCKED: %s", tc.cmd, res.Reason)
			}
		}
	}
}

func TestSessionTamperProofChain(t *testing.T) {
	session := NewSession("SESS-TEST-001", "ops_admin", "192.168.1.100", "192.168.1.200", "root", "SSH")
	engine := NewEngine()

	commands := []string{
		"pwd",
		"cd /var/www",
		"ls -la",
		"cat /etc/shadow", // Should be blocked
		"git status",
		"rm -rf /", // Should be blocked
		"exit",
	}

	for _, cmd := range commands {
		res := engine.CheckCommand(cmd)
		session.RecordCommand(cmd, res)
	}

	if session.TotalCmds != int64(len(commands)) {
		t.Fatalf("Expected %d commands, got %d", len(commands), session.TotalCmds)
	}
	if session.BlockedCmds != 2 {
		t.Fatalf("Expected 2 blocked commands, got %d", session.BlockedCmds)
	}

	// 验证未被篡改时链完整性
	valid, count := session.VerifyIntegrity()
	if !valid {
		t.Fatalf("Integrity verification failed unexpectedly at index %d", count)
	}

	// 导出电子存证证书并核验
	cert := session.GenerateCertificate()
	if !cert.IntegrityPass {
		t.Errorf("Certificate integrity pass flag is false")
	}
	if cert.TotalCommands != int64(len(commands)) || cert.BlockedCount != 2 {
		t.Errorf("Certificate counters mismatch: %+v", cert)
	}

	// 模拟攻击者非法篡改历史审计记录第 2 条命令
	session.Commands[2].Command = "malicious_covert_script.sh"
	tamperedValid, failedIdx := session.VerifyIntegrity()
	if tamperedValid {
		t.Fatalf("Tampered session chain was falsely verified as valid!")
	}
	if failedIdx != 2 {
		t.Errorf("Expected failure at index 2, got index %d", failedIdx)
	}
}
