package soar

import (
	"testing"
)

func TestSOAREngineLifecycle(t *testing.T) {
	engine := NewSOAREngine()
	if engine == nil {
		t.Fatal("NewSOAREngine returned nil")
	}

	// 验证内置剧本
	playbooks := engine.GetPlaybooks()
	if len(playbooks) < 4 {
		t.Fatalf("expected at least 4 playbooks, got %d", len(playbooks))
	}

	// 验证预置封禁与告警
	incidents := engine.GetIncidents()
	if len(incidents) < 2 {
		t.Fatalf("expected at least 2 preset incidents, got %d", len(incidents))
	}

	blocked := engine.GetBlockedIPs()
	if len(blocked) < 2 {
		t.Fatalf("expected at least 2 preset blocked IPs, got %d", len(blocked))
	}

	// 测试解除封禁
	testIP := "198.51.100.88"
	err := engine.UnblockIP(testIP, "sec_admin")
	if err != nil {
		t.Fatalf("failed to unblock IP: %v", err)
	}

	// 再次查验封禁状态
	var foundActive bool
	for _, b := range engine.GetBlockedIPs() {
		if b.IP == testIP && b.Active {
			foundActive = true
		}
	}
	if foundActive {
		t.Fatalf("expected IP %s to be inactive in blocklist", testIP)
	}

	// 测试剧本切换
	err = engine.TogglePlaybook("PB-APT-01", false)
	if err != nil {
		t.Fatalf("failed to toggle playbook: %v", err)
	}

	// 测试多阶段 APT 实弹协同演练
	drillIP := "192.0.2.199"
	drillInc := engine.RunMultiStageDrill(drillIP)
	if drillInc == nil {
		t.Fatal("RunMultiStageDrill returned nil incident")
	}

	if drillInc.SourceIP != drillIP {
		t.Fatalf("expected source IP %s, got %s", drillIP, drillInc.SourceIP)
	}

	if drillInc.ThreatScore < 90 {
		t.Fatalf("expected threat score >= 90 for multi-stage attack, got %d", drillInc.ThreatScore)
	}

	if len(drillInc.Stages) < 3 {
		t.Fatalf("expected at least 3 kill chain stages, got %d", len(drillInc.Stages))
	}

	if drillInc.DigitalSignature == "" {
		t.Fatal("expected digital signature on incident, got empty")
	}
}
