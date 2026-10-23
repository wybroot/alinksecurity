package dashboard

import (
	"testing"
	"time"
)

func TestDashboardService(t *testing.T) {
	svc := NewService()
	overview := svc.GetOverview()

	if overview.TotalAgents < 6 {
		t.Fatalf("expected at least 6 default agents, got %d", overview.TotalAgents)
	}

	if overview.OnlineAgents != overview.TotalAgents {
		t.Fatalf("expected all default agents online, got %d/%d", overview.OnlineAgents, overview.TotalAgents)
	}

	if overview.Compliance == nil || overview.Compliance.OverallScore < 95.0 {
		t.Fatalf("expected compliance score >= 95.0, got %v", overview.Compliance)
	}

	// 记录心跳更新
	svc.RecordHeartbeat(AgentTelemetry{
		AgentID:     "agent-waf-node01",
		AgentType:   "WAF",
		HostIP:      "192.168.10.10",
		Status:      "ONLINE",
		CPUUsage:    2.5,
		MemoryMB:    30.2,
		ActiveRules: 150,
	})

	// 记录安全事件
	svc.RecordEvent(ThreatEventSummary{
		EventID:    "TEST-EVT-01",
		Timestamp:  time.Now(),
		Component:  "WAF",
		ThreatType: "XSS_ATTACK",
		Severity:   "HIGH",
		SourceIP:   "10.0.0.99",
		Summary:    "Cross-site scripting blocked",
		Action:     "BLOCKED",
	})

	updated := svc.GetOverview()
	if updated.TotalThreatsToday <= overview.TotalThreatsToday {
		t.Fatalf("expected threat count to increase, got %d <= %d", updated.TotalThreatsToday, overview.TotalThreatsToday)
	}

	if updated.RecentEvents[0].EventID != "TEST-EVT-01" {
		t.Fatalf("expected latest event to be TEST-EVT-01, got %s", updated.RecentEvents[0].EventID)
	}
}
