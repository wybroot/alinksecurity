package cfw

import (
	"strings"
	"testing"
)

func TestZoneLookupAndRuleEvaluation(t *testing.T) {
	engine := NewEngine()

	// 1. 验证安全域映射
	if z := engine.LookupZone("10.0.1.15"); z != ZoneDMZ {
		t.Errorf("expected 10.0.1.15 to be ZoneDMZ, got %v", z)
	}
	if z := engine.LookupZone("10.0.2.20"); z != ZoneApp {
		t.Errorf("expected 10.0.2.20 to be ZoneApp, got %v", z)
	}
	if z := engine.LookupZone("10.0.3.88"); z != ZoneData {
		t.Errorf("expected 10.0.3.88 to be ZoneData, got %v", z)
	}

	// 2. 正常合法白名单流量放行测试 (DMZ -> APP:8080)
	allowEvt := engine.EvaluatePacket(PacketContext{
		SrcIP:    "10.0.1.10",
		DstIP:    "10.0.2.5",
		DstPort:  8080,
		Protocol: "TCP",
	})
	if allowEvt.Action != ActionAllow {
		t.Errorf("expected ALLOW for DMZ->APP:8080, got %v", allowEvt.Action)
	}
	if allowEvt.MatchedRuleID != "CFW-PERMIT-DMZ-TO-APP" {
		t.Errorf("unexpected matched rule: %s", allowEvt.MatchedRuleID)
	}

	// 3. 等保 2.0 红线违规阻断测试: DMZ -> DATA:3306 直连违规
	crossZoneEvt := engine.EvaluatePacket(PacketContext{
		SrcIP:    "10.0.1.10",
		DstIP:    "10.0.3.88",
		DstPort:  3306,
		Protocol: "TCP",
	})
	if crossZoneEvt.Action != ActionDrop {
		t.Errorf("expected DROP for cross-zone DMZ->DATA, got %v", crossZoneEvt.Action)
	}
	if !crossZoneEvt.IsViolation || crossZoneEvt.ViolationType != "ZONE_BOUNDARY_CROSSING" {
		t.Errorf("expected ZONE_BOUNDARY_CROSSING violation, got %v", crossZoneEvt.ViolationType)
	}

	// 4. 零信任默认阻断测试 (外部随机未知 IP -> DATA 数据库)
	unauthEvt := engine.EvaluatePacket(PacketContext{
		SrcIP:    "192.168.100.99",
		DstIP:    "10.0.3.88",
		DstPort:  3306,
		Protocol: "TCP",
	})
	if unauthEvt.Action != ActionDrop {
		t.Errorf("expected DROP for unauthenticated connection, got %v", unauthEvt.Action)
	}
	if unauthEvt.ViolationType != "DEFAULT_ZERO_TRUST_DROP" {
		t.Errorf("expected DEFAULT_ZERO_TRUST_DROP, got %s", unauthEvt.ViolationType)
	}
}

func TestExportNftables(t *testing.T) {
	engine := NewEngine()
	nftConfig := engine.ExportNftables()

	if !strings.Contains(nftConfig, "table inet alinksec_filter") {
		t.Fatalf("nftables config missing table header")
	}
	if !strings.Contains(nftConfig, "policy drop") {
		t.Fatalf("nftables config missing drop policy")
	}
	if !strings.Contains(nftConfig, "dport 3306 accept") {
		t.Fatalf("nftables config missing 3306 rule")
	}
}

func TestCFWAgentInspect(t *testing.T) {
	cfg := &AgentConfig{
		AgentID:    "test-cfw-agent",
		Standalone: true,
	}
	agent := NewCFWAgent(cfg)

	var interceptedEvents []*FirewallEvent
	agent.SetEventCallback(func(evt *FirewallEvent) {
		interceptedEvents = append(interceptedEvents, evt)
	})

	// 发送放行流量
	evt1 := agent.InspectPacket(PacketContext{
		SrcIP:    "10.0.2.10",
		DstIP:    "10.0.3.5",
		DstPort:  3306,
		Protocol: "TCP",
	})
	if evt1.Action != ActionAllow {
		t.Errorf("expected Allow, got %v", evt1.Action)
	}

	// 发送违规流量
	evt2 := agent.InspectPacket(PacketContext{
		SrcIP:    "10.0.1.5",
		DstIP:    "10.0.3.5",
		DstPort:  3306,
		Protocol: "TCP",
	})
	if evt2.Action != ActionDrop {
		t.Errorf("expected Drop, got %v", evt2.Action)
	}

	eval, dropped := agent.GetMetrics()
	if eval != 2 || dropped != 1 {
		t.Errorf("unexpected metrics: eval=%d, dropped=%d", eval, dropped)
	}

	if len(interceptedEvents) != 2 {
		t.Errorf("expected 2 intercepted events, got %d", len(interceptedEvents))
	}
}
