package hub

import (
	"context"
	"net"
	"testing"
	"time"

	pb "alinksec/api/proto/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

func dialer(s *HubServer) func(context.Context, string) (net.Conn, error) {
	lis := bufconn.Listen(bufSize)
	baseServer := grpc.NewServer()
	pb.RegisterAlinkSecHubServiceServer(baseServer, s)

	go func() {
		if err := baseServer.Serve(lis); err != nil {
			panic(err)
		}
	}()

	return func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
}

func setupTestGRPC(t *testing.T) (pb.AlinkSecHubServiceClient, *HubServer, func()) {
	hubServer := NewHubServer()
	ctx := context.Background()

	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(dialer(hubServer)),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial bufnet: %v", err)
	}

	client := pb.NewAlinkSecHubServiceClient(conn)

	cleanup := func() {
		conn.Close()
	}

	return client, hubServer, cleanup
}

func TestRegisterAndHeartbeat(t *testing.T) {
	client, hubServer, cleanup := setupTestGRPC(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 1. 测试注册
	regResp, err := client.RegisterAgent(ctx, &pb.RegisterRequest{
		AgentId:   "agent-edr-001",
		AgentType: pb.AgentType_AGENT_EDR,
		Version:   "1.0.0",
		Hostname:  "prod-node-01",
		Ip:        "192.168.10.15",
		Mac:       "52:54:00:12:34:56",
		Os:        "Linux 5.15.0",
		Arch:      "x86_64",
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	if !regResp.Success || regResp.SessionToken == "" {
		t.Fatalf("unexpected register response: %+v", regResp)
	}

	token := regResp.SessionToken

	// 2. 测试心跳探活 (正常情况)
	hbResp, err := client.SendHeartbeat(ctx, &pb.HeartbeatRequest{
		AgentId:           "agent-edr-001",
		SessionToken:      token,
		Timestamp:         time.Now().Unix(),
		CpuUsage:          12.5,
		MemoryUsedBytes:   1024 * 1024 * 250,
		DiskUsedBytes:     1024 * 1024 * 1024 * 10,
		ActiveRulesCount:  3,
	})
	if err != nil {
		t.Fatalf("SendHeartbeat failed: %v", err)
	}

	if !hbResp.Acknowledged {
		t.Fatal("expected heartbeat to be acknowledged")
	}

	// 验证内存状态更新
	agent, ok := hubServer.GetAgent("agent-edr-001")
	if !ok || agent.CPUUsage != 12.5 {
		t.Fatalf("agent state in hub was not updated properly: %+v", agent)
	}

	// 3. 测试心跳探活 (非法 Token)
	_, err = client.SendHeartbeat(ctx, &pb.HeartbeatRequest{
		AgentId:      "agent-edr-001",
		SessionToken: "invalid-token",
		Timestamp:    time.Now().Unix(),
	})
	if err == nil {
		t.Fatal("expected error for invalid session token, got nil")
	}
}

func TestPolicySync(t *testing.T) {
	client, _, cleanup := setupTestGRPC(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 注册探针
	regResp, err := client.RegisterAgent(ctx, &pb.RegisterRequest{
		AgentId:   "agent-tamper-001",
		AgentType: pb.AgentType_AGENT_TAMPER,
		Hostname:  "web-node-01",
		Ip:        "192.168.10.20",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// 拉取策略
	policy, err := client.SyncPolicy(ctx, &pb.PolicySyncRequest{
		AgentId:              "agent-tamper-001",
		SessionToken:         regResp.SessionToken,
		CurrentPolicyVersion: "",
	})
	if err != nil {
		t.Fatalf("SyncPolicy failed: %v", err)
	}

	if policy.PolicyVersion != "v1.0.0" {
		t.Fatalf("expected policy version v1.0.0, got %s", policy.PolicyVersion)
	}

	if len(policy.FileRules) == 0 {
		t.Fatal("expected file rules in policy package")
	}
}

func TestReportEventsStreaming(t *testing.T) {
	client, hubServer, cleanup := setupTestGRPC(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 注册探针
	_, err := client.RegisterAgent(ctx, &pb.RegisterRequest{
		AgentId:   "agent-waf-001",
		AgentType: pb.AgentType_AGENT_WAF,
		Hostname:  "waf-gateway-01",
		Ip:        "192.168.1.100",
	})
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	initialHash := hubServer.GetLastChainedHash()

	stream, err := client.ReportEvents(ctx)
	if err != nil {
		t.Fatalf("ReportEvents stream create failed: %v", err)
	}

	// 发送三条安全事件
	events := []*pb.RawSecurityEvent{
		{
			EventId:         "evt-001",
			SourceAgentType: pb.AgentType_AGENT_WAF,
			AgentId:         "agent-waf-001",
			HostIp:          "192.168.1.100",
			Hostname:        "waf-gateway-01",
			EventTime:       time.Now().Unix(),
			Level:           pb.EventLevel_LEVEL_HIGH,
			Category:        "SQL_INJECTION",
			RuleId:          "rule_waf_sqli",
			Message:         "Detected SQL injection attempt in /login?user=admin' OR 1=1--",
		},
		{
			EventId:         "evt-002",
			SourceAgentType: pb.AgentType_AGENT_WAF,
			AgentId:         "agent-waf-001",
			HostIp:          "192.168.1.100",
			Hostname:        "waf-gateway-01",
			EventTime:       time.Now().Unix(),
			Level:           pb.EventLevel_LEVEL_CRITICAL,
			Category:        "RCE_ATTEMPT",
			RuleId:          "rule_waf_rce",
			Message:         "Detected command injection in /api/ping?ip=127.0.0.1;whoami",
		},
		{
			EventId:         "evt-003",
			SourceAgentType: pb.AgentType_AGENT_WAF,
			AgentId:         "agent-waf-001",
			HostIp:          "192.168.1.100",
			Hostname:        "waf-gateway-01",
			EventTime:       time.Now().Unix(),
			Level:           pb.EventLevel_LEVEL_WARN,
			Category:        "SCANNER",
			RuleId:          "rule_waf_scan",
			Message:         "Detected vulnerability scanner User-Agent: sqlmap/1.7",
		},
	}

	for _, evt := range events {
		if err := stream.Send(evt); err != nil {
			t.Fatalf("failed to send event: %v", err)
		}
	}

	ack, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("failed to close and receive ack: %v", err)
	}

	if ack.AcceptedCount != 3 {
		t.Fatalf("expected 3 accepted events, got %d", ack.AcceptedCount)
	}

	// 验证防篡改链式哈希已被更新且发生雪崩效应变化
	newHash := hubServer.GetLastChainedHash()
	if newHash == initialHash {
		t.Fatal("expected anti-tamper chained hash to be updated, but remained unchanged")
	}
}
