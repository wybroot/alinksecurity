package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/logger"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	hubAddr := flag.String("hub", "127.0.0.1:50051", "AlinkSec Hub gRPC address")
	agentID := flag.String("id", "agent-edr-node01", "Agent identifier")
	flag.Parse()

	logger.InitGlobalLogger(logger.Config{
		Level:  "info",
		Format: "text",
	}, os.Stdout)

	logger.Info("Starting Mock Agent", "id", *agentID, "target_hub", *hubAddr)

	conn, err := grpc.Dial(*hubAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logger.Error("Failed to connect to Hub", "err", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := pb.NewAlinkSecHubServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. 探针上线注册
	logger.Info("[Step 1] Registering Agent with Hub...")
	regResp, err := client.RegisterAgent(ctx, &pb.RegisterRequest{
		AgentId:   *agentID,
		AgentType: pb.AgentType_AGENT_EDR,
		Version:   "1.0.0",
		Hostname:  "test-worker-node",
		Ip:        "192.168.10.50",
		Os:        "Windows Server 2022 / Linux",
		Arch:      "amd64",
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		logger.Error("Registration failed", "err", err)
		os.Exit(1)
	}
	logger.Info("[Step 1 Success] Agent registered successfully",
		"session_token", regResp.SessionToken,
		"heartbeat_interval", regResp.HeartbeatIntervalSec,
	)

	sessionToken := regResp.SessionToken

	// 2. 发送心跳探活
	logger.Info("[Step 2] Sending Heartbeat telemetry...")
	hbResp, err := client.SendHeartbeat(ctx, &pb.HeartbeatRequest{
		AgentId:          *agentID,
		SessionToken:     sessionToken,
		Timestamp:        time.Now().Unix(),
		CpuUsage:         8.4,
		MemoryUsedBytes:  1024 * 1024 * 320,
		DiskUsedBytes:    1024 * 1024 * 1024 * 40,
		ActiveRulesCount: 10,
	})
	if err != nil {
		logger.Error("Heartbeat failed", "err", err)
		os.Exit(1)
	}
	logger.Info("[Step 2 Success] Heartbeat acknowledged",
		"need_policy_sync", hbResp.NeedPolicySync,
		"latest_policy_ver", hbResp.LatestPolicyVersion,
	)

	// 3. 拉取并同步防御策略
	logger.Info("[Step 3] Syncing Defense Policies...")
	policy, err := client.SyncPolicy(ctx, &pb.PolicySyncRequest{
		AgentId:              *agentID,
		SessionToken:         sessionToken,
		CurrentPolicyVersion: "",
	})
	if err != nil {
		logger.Error("Policy sync failed", "err", err)
		os.Exit(1)
	}
	logger.Info("[Step 3 Success] Received Policy Package",
		"version", policy.PolicyVersion,
		"file_rules_count", len(policy.FileRules),
		"process_rules_count", len(policy.ProcessRules),
		"network_rules_count", len(policy.NetworkRules),
	)

	for _, fr := range policy.FileRules {
		fmt.Printf("   -> [FileRule] ID: %s, PathPattern: %s, Protected: %v\n", fr.RuleId, fr.PathPattern, fr.IsProtected)
	}
	for _, pr := range policy.ProcessRules {
		fmt.Printf("   -> [ProcessRule] ID: %s, ProcessName: %s, BlockMismatch: %v\n", pr.RuleId, pr.ProcessName, pr.BlockIfMismatch)
	}

	// 4. 模拟上报威胁安全事件 (流式上报)
	logger.Info("[Step 4] Reporting Security Threat Events (Streaming)...")
	stream, err := client.ReportEvents(ctx)
	if err != nil {
		logger.Error("Failed to open report stream", "err", err)
		os.Exit(1)
	}

	events := []*pb.RawSecurityEvent{
		{
			EventId:         fmt.Sprintf("evt-%d-01", time.Now().Unix()),
			SourceAgentType: pb.AgentType_AGENT_EDR,
			AgentId:         *agentID,
			HostIp:          "192.168.10.50",
			Hostname:        "test-worker-node",
			EventTime:       time.Now().Unix(),
			Level:           pb.EventLevel_LEVEL_CRITICAL,
			Category:        "PRIVILEGE_ESCALATION",
			RuleId:          "rule_proc_001",
			Message:         "Detected unauthorized suspicious process spawn: ncat -e /bin/bash",
		},
		{
			EventId:         fmt.Sprintf("evt-%d-02", time.Now().Unix()),
			SourceAgentType: pb.AgentType_AGENT_EDR,
			AgentId:         *agentID,
			HostIp:          "192.168.10.50",
			Hostname:        "test-worker-node",
			EventTime:       time.Now().Unix(),
			Level:           pb.EventLevel_LEVEL_HIGH,
			Category:        "TAMPER_ATTEMPT",
			RuleId:          "rule_file_001",
			Message:         "Blocked unauthorized modification to protected path: /etc/shadow",
		},
	}

	for _, evt := range events {
		if err := stream.Send(evt); err != nil {
			logger.Error("Failed to send event", "err", err)
			os.Exit(1)
		}
		logger.Info("   Sent threat event", "event_id", evt.EventId, "category", evt.Category)
	}

	ack, err := stream.CloseAndRecv()
	if err != nil {
		logger.Error("Failed to receive stream ack", "err", err)
		os.Exit(1)
	}

	logger.Info("[Step 4 Success] All events acknowledged by Hub", "accepted_count", ack.AcceptedCount)
	logger.Info("All Phase 0 Mock Agent E2E verification steps completed successfully!")
}
