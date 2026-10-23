package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"alinksec/pkg/bastion"
	"alinksec/pkg/logger"
)

func main() {
	agentID := flag.String("id", "agent-bastion-01", "Bastion 4A privileged audit agent identifier")
	hubAddr := flag.String("hub", "127.0.0.1:50051", "AlinkSec Hub gRPC address")
	standalone := flag.Bool("standalone", false, "Run in standalone mode without connecting to Hub")
	evalCmd := flag.String("eval-cmd", "", "Evaluate a command against 4A rules and exit")
	evalSession := flag.Bool("eval-session", false, "Run full mock session and export tamper-proof certificate")

	flag.Parse()

	logger.InitGlobalLogger(logger.Config{
		Level:  "info",
		Format: "json",
	}, nil)

	hostname, _ := os.Hostname()

	hubTarget := *hubAddr
	if *standalone {
		hubTarget = ""
	}

	cfg := &bastion.AgentConfig{
		AgentID:       *agentID,
		HubAddress:    hubTarget,
		ListenAddress: "0.0.0.0:2222",
		Hostname:      hostname,
		LocalIP:       "127.0.0.1",
	}

	agent := bastion.NewBastionAgent(cfg)

	// 单条指令快速评估模式
	if *evalCmd != "" {
		res := agent.GetEngine().CheckCommand(*evalCmd)
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		if !res.Allowed {
			os.Exit(1)
		}
		return
	}

	// 模拟完整会话并导出存证证书
	if *evalSession {
		session := bastion.NewSession("SESS-MOCK-EVAL", "sec_ops", "10.0.1.50", "10.0.3.10", "root", "SSH")
		mockCmds := []string{
			"pwd",
			"ls -la /var/log",
			"systemctl status alinksec-hub",
			"cat /etc/shadow", // Blocked
			"chmod -R 777 /",  // Blocked
			"date",
		}

		for _, cmd := range mockCmds {
			res, rec := agent.ExecuteAndAudit(session, cmd)
			status := "ALLOWED"
			if !res.Allowed {
				status = "BLOCKED"
			}
			fmt.Printf("[%s] %-30s -> Hash: %s\n", status, cmd, rec.CurrentHash[:16]+"...")
		}

		session.Close("NORMAL_DISCONNECT")
		cert := session.GenerateCertificate()
		certJSON, _ := json.MarshalIndent(cert, "", "  ")
		fmt.Println("\n--- 等保 2.0 (三级) 运维会话防篡改存证凭证 ---")
		fmt.Println(string(certJSON))
		return
	}

	// 正常运行模式
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		logger.Error("Failed to start bastion agent", "error", err)
		os.Exit(1)
	}

	logger.Info("AlinkSec Bastion 4A agent is running", "id", *agentID)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down Bastion agent...")
	agent.Stop()
}
