package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"alinksec/pkg/edr"
	"alinksec/pkg/logger"
)

func main() {
	var (
		agentID           = flag.String("agent-id", "edr-host-01", "EDR Agent unique ID")
		hubAddr           = flag.String("hub", "", "AlinkSec Hub gRPC address (e.g. 127.0.0.1:50051, optional)")
		heartbeatInterval = flag.Duration("heartbeat-interval", 10*time.Second, "Heartbeat interval")
		baselineInterval  = flag.Duration("baseline-interval", 30*time.Minute, "Baseline audit interval")
		auditOnly         = flag.Bool("audit-only", false, "Run single baseline audit and print report, then exit")
		tlsEnabled        = flag.Bool("tls", false, "Enable mTLS connection to hub")
		tlsCert           = flag.String("tls-cert", "", "mTLS client certificate path")
		tlsKey            = flag.String("tls-key", "", "mTLS client private key path")
		tlsCA             = flag.String("tls-ca", "", "mTLS CA certificate path")
		serverName        = flag.String("server-name", "alinksec-hub", "mTLS server name")
	)
	flag.Parse()

	logger.InitGlobalLogger(logger.Config{
		Level:  "info",
		Format: "json",
	}, os.Stdout)

	cfg := edr.Config{
		AgentID:           *agentID,
		HubAddr:           *hubAddr,
		HeartbeatInterval: *heartbeatInterval,
		BaselineInterval:  *baselineInterval,
		TLSEnabled:        *tlsEnabled,
		TLSCert:           *tlsCert,
		TLSKey:            *tlsKey,
		TLSCA:             *tlsCA,
		ServerName:        *serverName,
	}

	agent := edr.NewAgent(cfg)

	// 若处于仅基线评估模式
	if *auditOnly {
		fmt.Println("================================================================================")
		fmt.Println("             GB/T 22239-2019 等保 2.0 三级 - 主机安全计算环境基线核查报告         ")
		fmt.Println("================================================================================")
		items := agent.RunBaselineAudit()
		out, _ := json.MarshalIndent(items, "", "  ")
		fmt.Println(string(out))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := agent.Start(ctx); err != nil {
			logger.Error("EDR agent encountered fatal error", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Stopping AlinkSec Host EDR Agent...")
	agent.Stop()
	logger.Info("EDR Agent terminated safely")
}
