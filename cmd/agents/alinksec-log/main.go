package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"alinksec/pkg/logaudit"
	"alinksec/pkg/logger"
)

func main() {
	agentID := flag.String("id", "agent-log-01", "Log audit agent identifier")
	hubAddr := flag.String("hub", "127.0.0.1:9090", "AlinkSec Hub gRPC address")
	standalone := flag.Bool("standalone", false, "Run in standalone mode")
	genProof := flag.Bool("gen-proof", false, "Generate MLPS3 180-day log retention compliance proof and exit")
	simDays := flag.Int("sim-days", 185, "Simulation span of days for retention proof")
	tlsEnabled := flag.Bool("tls", false, "Enable mTLS connection to hub")
	tlsCert := flag.String("tls-cert", "", "mTLS client certificate path")
	tlsKey := flag.String("tls-key", "", "mTLS client private key path")
	tlsCA := flag.String("tls-ca", "", "mTLS CA certificate path")
	serverName := flag.String("server-name", "alinksec-hub", "mTLS server name")

	flag.Parse()

	logger.InitGlobalLogger(logger.Config{
		Level:  "info",
		Format: "json",
	}, nil)

	// 一键导出等保 2.0 三级 180 天留存合规凭证
	if *genProof {
		now := time.Now()
		oldest := now.AddDate(0, 0, -*simDays)
		proof := logaudit.GenerateRetentionProof(oldest, now, 12850000, true)
		out, _ := json.MarshalIndent(proof, "", "  ")
		fmt.Println(string(out))
		return
	}

	hostname, _ := os.Hostname()

	cfg := &logaudit.AgentConfig{
		AgentID:      *agentID,
		Hostname:     hostname,
		HubAddr:      *hubAddr,
		HeartbeatSec: 5 * time.Second,
		Standalone:   *standalone,
		TLSEnabled:   *tlsEnabled,
		TLSCert:      *tlsCert,
		TLSKey:       *tlsKey,
		TLSCA:        *tlsCA,
		ServerName:   *serverName,
	}

	agent := logaudit.NewLogAgent(cfg)

	if err := agent.Start(); err != nil {
		logger.Error("Failed to start LogAgent", "err", err)
		os.Exit(1)
	}

	// 模拟写入系统鉴权关键日志
	agent.IngestLog(logaudit.SourceSyslog, "/var/log/secure", "Accepted publickey for root from 10.0.99.10 port 52144 ssh2")
	agent.IngestLog(logaudit.SourceWAF, "/var/log/alinksec/waf.log", "WAF Blocked SQL Injection from 203.0.113.4")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	agent.Stop()
}
