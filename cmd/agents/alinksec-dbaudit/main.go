package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"alinksec/pkg/dbaudit"
	"alinksec/pkg/logger"
)

func main() {
	agentID := flag.String("id", "agent-dbaudit-01", "Database audit agent identifier")
	proto := flag.String("proto", "MySQL", "Database protocol: MySQL or PostgreSQL")
	listenAddr := flag.String("listen", "127.0.0.1:13306", "Proxy listen address")
	targetAddr := flag.String("target", "127.0.0.1:3306", "Target database server address")
	hubAddr := flag.String("hub", "127.0.0.1:9090", "AlinkSec Hub gRPC address")
	standalone := flag.Bool("standalone", false, "Run in standalone mode without hub")
	testSQL := flag.String("test-sql", "", "Evaluate a specific SQL statement and output audit result in JSON, then exit")
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
	hostname, _ := os.Hostname()

	// 若提供 -test-sql，以离线分析模式输出诊断
	if *testSQL != "" {
		analyzer := dbaudit.NewSQLAnalyzer()
		rec := analyzer.Analyze("192.168.1.100:54321", *targetAddr, "app_user", "prod_db", *testSQL, dbaudit.DBProtocol(*proto), 2)
		out, _ := json.MarshalIndent(rec, "", "  ")
		fmt.Println(string(out))
		return
	}

	cfg := &dbaudit.AgentConfig{
		AgentID:      *agentID,
		Hostname:     hostname,
		HubAddr:      *hubAddr,
		ListenAddr:   *listenAddr,
		TargetDBAddr: *targetAddr,
		Protocol:     dbaudit.DBProtocol(*proto),
		HeartbeatSec: 5 * time.Second,
		Standalone:   *standalone,
		TLSEnabled:   *tlsEnabled,
		TLSCert:      *tlsCert,
		TLSKey:       *tlsKey,
		TLSCA:        *tlsCA,
		ServerName:   *serverName,
	}

	agent := dbaudit.NewDBAuditAgent(cfg)

	agent.SetAuditCallback(func(r *dbaudit.AuditRecord) {
		if r.IsThreat {
			logger.Warn("🚨 [HIGH RISK AUDIT ALERT]",
				"rule_id", r.RuleID,
				"risk_level", r.RiskLevel,
				"threat_type", r.ThreatType,
				"user", r.DBUser,
				"sql", r.SQL,
			)
		} else {
			logger.Info("Audit Log Recorded",
				"op", r.Operation,
				"risk", r.RiskLevel,
				"user", r.DBUser,
				"sql", r.SQL,
			)
		}
	})

	if err := agent.Start(); err != nil {
		logger.Error("Failed to start DBAudit agent", "err", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	agent.Stop()
}
