package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"alinksec/pkg/logger"
	"alinksec/pkg/tamper"
)

func main() {
	var (
		agentID    = flag.String("agent-id", "tamper-node-01", "Tamper Agent unique ID")
		watchDir   = flag.String("watch-dir", "./wwwroot", "Web publish directory to protect")
		backupDir  = flag.String("backup-dir", "", "Isolated safe vault directory (default: <watch-dir>_vault)")
		hubAddr    = flag.String("hub", "", "AlinkSec Hub gRPC address (e.g. 127.0.0.1:50051, optional)")
		autoRevert = flag.Bool("auto-revert", true, "Enable millisecond auto-reversion of tampered files")
	)
	flag.Parse()

	logger.InitGlobalLogger(logger.Config{
		Level:  "info",
		Format: "json",
	}, os.Stdout)

	// 若测试目标目录不存在，创建一个示例目录
	if _, err := os.Stat(*watchDir); os.IsNotExist(err) {
		_ = os.MkdirAll(*watchDir, 0755)
		_ = os.WriteFile(*watchDir+"/index.html", []byte("<html><body><h1>Protected Enterprise Web Application</h1></body></html>"), 0644)
	}

	cfg := tamper.Config{
		AgentID:    *agentID,
		WatchDir:   *watchDir,
		BackupDir:  *backupDir,
		HubAddr:    *hubAddr,
		AutoRevert: *autoRevert,
	}

	agent, err := tamper.NewAgent(cfg)
	if err != nil {
		logger.Error("Failed to initialize Tamper Agent", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := agent.Start(ctx); err != nil {
			logger.Error("Tamper agent failed", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Stopping AlinkSec Web Tamper-Proof Agent...")
	agent.Stop()
	logger.Info("Tamper Agent terminated safely")
}
