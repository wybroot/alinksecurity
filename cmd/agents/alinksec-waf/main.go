package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"alinksec/pkg/logger"
	"alinksec/pkg/waf"
)

func main() {
	var (
		listenAddr  = flag.String("listen", ":8000", "WAF listening address")
		upstreamURL = flag.String("upstream", "http://127.0.0.1:8080", "Protected backend upstream URL")
		agentID     = flag.String("agent-id", "waf-node-01", "WAF Agent unique ID")
		hubAddr     = flag.String("hub", "", "AlinkSec Hub gRPC address (e.g. 127.0.0.1:50051, optional)")
		ccLimit     = flag.Int("cc-limit", 100, "Max requests per IP within 10s window (anti-CC)")
		tlsEnabled  = flag.Bool("tls", false, "Enable mTLS connection to hub")
		tlsCert     = flag.String("tls-cert", "", "mTLS client certificate path")
		tlsKey      = flag.String("tls-key", "", "mTLS client private key path")
		tlsCA       = flag.String("tls-ca", "", "mTLS CA certificate path")
		serverName  = flag.String("server-name", "alinksec-hub", "mTLS server name")
	)
	flag.Parse()

	logger.InitGlobalLogger(logger.Config{
		Level:  "info",
		Format: "json",
	}, os.Stdout)

	cfg := waf.Config{
		ListenAddr:  *listenAddr,
		UpstreamURL: *upstreamURL,
		AgentID:     *agentID,
		HubAddr:     *hubAddr,
		MaxCCLimit:  *ccLimit,
		TLSEnabled:  *tlsEnabled,
		TLSCert:     *tlsCert,
		TLSKey:      *tlsKey,
		TLSCA:       *tlsCA,
		ServerName:  *serverName,
	}

	agent, err := waf.NewAgent(cfg)
	if err != nil {
		logger.Error("Failed to initialize WAF agent", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := agent.Start(ctx); err != nil && err != http.ErrServerClosed {
			logger.Error("WAF server failed", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down AlinkSec Cloud WAF gracefully...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := agent.Shutdown(shutdownCtx); err != nil {
		logger.Error("WAF agent shutdown error", "err", err)
	}

	logger.Info("WAF agent terminated safely")
}
