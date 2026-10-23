package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"alinksec/pkg/logger"
	"alinksec/pkg/manager"
)

func main() {
	var (
		port      = flag.Int("port", 8080, "Manager HTTP API port")
		jwtSecret = flag.String("jwt-secret", "alinksec-production-secret-key-32b!", "JWT HMAC-SHA256 signing secret")
	)
	flag.Parse()

	logger.InitGlobalLogger(logger.Config{
		Level:  "info",
		Format: "json",
	}, os.Stdout)

	server := manager.NewHTTPServer([]byte(*jwtSecret))
	addr := fmt.Sprintf(":%d", *port)

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      server.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("Starting AlinkSec Security Management Center (Northbound REST API)...",
			"addr", addr,
			"compliance", "GB/T 22239-2019 MLPS3",
			"auth_mode", "Three-Role Separation + TOTP 2FA",
		)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Manager HTTP server terminated unexpectedly", "err", err)
			os.Exit(1)
		}
	}()

	// 优雅关机监听
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down AlinkSec Security Management Center...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("Manager HTTP server forced to shutdown", "err", err)
	}

	logger.Info("Manager HTTP server exited safely")
}
