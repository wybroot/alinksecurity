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

	"alinksec/pkg/config"
	"alinksec/pkg/logger"
	"alinksec/pkg/manager"
	"alinksec/pkg/storage"
)

func main() {
	var (
		port      = flag.Int("port", 8080, "Manager HTTP API port")
		addrFlag  = flag.String("addr", "", "Manager HTTP listen address (e.g. :8080 or 127.0.0.1:8080)")
		jwtSecret = flag.String("jwt-secret", "alinksec-production-secret-key-32b!", "JWT HMAC-SHA256 signing secret")
	)
	flag.Parse()

	logger.InitGlobalLogger(logger.Config{
		Level:  "info",
		Format: "json",
	}, os.Stdout)

	secret := []byte(*jwtSecret)
	addr := fmt.Sprintf(":%d", *port)
	if *addrFlag != "" {
		addr = *addrFlag
	}

	cfg := config.LoadManagerConfig()
	if *addrFlag == "" && cfg.HTTPPort > 0 {
		addr = fmt.Sprintf(":%d", cfg.HTTPPort)
	}
	if cfg.JWTSecret != "" && *jwtSecret == "alinksec-production-secret-key-32b!" {
		secret = []byte(cfg.JWTSecret)
	}

	// 初始化生产级存储引擎 (PostgreSQL 或高可用内存降级)
	var store storage.StorageEngine
	if cfg.Storage == "postgres" && cfg.PostgresDSN != "" {
		pgStore, err := storage.NewPostgresStorage(cfg.PostgresDSN)
		if err != nil {
			logger.Warn("Failed to connect to PostgreSQL, falling back to in-memory store", "err", err)
			store = storage.NewMemoryStorage()
		} else {
			logger.Info("Connected to PostgreSQL storage engine successfully")
			store = pgStore
		}
	} else {
		logger.Info("Using high-performance in-memory storage engine")
		store = storage.NewMemoryStorage()
	}

	// 初始化 ClickHouse 管道
	chWriter := storage.NewClickHouseWriter(cfg.ClickHouseURL, "alinksec", 200, 1*time.Second)

	server := manager.NewProductionHTTPServer(secret, store, chWriter)

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
