package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/config"
	"alinksec/pkg/crypto/tlsutil"
	"alinksec/pkg/eventbus"
	"alinksec/pkg/hub"
	"alinksec/pkg/logger"
	"alinksec/pkg/storage"

	"google.golang.org/grpc"
)

func main() {
	cfg := config.LoadHubConfig()

	logger.InitGlobalLogger(logger.Config{
		Level:     cfg.LogLevel,
		Format:    "json",
		AddSource: false,
	}, os.Stdout)

	logger.Info("Starting AlinkSec Hub Control Center (南向安全中枢)",
		"grpc_port", cfg.GRPCPort,
		"storage", cfg.Storage,
		"tls_enabled", cfg.TLSEnabled,
	)

	addr := fmt.Sprintf(":%d", cfg.GRPCPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("Failed to listen on gRPC port", "addr", addr, "err", err)
		os.Exit(1)
	}

	var grpcOpts []grpc.ServerOption
	if cfg.TLSEnabled {
		serverCertPEM, err := os.ReadFile(cfg.TLSCert)
		if err != nil {
			logger.Error("Failed to read server cert", "path", cfg.TLSCert, "err", err)
			os.Exit(1)
		}
		serverKeyPEM, err := os.ReadFile(cfg.TLSKey)
		if err != nil {
			logger.Error("Failed to read server key", "path", cfg.TLSKey, "err", err)
			os.Exit(1)
		}
		caCertPEM, err := os.ReadFile(cfg.TLSCA)
		if err != nil {
			logger.Error("Failed to read CA cert", "path", cfg.TLSCA, "err", err)
			os.Exit(1)
		}

		creds, err := tlsutil.LoadServerMTLSCredentials(serverCertPEM, serverKeyPEM, caCertPEM)
		if err != nil {
			logger.Error("Failed to initialize server mTLS credentials", "err", err)
			os.Exit(1)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
		logger.Info("gRPC mTLS enabled with mutual certificate verification (等保 8.1.3.1)")
	}

	grpcServer := grpc.NewServer(grpcOpts...)

	// 初始化生产级存储引擎
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

	// 初始化 ClickHouse 批量写入管道
	chWriter := storage.NewClickHouseWriter(cfg.ClickHouseURL, "alinksec", 200, 1*time.Second)

	// 初始化事件总线
	bus := eventbus.NewMemoryBus() // 默认内存总线，若配置 NATS 则可无缝扩展

	hubService := hub.NewProductionHubServer(store, chWriter, bus)
	pb.RegisterAlinkSecHubServiceServer(grpcServer, hubService)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动心跳超时监控看门狗 (30s 超时, 10s 检查一次)
	hubService.StartHeartbeatMonitor(ctx, 10*time.Second, 30*time.Second)

	// 优雅停机信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info("AlinkSec Hub listening for Southbound Agent connections", "addr", addr)
		if err := grpcServer.Serve(lis); err != nil {
			logger.Error("gRPC server stopped unexpectedly", "err", err)
		}
	}()

	sig := <-sigCh
	logger.Info("Received shutdown signal, gracefully stopping gRPC server...", "signal", sig.String())
	grpcServer.GracefulStop()
	chWriter.Close()
	logger.Info("AlinkSec Hub shutdown completed.")
}
