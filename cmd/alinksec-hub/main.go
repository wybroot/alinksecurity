package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/config"
	"alinksec/pkg/hub"
	"alinksec/pkg/logger"

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
	)

	addr := fmt.Sprintf(":%d", cfg.GRPCPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("Failed to listen on gRPC port", "addr", addr, "err", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()
	hubService := hub.NewHubServer()
	pb.RegisterAlinkSecHubServiceServer(grpcServer, hubService)

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
	logger.Info("AlinkSec Hub shutdown completed.")
}
