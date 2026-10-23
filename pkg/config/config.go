package config

import (
	"os"
	"strconv"
)

// HubConfig Hub 服务配置
type HubConfig struct {
	GRPCPort int    `json:"grpc_port"`
	LogLevel string `json:"log_level"`
	Storage  string `json:"storage"` // "memory", "postgres"
}

// LoadHubConfig 从环境变量加载配置，提供安全默认值
func LoadHubConfig() *HubConfig {
	cfg := &HubConfig{
		GRPCPort: 50051,
		LogLevel: "info",
		Storage:  "memory",
	}

	if portStr := os.Getenv("ALINKSEC_HUB_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			cfg.GRPCPort = p
		}
	}

	if lvl := os.Getenv("ALINKSEC_LOG_LEVEL"); lvl != "" {
		cfg.LogLevel = lvl
	}

	if st := os.Getenv("ALINKSEC_STORAGE"); st != "" {
		cfg.Storage = st
	}

	return cfg
}
