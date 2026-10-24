package config

import (
	"os"
	"strconv"
)

// HubConfig Hub 服务配置
type HubConfig struct {
	GRPCPort      int    `json:"grpc_port"`
	LogLevel      string `json:"log_level"`
	Storage       string `json:"storage"` // "memory", "postgres"
	PostgresDSN   string `json:"postgres_dsn"`
	ClickHouseURL string `json:"clickhouse_url"`
	NATSURL       string `json:"nats_url"`
	TLSEnabled    bool   `json:"tls_enabled"`
	TLSCert       string `json:"tls_cert"`
	TLSKey        string `json:"tls_key"`
	TLSCA         string `json:"tls_ca"`
}

// LoadHubConfig 从环境变量加载配置，提供安全默认值
func LoadHubConfig() *HubConfig {
	cfg := &HubConfig{
		GRPCPort:      50051,
		LogLevel:      "info",
		Storage:       "memory",
		PostgresDSN:   "postgres://alinksec:AlinkSec@2026!@localhost:5432/alinksec_db?sslmode=disable",
		ClickHouseURL: "http://localhost:8123",
		NATSURL:       "nats://localhost:4222",
		TLSEnabled:    false,
		TLSCert:       "deploy/certs/hub.crt",
		TLSKey:        "deploy/certs/hub.key",
		TLSCA:         "deploy/certs/ca.crt",
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

	if dsn := os.Getenv("ALINKSEC_PG_DSN"); dsn != "" {
		cfg.PostgresDSN = dsn
		cfg.Storage = "postgres"
	}

	if ch := os.Getenv("ALINKSEC_CLICKHOUSE_URL"); ch != "" {
		cfg.ClickHouseURL = ch
	}

	if nats := os.Getenv("ALINKSEC_NATS_URL"); nats != "" {
		cfg.NATSURL = nats
	}

	if tlsEn := os.Getenv("ALINKSEC_TLS_ENABLED"); tlsEn == "true" || tlsEn == "1" {
		cfg.TLSEnabled = true
	}
	if cert := os.Getenv("ALINKSEC_TLS_CERT"); cert != "" {
		cfg.TLSCert = cert
	}
	if key := os.Getenv("ALINKSEC_TLS_KEY"); key != "" {
		cfg.TLSKey = key
	}
	if ca := os.Getenv("ALINKSEC_TLS_CA"); ca != "" {
		cfg.TLSCA = ca
	}

	return cfg
}

// ManagerConfig 管理控制台配置
type ManagerConfig struct {
	HTTPPort      int    `json:"http_port"`
	LogLevel      string `json:"log_level"`
	Storage       string `json:"storage"`
	PostgresDSN   string `json:"postgres_dsn"`
	ClickHouseURL string `json:"clickhouse_url"`
	NATSURL       string `json:"nats_url"`
	JWTSecret     string `json:"jwt_secret"`
	StaticDir     string `json:"static_dir"`
}

// LoadManagerConfig 从环境变量加载配置
func LoadManagerConfig() *ManagerConfig {
	cfg := &ManagerConfig{
		HTTPPort:      8080,
		LogLevel:      "info",
		Storage:       "memory",
		PostgresDSN:   "postgres://alinksec:AlinkSec@2026!@localhost:5432/alinksec_db?sslmode=disable",
		ClickHouseURL: "http://localhost:8123",
		NATSURL:       "nats://localhost:4222",
		JWTSecret:     "alinksec-mlps3-super-secret-key-2026-production",
		StaticDir:     "web",
	}

	if portStr := os.Getenv("ALINKSEC_MANAGER_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			cfg.HTTPPort = p
		}
	}

	if lvl := os.Getenv("ALINKSEC_LOG_LEVEL"); lvl != "" {
		cfg.LogLevel = lvl
	}

	if st := os.Getenv("ALINKSEC_STORAGE"); st != "" {
		cfg.Storage = st
	}

	if dsn := os.Getenv("ALINKSEC_PG_DSN"); dsn != "" {
		cfg.PostgresDSN = dsn
		cfg.Storage = "postgres"
	}

	if ch := os.Getenv("ALINKSEC_CLICKHOUSE_URL"); ch != "" {
		cfg.ClickHouseURL = ch
	}

	if nats := os.Getenv("ALINKSEC_NATS_URL"); nats != "" {
		cfg.NATSURL = nats
	}

	if jwt := os.Getenv("ALINKSEC_JWT_SECRET"); jwt != "" {
		cfg.JWTSecret = jwt
	}

	if dir := os.Getenv("ALINKSEC_STATIC_DIR"); dir != "" {
		cfg.StaticDir = dir
	}

	return cfg
}
