package waf

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/crypto"
	"alinksec/pkg/crypto/tlsutil"
	"alinksec/pkg/logger"
	"google.golang.org/grpc"
)

// WAFMetrics 运行度量指标
type WAFMetrics struct {
	TotalRequests   uint64
	BlockedRequests uint64
	SQLiCount       uint64
	XSSCount        uint64
	RCECount        uint64
	LFICount        uint64
	ScannerCount    uint64
	CCCount         uint64
}

// Config WAF 配置
type Config struct {
	ListenAddr  string `json:"listen_addr"`  // WAF 侦听端口 (如 :8000)
	UpstreamURL string `json:"upstream_url"` // 后端被保护应用 (如 http://127.0.0.1:8080)
	AgentID     string `json:"agent_id"`     // WAF 探针唯一标识
	HubAddr     string `json:"hub_addr"`     // 安全中枢 gRPC 地址 (可选，留空则完全离线独立运行)
	MaxCCLimit  int    `json:"max_cc_limit"` // CC 频控上限 (10秒内次数)
	TLSEnabled  bool   `json:"tls_enabled"`
	TLSCert     string `json:"tls_cert"`
	TLSKey      string `json:"tls_key"`
	TLSCA       string `json:"tls_ca"`
	ServerName  string `json:"server_name"`
}

// Agent WAF 实例
type Agent struct {
	cfg          Config
	engine       *Engine
	metrics      WAFMetrics
	hubClient    pb.AlinkSecHubServiceClient
	grpcConn     *grpc.ClientConn
	sessionToken string
	eventStream  grpc.ClientStreamingClient[pb.RawSecurityEvent, pb.ReportAck]
	server       *http.Server
}

// NewAgent 创建 WAF 探针
func NewAgent(cfg Config) (*Agent, error) {
	if cfg.AgentID == "" {
		cfg.AgentID = "waf-" + time.Now().Format("20060102150405")
	}

	engine := NewEngine()
	if cfg.MaxCCLimit > 0 {
		engine.rateLimiter = NewRateLimiter(cfg.MaxCCLimit, 10*time.Second)
	}

	a := &Agent{
		cfg:    cfg,
		engine: engine,
	}

	return a, nil
}

// Start 启动 WAF 代理与安全侦听服务
func (a *Agent) Start(ctx context.Context) error {
	upstream, err := url.Parse(a.cfg.UpstreamURL)
	if err != nil {
		return fmt.Errorf("invalid upstream URL %s: %w", a.cfg.UpstreamURL, err)
	}

	// 连接 Hub (若配置)
	if a.cfg.HubAddr != "" {
		if err := a.connectHub(ctx); err != nil {
			logger.Warn("Hub connection failed, running WAF in standalone mode", "err", err)
		}
	}

	proxyHandler := NewProxyHandler(a.engine, upstream, a.handleThreatEvent)

	// 注入请求计数包装器
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddUint64(&a.metrics.TotalRequests, 1)
		proxyHandler.ServeHTTP(w, r)
	})

	a.server = &http.Server{
		Addr:         a.cfg.ListenAddr,
		Handler:      wrappedHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	logger.Info("AlinkSec Modular Cloud WAF started successfully",
		"listen", a.cfg.ListenAddr,
		"upstream", a.cfg.UpstreamURL,
		"agent_id", a.cfg.AgentID,
		"hub_connected", a.cfg.HubAddr != "",
	)

	return a.server.ListenAndServe()
}

// Shutdown 优雅关闭
func (a *Agent) Shutdown(ctx context.Context) error {
	if a.grpcConn != nil {
		_ = a.grpcConn.Close()
	}
	if a.server != nil {
		return a.server.Shutdown(ctx)
	}
	return nil
}

// GetMetrics 获取统计数据
func (a *Agent) GetMetrics() WAFMetrics {
	return WAFMetrics{
		TotalRequests:   atomic.LoadUint64(&a.metrics.TotalRequests),
		BlockedRequests: atomic.LoadUint64(&a.metrics.BlockedRequests),
		SQLiCount:       atomic.LoadUint64(&a.metrics.SQLiCount),
		XSSCount:        atomic.LoadUint64(&a.metrics.XSSCount),
		RCECount:        atomic.LoadUint64(&a.metrics.RCECount),
		LFICount:        atomic.LoadUint64(&a.metrics.LFICount),
		ScannerCount:    atomic.LoadUint64(&a.metrics.ScannerCount),
		CCCount:         atomic.LoadUint64(&a.metrics.CCCount),
	}
}

// handleThreatEvent 内部威胁阻断触发与指标更新
func (a *Agent) handleThreatEvent(clientIP, method, uri string, result MatchResult) {
	atomic.AddUint64(&a.metrics.BlockedRequests, 1)

	switch result.ThreatType {
	case ThreatSQLi:
		atomic.AddUint64(&a.metrics.SQLiCount, 1)
	case ThreatXSS:
		atomic.AddUint64(&a.metrics.XSSCount, 1)
	case ThreatRCE:
		atomic.AddUint64(&a.metrics.RCECount, 1)
	case ThreatPathTraversal:
		atomic.AddUint64(&a.metrics.LFICount, 1)
	case ThreatScanner:
		atomic.AddUint64(&a.metrics.ScannerCount, 1)
	case ThreatRateLimit:
		atomic.AddUint64(&a.metrics.CCCount, 1)
	}

	// 若连接了 Hub，异步流式上报安全事件
	if a.eventStream != nil {
		eventID, _ := crypto.GenerateSecureToken(16)
		evt := &pb.RawSecurityEvent{
			EventId:         eventID,
			SourceAgentType: pb.AgentType_AGENT_WAF,
			AgentId:         a.cfg.AgentID,
			HostIp:          clientIP,
			Hostname:        "waf-gateway",
			EventTime:       time.Now().Unix(),
			Level:           result.Severity,
			Category:        string(result.ThreatType),
			RuleId:          result.RuleID,
			Message:         fmt.Sprintf("WAF Blocked [%s] on %s %s: %s", result.ThreatType, method, uri, result.Description),
			RawPayload:      []byte(result.Sample),
			Signature:       crypto.SHA256String(fmt.Sprintf("%s|%s|%s", eventID, result.RuleID, result.Sample)),
		}

		_ = a.eventStream.Send(evt)
	}
}

func (a *Agent) connectHub(ctx context.Context) error {
	conn, err := tlsutil.DialHub(ctx, a.cfg.HubAddr, a.cfg.TLSEnabled, a.cfg.TLSCert, a.cfg.TLSKey, a.cfg.TLSCA, a.cfg.ServerName)
	if err != nil {
		return err
	}
	a.grpcConn = conn
	a.hubClient = pb.NewAlinkSecHubServiceClient(conn)

	// 注册探针
	regResp, err := a.hubClient.RegisterAgent(ctx, &pb.RegisterRequest{
		AgentId:   a.cfg.AgentID,
		AgentType: pb.AgentType_AGENT_WAF,
		Version:   "v1.0.0",
		Hostname:  "waf-gateway",
		Ip:        "127.0.0.1",
		Os:        "linux/windows",
		Arch:      "amd64",
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("register to hub failed: %w", err)
	}

	a.sessionToken = regResp.SessionToken

	// 打开事件上报流
	stream, err := a.hubClient.ReportEvents(ctx)
	if err != nil {
		return fmt.Errorf("open report stream failed: %w", err)
	}
	a.eventStream = stream

	return nil
}
