package edr

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/crypto"
	"alinksec/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Config EDR 探针配置
type Config struct {
	AgentID           string        `json:"agent_id"`
	HubAddr           string        `json:"hub_addr"`           // 安全管理中心 gRPC 地址 (留空则单机独立运行)
	HeartbeatInterval time.Duration `json:"heartbeat_interval"` // 心跳间隔 (默认 10s)
	BaselineInterval  time.Duration `json:"baseline_interval"`  // 基线巡检周期 (默认 30m)
}

// Agent 主机安全 EDR 探针实例
type Agent struct {
	cfg          Config
	baseline     *BaselineChecker
	detector     *Detector
	collector    *Collector
	hubClient    pb.AlinkSecHubServiceClient
	grpcConn     *grpc.ClientConn
	sessionToken string
	eventStream  grpc.ClientStreamingClient[pb.RawSecurityEvent, pb.ReportAck]
	policyVer    string

	// 指标
	threatEventsCount uint64
	baselineRunCount  uint64
}

// NewAgent 创建 EDR 探针
func NewAgent(cfg Config) *Agent {
	if cfg.AgentID == "" {
		cfg.AgentID = "edr-" + time.Now().Format("20060102150405")
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 10 * time.Second
	}
	if cfg.BaselineInterval <= 0 {
		cfg.BaselineInterval = 30 * time.Minute
	}

	return &Agent{
		cfg:       cfg,
		baseline:  NewBaselineChecker(),
		detector:  NewDetector(),
		collector: NewCollector(),
		policyVer: "v1.0.0",
	}
}

// Start 启动 EDR 探针主循环
func (a *Agent) Start(ctx context.Context) error {
	logger.Info("AlinkSec Host EDR Agent starting...", "agent_id", a.cfg.AgentID)

	// 若配置了 Hub 地址，建立 gRPC 南向连接
	if a.cfg.HubAddr != "" {
		if err := a.connectHub(ctx); err != nil {
			logger.Warn("Failed to connect to Hub, running in standalone mode", "err", err)
		} else {
			go a.heartbeatLoop(ctx)
		}
	}

	// 启动首次及周期性安全基线合规自检
	go a.baselineLoop(ctx)

	logger.Info("AlinkSec Host EDR Agent is active and protecting host",
		"agent_id", a.cfg.AgentID,
		"hub_connected", a.cfg.HubAddr != "",
	)

	<-ctx.Done()
	return nil
}

// Stop 停止探针
func (a *Agent) Stop() {
	if a.grpcConn != nil {
		_ = a.grpcConn.Close()
	}
	logger.Info("AlinkSec Host EDR Agent stopped safely")
}

// InspectProcess 外部或内核调用注入的进程审查入口
func (a *Agent) InspectProcess(proc ProcessInfo) (DetectionResult, bool) {
	result, matched := a.detector.InspectProcess(proc)
	if matched {
		atomic.AddUint64(&a.threatEventsCount, 1)
		logger.Warn("EDR Detected Host Threat Process",
			"rule_id", result.RuleID,
			"threat_type", result.ThreatType,
			"pid", proc.PID,
			"cmdline", proc.CommandLine,
		)
		a.reportThreat(result)
	}
	return result, matched
}

// RecordLoginFailure 外部身份认证或 PAM 模块上报的失败记录
func (a *Agent) RecordLoginFailure(sourceIdentifier string) (DetectionResult, bool) {
	result, matched := a.detector.RecordLoginFailure(sourceIdentifier)
	if matched {
		atomic.AddUint64(&a.threatEventsCount, 1)
		logger.Warn("EDR Detected Brute Force Attack",
			"rule_id", result.RuleID,
			"source", sourceIdentifier,
		)
		a.reportThreat(result)
	}
	return result, matched
}

// RunBaselineAudit 手动触发一次安全基线核查
func (a *Agent) RunBaselineAudit() []BaselineItem {
	atomic.AddUint64(&a.baselineRunCount, 1)
	return a.baseline.RunAudit()
}

func (a *Agent) baselineLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.BaselineInterval)
	defer ticker.Stop()

	// 启动时立即执行一次合规巡检
	items := a.baseline.RunAudit()
	logger.Info("MLPS3 Host Security Baseline Audit Completed",
		"total_items", len(items),
		"agent_id", a.cfg.AgentID,
	)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			items = a.baseline.RunAudit()
			logger.Info("Periodic Baseline Audit Executed", "items_count", len(items))
		}
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tele := a.collector.GetTelemetry(int32(len(a.detector.rules)))
			resp, err := a.hubClient.SendHeartbeat(ctx, &pb.HeartbeatRequest{
				AgentId:          a.cfg.AgentID,
				SessionToken:     a.sessionToken,
				Timestamp:        time.Now().Unix(),
				CpuUsage:         tele.CPUPercent,
				MemoryUsedBytes:  int64(tele.MemoryPercent * 1024 * 1024 * 1024 / 100),
				DiskUsedBytes:    int64(tele.DiskPercent * 1024 * 1024 * 1024 / 100),
				ActiveRulesCount: int32(len(a.detector.rules)),
			})
			if err != nil {
				logger.Warn("EDR heartbeat failed", "err", err)
			} else if resp != nil && resp.NeedPolicySync {
				logger.Info("Hub announced new policy update, initiating sync...", "latest", resp.LatestPolicyVersion)
				a.syncPolicy(ctx)
			}
		}
	}
}

func (a *Agent) syncPolicy(ctx context.Context) {
	pkg, err := a.hubClient.SyncPolicy(ctx, &pb.PolicySyncRequest{
		AgentId:              a.cfg.AgentID,
		SessionToken:         a.sessionToken,
		CurrentPolicyVersion: a.policyVer,
	})
	if err != nil {
		logger.Warn("Failed to sync policy", "err", err)
		return
	}
	a.policyVer = pkg.PolicyVersion
	logger.Info("EDR policy synchronized successfully", "version", pkg.PolicyVersion)
}

func (a *Agent) reportThreat(result DetectionResult) {
	if a.eventStream == nil {
		return
	}

	eventID, _ := crypto.GenerateSecureToken(16)
	hostname, ip, _, _ := a.collector.GetHostInfo()

	evt := &pb.RawSecurityEvent{
		EventId:         eventID,
		SourceAgentType: pb.AgentType_AGENT_EDR,
		AgentId:         a.cfg.AgentID,
		HostIp:          ip,
		Hostname:        hostname,
		EventTime:       time.Now().Unix(),
		Level:           result.Level,
		Category:        string(result.ThreatType),
		RuleId:          result.RuleID,
		Message:         fmt.Sprintf("[%s] %s: %s", result.ThreatType, result.Title, result.Description),
		RawPayload:      []byte(result.Payload),
		Signature:       crypto.SHA256String(fmt.Sprintf("%s|%s|%s", eventID, result.RuleID, result.Payload)),
	}

	_ = a.eventStream.Send(evt)
}

func (a *Agent) connectHub(ctx context.Context) error {
	conn, err := grpc.DialContext(ctx, a.cfg.HubAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	a.grpcConn = conn
	a.hubClient = pb.NewAlinkSecHubServiceClient(conn)

	hostname, ip, osName, arch := a.collector.GetHostInfo()

	regResp, err := a.hubClient.RegisterAgent(ctx, &pb.RegisterRequest{
		AgentId:   a.cfg.AgentID,
		AgentType: pb.AgentType_AGENT_EDR,
		Version:   "v1.0.0",
		Hostname:  hostname,
		Ip:        ip,
		Os:        osName,
		Arch:      arch,
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("register to hub failed: %w", err)
	}

	a.sessionToken = regResp.SessionToken

	stream, err := a.hubClient.ReportEvents(ctx)
	if err != nil {
		return fmt.Errorf("open report stream failed: %w", err)
	}
	a.eventStream = stream

	return nil
}
