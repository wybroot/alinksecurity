package cfw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// AgentConfig 微隔离防火墙探针配置
type AgentConfig struct {
	AgentID      string        `json:"agent_id"`
	Hostname     string        `json:"hostname"`
	HubAddr      string        `json:"hub_addr"`
	HeartbeatSec time.Duration `json:"heartbeat_sec"`
	Standalone   bool          `json:"standalone"`
}

// CFWAgent 微隔离与云防火墙探针
type CFWAgent struct {
	cfg          *AgentConfig
	engine       *Engine
	ctx          context.Context
	cancel       context.CancelFunc
	token        string
	policyVer    string
	wg           sync.WaitGroup

	// 指标
	evaluatedPackets uint64
	droppedPackets   uint64

	// gRPC 客户端连接
	grpcConn      *grpc.ClientConn
	hubClient     pb.AlinkSecHubServiceClient
	eventStream   pb.AlinkSecHubService_ReportEventsClient
	eventStreamMu sync.Mutex

	onEvent func(evt *FirewallEvent)
}

// NewCFWAgent 构造微隔离防火墙探针
func NewCFWAgent(cfg *AgentConfig) *CFWAgent {
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &CFWAgent{
		cfg:    cfg,
		engine: NewEngine(),
		ctx:    ctx,
		cancel: cancel,
	}
}

// SetEventCallback 设置事件回调 (单测与订阅)
func (a *CFWAgent) SetEventCallback(fn func(evt *FirewallEvent)) {
	a.onEvent = fn
}

// GetEngine 获取底层引擎
func (a *CFWAgent) GetEngine() *Engine {
	return a.engine
}

// Start 启动微隔离探针
func (a *CFWAgent) Start() error {
	logger.Info("Starting alinksec-cfw agent (Microsegmentation)",
		"agent_id", a.cfg.AgentID,
		"standalone", a.cfg.Standalone,
		"hub_addr", a.cfg.HubAddr,
	)

	if !a.cfg.Standalone && a.cfg.HubAddr != "" {
		if err := a.connectAndRegisterHub(); err != nil {
			logger.Error("Failed to register CFW with hub, running in fallback offline mode", "err", err)
		} else {
			go a.heartbeatLoop()
		}
	}

	return nil
}

// Stop 停止微隔离探针
func (a *CFWAgent) Stop() {
	logger.Info("Stopping alinksec-cfw agent...")
	a.cancel()

	a.eventStreamMu.Lock()
	if a.eventStream != nil {
		_, _ = a.eventStream.CloseAndRecv()
	}
	a.eventStreamMu.Unlock()

	if a.grpcConn != nil {
		_ = a.grpcConn.Close()
	}

	a.wg.Wait()
	logger.Info("alinksec-cfw agent stopped successfully")
}

// InspectPacket 评估网络流量并记录/上报
func (a *CFWAgent) InspectPacket(ctx PacketContext) *FirewallEvent {
	atomic.AddUint64(&a.evaluatedPackets, 1)
	evt := a.engine.EvaluatePacket(ctx)

	if evt.Action == ActionDrop {
		atomic.AddUint64(&a.droppedPackets, 1)
		logger.Warn("CFW Microsegmentation Dropped Packet",
			"src", ctx.SrcIP,
			"src_zone", ctx.SrcZone,
			"dst", ctx.DstIP,
			"dst_zone", ctx.DstZone,
			"proto", ctx.Protocol,
			"port", ctx.DstPort,
			"violation", evt.ViolationType,
			"reason", evt.Reason,
		)
		go a.reportFirewallEvent(evt)
	}

	if a.onEvent != nil {
		a.onEvent(evt)
	}

	return evt
}

// GetMetrics 获取流量拦截指标
func (a *CFWAgent) GetMetrics() (evaluated, dropped uint64) {
	return atomic.LoadUint64(&a.evaluatedPackets), atomic.LoadUint64(&a.droppedPackets)
}

func (a *CFWAgent) connectAndRegisterHub() error {
	conn, err := grpc.DialContext(a.ctx, a.cfg.HubAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	a.grpcConn = conn
	a.hubClient = pb.NewAlinkSecHubServiceClient(conn)

	regReq := &pb.RegisterRequest{
		AgentId:   a.cfg.AgentID,
		AgentType: pb.AgentType_AGENT_FIREWALL,
		Hostname:  a.cfg.Hostname,
		Version:   "v1.0.0",
		Timestamp: time.Now().Unix(),
	}

	resp, err := a.hubClient.RegisterAgent(a.ctx, regReq)
	if err != nil {
		return err
	}
	a.token = resp.SessionToken
	logger.Info("Successfully registered CFW with hub", "token_prefix", a.token[:8])
	return nil
}

func (a *CFWAgent) heartbeatLoop() {
	ticker := time.NewTicker(a.cfg.HeartbeatSec)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			evaluated, dropped := a.GetMetrics()
			hb := &pb.HeartbeatRequest{
				AgentId:          a.cfg.AgentID,
				SessionToken:     a.token,
				Timestamp:        time.Now().Unix(),
				CpuUsage:         0.5,
				MemoryUsedBytes:  14 * 1024 * 1024,
				DiskUsedBytes:    30 * 1024 * 1024,
				ActiveRulesCount: int32(len(a.engine.rules)),
			}
			resp, err := a.hubClient.SendHeartbeat(a.ctx, hb)
			if err != nil {
				logger.Error("CFW Heartbeat failed", "err", err)
			} else {
				logger.Debug("CFW Heartbeat ACK", "server_time", resp.ServerTime, "evaluated", evaluated, "dropped", dropped)
			}
		}
	}
}

func (a *CFWAgent) reportFirewallEvent(evt *FirewallEvent) {
	if a.hubClient == nil || a.cfg.Standalone {
		return
	}

	payloadMap := map[string]interface{}{
		"event_id":       evt.EventID,
		"src_ip":         evt.Context.SrcIP,
		"src_zone":       evt.Context.SrcZone,
		"dst_ip":         evt.Context.DstIP,
		"dst_zone":       evt.Context.DstZone,
		"protocol":       evt.Context.Protocol,
		"dst_port":       evt.Context.DstPort,
		"action":         evt.Action,
		"violation_type": evt.ViolationType,
		"rule_id":        evt.MatchedRuleID,
		"reason":         evt.Reason,
	}
	payloadJSON, _ := json.Marshal(payloadMap)
	hash := sha256.Sum256(payloadJSON)

	secEvt := &pb.RawSecurityEvent{
		EventId:         evt.EventID,
		SourceAgentType: pb.AgentType_AGENT_FIREWALL,
		AgentId:         a.cfg.AgentID,
		HostIp:          evt.Context.SrcIP,
		Hostname:        a.cfg.Hostname,
		EventTime:       evt.Timestamp.Unix(),
		Level:           pb.EventLevel_LEVEL_HIGH,
		Category:        "NETWORK_MICROSEGMENTATION",
		RuleId:          evt.MatchedRuleID,
		Message:         fmt.Sprintf("Microsegmentation Drop: %s", evt.Reason),
		RawPayload:      payloadJSON,
		Signature:        hex.EncodeToString(hash[:]),
	}

	a.eventStreamMu.Lock()
	defer a.eventStreamMu.Unlock()

	var err error
	if a.eventStream == nil {
		a.eventStream, err = a.hubClient.ReportEvents(a.ctx)
		if err != nil {
			logger.Error("Failed to open report stream from CFW", "err", err)
			return
		}
	}

	if sendErr := a.eventStream.Send(secEvt); sendErr != nil {
		logger.Error("Failed to send firewall event", "err", sendErr)
		a.eventStream = nil
	} else {
		logger.Info("Reported CFW violation event to hub", "event_id", evt.EventID, "rule_id", evt.MatchedRuleID)
	}
}
