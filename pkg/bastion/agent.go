package bastion

import (
	"context"
	"fmt"
	"sync"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/crypto"
	"alinksec/pkg/logger"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// AgentConfig 堡垒机探针配置
type AgentConfig struct {
	AgentID       string `json:"agent_id"`
	HubAddress    string `json:"hub_address"`
	ListenAddress string `json:"listen_address"`
	Hostname      string `json:"hostname"`
	LocalIP       string `json:"local_ip"`
}

// BastionAgent 4A 运维特权审计微服务探针
type BastionAgent struct {
	cfg          *AgentConfig
	engine       *Engine
	sm           *SessionManager
	grpcConn     *grpc.ClientConn
	client       pb.AlinkSecHubServiceClient
	sessionToken string
	stopChan     chan struct{}
	eventChan    chan *pb.RawSecurityEvent
	wg           sync.WaitGroup
	running      bool
	mu           sync.Mutex
}

// NewBastionAgent 初始化探针
func NewBastionAgent(cfg *AgentConfig) *BastionAgent {
	return &BastionAgent{
		cfg:       cfg,
		engine:    NewEngine(),
		sm:        NewSessionManager(),
		stopChan:  make(chan struct{}),
		eventChan: make(chan *pb.RawSecurityEvent, 1000),
	}
}

// Start 启动堡垒机审计探针
func (a *BastionAgent) Start(ctx context.Context) error {
	a.mu.Lock()
	a.running = true
	a.mu.Unlock()

	logger.Info("Starting AlinkSec Bastion 4A privileged audit agent",
		"agent_id", a.cfg.AgentID, "hub", a.cfg.HubAddress)

	if a.cfg.HubAddress != "" {
		if err := a.connectHub(); err != nil {
			logger.Warn("Failed to connect to Hub initially, running standalone mode", "error", err)
		} else {
			a.wg.Add(2)
			go a.heartbeatLoop()
			go a.eventStreamingLoop()
		}
	}

	return nil
}

// Stop 停止探针
func (a *BastionAgent) Stop() {
	a.mu.Lock()
	if !a.running {
		a.mu.Unlock()
		return
	}
	a.running = false
	close(a.stopChan)
	a.mu.Unlock()

	a.wg.Wait()
	if a.grpcConn != nil {
		_ = a.grpcConn.Close()
	}
	logger.Info("Bastion agent stopped cleanly")
}

// GetEngine 获取指令防御引擎
func (a *BastionAgent) GetEngine() *Engine {
	return a.engine
}

// GetSessionManager 获取会话管理器
func (a *BastionAgent) GetSessionManager() *SessionManager {
	return a.sm
}

// ExecuteAndAudit 执行指令审核并记录
func (a *BastionAgent) ExecuteAndAudit(session *Session, rawCmd string) (*CommandCheckResult, *SessionCommandRecord) {
	res := a.engine.CheckCommand(rawCmd)
	rec := session.RecordCommand(rawCmd, res)

	if !res.Allowed || res.RiskLevel == RiskHigh || res.RiskLevel == RiskCritical {
		event := a.buildSecurityEvent(session, rawCmd, res, rec)
		select {
		case a.eventChan <- event:
		default:
			logger.Warn("Bastion event queue full, dropping event", "cmd", rawCmd)
		}
	}

	return res, rec
}

func (a *BastionAgent) buildSecurityEvent(s *Session, cmd string, res *CommandCheckResult, rec *SessionCommandRecord) *pb.RawSecurityEvent {
	level := pb.EventLevel_LEVEL_WARN
	if res.RiskLevel == RiskCritical {
		level = pb.EventLevel_LEVEL_CRITICAL
	} else if res.RiskLevel == RiskHigh {
		level = pb.EventLevel_LEVEL_HIGH
	}

	ruleID := ""
	if res.MatchedRule != nil {
		ruleID = res.MatchedRule.RuleID
	}

	payload := fmt.Sprintf(`{"session_id":"%s","operator":"%s","client_ip":"%s","target":"%s","command":"%s","rule_id":"%s","action":"%s","hash":"%s"}`,
		s.SessionID, s.Username, s.ClientIP, s.TargetHost, cmd, ruleID, res.Action, rec.CurrentHash)

	eventID, _ := crypto.GenerateSecureToken(16)

	return &pb.RawSecurityEvent{
		EventId:         eventID,
		SourceAgentType: pb.AgentType_AGENT_BASTION,
		AgentId:         a.cfg.AgentID,
		HostIp:          s.TargetHost,
		Hostname:        a.cfg.Hostname,
		EventTime:       time.Now().Unix(),
		Level:           level,
		Category:        "BASTION_PRIVILEGE_CONTROL",
		RuleId:          ruleID,
		Message:         fmt.Sprintf("[4A高危指令阻断] 运维人员 %s 尝试执行危险指令: %s", s.Username, cmd),
		RawPayload:      []byte(payload),
		Signature:       crypto.SHA256String(fmt.Sprintf("%s|%s|%s", eventID, ruleID, payload)),
	}
}

func (a *BastionAgent) connectHub() error {
	conn, err := grpc.Dial(a.cfg.HubAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	a.grpcConn = conn
	a.client = pb.NewAlinkSecHubServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	regResp, err := a.client.RegisterAgent(ctx, &pb.RegisterRequest{
		AgentId:   a.cfg.AgentID,
		AgentType: pb.AgentType_AGENT_BASTION,
		Version:   "v1.0.0",
		Hostname:  a.cfg.Hostname,
		Ip:        a.cfg.LocalIP,
		Os:        "linux",
		Arch:      "amd64",
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return err
	}

	a.sessionToken = regResp.SessionToken
	logger.Info("Registered Bastion agent to Hub successfully", "session_token_prefix", a.sessionToken[:8])
	return nil
}

func (a *BastionAgent) heartbeatLoop() {
	defer a.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopChan:
			return
		case <-ticker.C:
			if a.client == nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, _ = a.client.SendHeartbeat(ctx, &pb.HeartbeatRequest{
				AgentId:          a.cfg.AgentID,
				SessionToken:     a.sessionToken,
				Timestamp:        time.Now().Unix(),
				CpuUsage:         0.5,
				MemoryUsedBytes:  18 * 1024 * 1024,
				ActiveRulesCount: int32(len(a.engine.rules)),
			})
			cancel()
		}
	}
}

func (a *BastionAgent) eventStreamingLoop() {
	defer a.wg.Done()
	for {
		select {
		case <-a.stopChan:
			return
		case event := <-a.eventChan:
			if a.client == nil {
				continue
			}
			streamCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			stream, err := a.client.ReportEvents(streamCtx)
			if err == nil {
				_ = stream.Send(event)
				_, _ = stream.CloseAndRecv()
			}
			cancel()
		}
	}
}
