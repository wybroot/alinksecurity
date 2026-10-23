package hub

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/crypto"
	"alinksec/pkg/eventbus"
	"alinksec/pkg/logger"
	"alinksec/pkg/storage"
)

// RegisteredAgent 内存中记录的 Agent 状态
type RegisteredAgent struct {
	AgentID           string
	AgentType         pb.AgentType
	Version           string
	Hostname          string
	IP                string
	SessionToken      string
	Status            string // "online", "offline"
	LastHeartbeatTime time.Time
	CPUUsage          float32
	MemoryUsedBytes   int64
	DiskUsedBytes     int64
	ActiveRulesCount  int32
	CurrentPolicyVer  string
}

// HubServer 实现了 pb.AlinkSecHubServiceServer 接口
type HubServer struct {
	pb.UnimplementedAlinkSecHubServiceServer
	mu              sync.RWMutex
	agents          map[string]*RegisteredAgent
	latestPolicyVer string
	latestPolicies  map[pb.AgentType]*pb.PolicyPackage
	eventCh         chan *pb.RawSecurityEvent
	lastChainedHash string

	// 生产级存储与事件总线扩展
	storage    storage.StorageEngine
	clickhouse *storage.ClickHouseWriter
	bus        eventbus.Bus
}

// NewHubServer 创建 Hub 服务实例
func NewHubServer() *HubServer {
	return NewProductionHubServer(nil, nil, nil)
}

// NewProductionHubServer 创建生产级 Hub 服务实例
func NewProductionHubServer(store storage.StorageEngine, chWriter *storage.ClickHouseWriter, bus eventbus.Bus) *HubServer {
	s := &HubServer{
		agents:          make(map[string]*RegisteredAgent),
		latestPolicyVer: "v1.0.0",
		latestPolicies:  make(map[pb.AgentType]*pb.PolicyPackage),
		eventCh:         make(chan *pb.RawSecurityEvent, 10000),
		lastChainedHash: "0000000000000000000000000000000000000000000000000000000000000000",
		storage:         store,
		clickhouse:      chWriter,
		bus:             bus,
	}

	// 初始化一个基准策略包 (用于示例与验证)
	s.initDefaultPolicies()
	return s
}

func (s *HubServer) initDefaultPolicies() {
	defaultPkg := &pb.PolicyPackage{
		PolicyVersion: "v1.0.0",
		CreatedAt:     time.Now().Unix(),
		Signature:     []byte(crypto.SHA256String("alinksec-policy-v1.0.0")),
		FileRules: []*pb.FileRule{
			{
				RuleId:         "rule_file_001",
				PathPattern:    "/etc/shadow",
				IsProtected:    true,
				BackupOnModify: true,
			},
			{
				RuleId:         "rule_file_002",
				PathPattern:    "/var/www/html/**",
				IsProtected:    true,
				BackupOnModify: true,
			},
		},
		ProcessRules: []*pb.ProcessRule{
			{
				RuleId:          "rule_proc_001",
				ProcessName:     "ncat",
				AllowedHash:     "",
				BlockIfMismatch: true,
			},
		},
		NetworkRules: []*pb.NetworkRule{
			{
				RuleId:    "rule_net_001",
				Direction: "IN",
				Protocol:  "TCP",
				SrcCidr:   "0.0.0.0/0",
				DstPort:   "22",
				Action:    "LOG",
			},
		},
	}

	s.latestPolicies[pb.AgentType_AGENT_EDR] = defaultPkg
	s.latestPolicies[pb.AgentType_AGENT_WAF] = defaultPkg
	s.latestPolicies[pb.AgentType_AGENT_FIREWALL] = defaultPkg
	s.latestPolicies[pb.AgentType_AGENT_AUDIT] = defaultPkg
	s.latestPolicies[pb.AgentType_AGENT_TAMPER] = defaultPkg
}

// SetStorageEngine 配置生产关系数据库持久化引擎 (PostgreSQL)
func (s *HubServer) SetStorageEngine(se storage.StorageEngine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storage = se
}

// SetClickHouseWriter 配置等保 180 天原始日志与审计 ClickHouse 写入器
func (s *HubServer) SetClickHouseWriter(cw *storage.ClickHouseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clickhouse = cw
}

// SetEventBus 配置 NATS 生产事件总线
func (s *HubServer) SetEventBus(b eventbus.Bus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bus = b
}

// StartHeartbeatMonitor 启动探针心跳离线监测看门狗 (生产高可用)
func (s *HubServer) StartHeartbeatMonitor(ctx context.Context, interval, timeout time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				now := time.Now()
				for id, a := range s.agents {
					if a.Status == "online" && now.Sub(a.LastHeartbeatTime) > timeout {
						a.Status = "offline"
						logger.Warn("Agent detected OFFLINE (heartbeat timeout)",
							"agent_id", id,
							"agent_type", a.AgentType.String(),
							"ip", a.IP,
							"last_seen", a.LastHeartbeatTime.Format(time.RFC3339),
						)
					}
				}
				store := s.storage
				s.mu.Unlock()

				// 若配置了持久化数据库，同步标记持久化层状态
				if store != nil {
					if _, err := store.MarkOfflineAgents(ctx, timeout); err != nil {
						logger.Warn("Failed to sync offline agents to postgres", "err", err)
					}
				}
			}
		}
	}()
}

// RegisterAgent 探针上线注册
func (s *HubServer) RegisterAgent(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req.AgentId == "" {
		return &pb.RegisterResponse{
			Success: false,
			Message: "agent_id cannot be empty",
		}, errors.New("agent_id cannot be empty")
	}

	token, err := crypto.GenerateSecureToken(32)
	if err != nil {
		return &pb.RegisterResponse{
			Success: false,
			Message: "failed to generate session token",
		}, err
	}

	s.mu.Lock()
	s.agents[req.AgentId] = &RegisteredAgent{
		AgentID:           req.AgentId,
		AgentType:         req.AgentType,
		Version:           req.Version,
		Hostname:          req.Hostname,
		IP:                req.Ip,
		SessionToken:      token,
		Status:            "online",
		LastHeartbeatTime: time.Now(),
	}

	store := s.storage
	s.mu.Unlock()

	// 生产持久化落盘
	if store != nil {
		go func() {
			rec := &storage.AgentRecord{
				AgentID:           req.AgentId,
				AgentType:         req.AgentType,
				AgentTypeStr:      req.AgentType.String(),
				Version:           req.Version,
				Hostname:          req.Hostname,
				IP:                req.Ip,
				SessionToken:      token,
				Status:            "online",
				LastHeartbeatTime: time.Now(),
			}
			if err := store.SaveAgent(context.Background(), rec); err != nil {
				logger.Warn("Failed to persist registered agent to PostgreSQL", "err", err)
			}
		}()
	}

	logger.Info("Agent registered successfully",
		"agent_id", req.AgentId,
		"agent_type", req.AgentType.String(),
		"ip", req.Ip,
		"hostname", req.Hostname,
	)

	return &pb.RegisterResponse{
		Success:              true,
		Message:              "registered successfully",
		SessionToken:         token,
		HeartbeatIntervalSec: 15,
		ServerTime:           time.Now().Unix(),
	}, nil
}

// SendHeartbeat 心跳探活与状态同步
func (s *HubServer) SendHeartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent, exists := s.agents[req.AgentId]
	if !exists || agent.SessionToken != req.SessionToken {
		return &pb.HeartbeatResponse{
			Acknowledged: false,
			ServerTime:   time.Now().Unix(),
		}, errors.New("unauthorized agent heartbeat or invalid session token")
	}

	agent.LastHeartbeatTime = time.Now()
	agent.CPUUsage = req.CpuUsage
	agent.MemoryUsedBytes = req.MemoryUsedBytes
	agent.DiskUsedBytes = req.DiskUsedBytes
	agent.ActiveRulesCount = req.ActiveRulesCount
	agent.Status = "online"

	needSync := agent.CurrentPolicyVer != s.latestPolicyVer
	store := s.storage

	// 异步更新数据库心跳指标
	if store != nil {
		go func(aID string, cpu float32, mem, disk int64, rules int32, pVer string) {
			_ = store.UpdateAgentHeartbeat(context.Background(), aID, cpu, mem, disk, rules, pVer)
		}(req.AgentId, req.CpuUsage, req.MemoryUsedBytes, req.DiskUsedBytes, req.ActiveRulesCount, agent.CurrentPolicyVer)
	}

	return &pb.HeartbeatResponse{
		Acknowledged:        true,
		NeedPolicySync:      needSync,
		LatestPolicyVersion: s.latestPolicyVer,
		ServerTime:          time.Now().Unix(),
	}, nil
}

// ReportEvents 客户端流式上报安全事件
func (s *HubServer) ReportEvents(stream pb.AlinkSecHubService_ReportEventsServer) error {
	var count int64 = 0

	for {
		event, err := stream.Recv()
		if err == io.EOF {
			// 流传输结束，发送确认响应
			return stream.SendAndClose(&pb.ReportAck{
				AcceptedCount: count,
				ServerTime:    time.Now().Unix(),
			})
		}
		if err != nil {
			logger.Error("Error receiving event from stream", "err", err)
			return err
		}

		// 验证事件字段完整性
		if event.EventId == "" || event.AgentId == "" {
			logger.Warn("Dropped invalid event with missing ID or AgentID")
			continue
		}

		// 等保2.0 防篡改链式哈希计算
		s.mu.Lock()
		eventPayload := fmt.Sprintf("%s|%s|%d|%s", event.EventId, event.AgentId, event.EventTime, event.Message)
		s.lastChainedHash = crypto.ComputeChainedHash(s.lastChainedHash, []byte(eventPayload))
		currentChainHash := s.lastChainedHash
		cw := s.clickhouse
		eb := s.bus
		s.mu.Unlock()

		count++

		// 生产级 ClickHouse 批处理持久化 (留存 >= 180天)
		if cw != nil {
			cw.WriteSecurityEvent(&storage.SecurityEventRecord{
				EventID:    event.EventId,
				SourceType: event.SourceAgentType.String(),
				AgentID:    event.AgentId,
				HostIP:     event.HostIp,
				Hostname:   event.Hostname,
				EventTime:  time.Unix(event.EventTime, 0),
				Level:      event.Level.String(),
				Category:   event.Category,
				RuleID:     event.RuleId,
				Message:    event.Message,
				RawPayload: string(event.RawPayload),
				Signature:  string(event.Signature),
				ChainHash:  currentChainHash,
			})
		}

		// 生产级 NATS 事件总线广播 (供 SOAR、告警降噪与态势流消费)
		if eb != nil {
			subject := fmt.Sprintf("alinksec.events.%s", strings.ToLower(event.SourceAgentType.String()))
			_ = eb.Publish(subject, &eventbus.EventMessage{
				EventID:     event.EventId,
				SourceType:  event.SourceAgentType.String(),
				AgentID:     event.AgentId,
				SourceIP:    event.HostIp,
				Hostname:    event.Hostname,
				Level:       event.Level.String(),
				RuleID:      event.RuleId,
				ThreatType:  event.Category,
				Message:     event.Message,
				RawPayload:  string(event.RawPayload),
				EventTime:   time.Unix(event.EventTime, 0),
				ChainedHash: currentChainHash,
			})
		}

		// 非阻塞投递到内部处理管道
		select {
		case s.eventCh <- event:
		default:
			logger.Warn("Event queue full, dropping event buffer overflow", "event_id", event.EventId)
		}
	}
}

// SyncPolicy 策略下发
func (s *HubServer) SyncPolicy(ctx context.Context, req *pb.PolicySyncRequest) (*pb.PolicyPackage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agent, exists := s.agents[req.AgentId]
	if !exists || agent.SessionToken != req.SessionToken {
		return nil, errors.New("unauthorized policy sync request")
	}

	pkg, ok := s.latestPolicies[agent.AgentType]
	if !ok {
		return nil, fmt.Errorf("no policy found for agent type: %v", agent.AgentType)
	}

	// 记录已同步版本
	agent.CurrentPolicyVer = pkg.PolicyVersion

	logger.Info("Policy synchronized to agent",
		"agent_id", req.AgentId,
		"policy_version", pkg.PolicyVersion,
	)

	return pkg, nil
}

// GetAgent 获取指定 Agent 状态 (辅助查询)
func (s *HubServer) GetAgent(agentID string) (*RegisteredAgent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[agentID]
	if !ok {
		return nil, false
	}
	cp := *a
	return &cp, true
}

// GetLastChainedHash 获取最新防篡改链式哈希
func (s *HubServer) GetLastChainedHash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastChainedHash
}
