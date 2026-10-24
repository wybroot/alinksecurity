package dbaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/crypto/tlsutil"
	"alinksec/pkg/logger"
	"google.golang.org/grpc"
)

// AgentConfig 数据库审计探针配置
type AgentConfig struct {
	AgentID      string        `json:"agent_id"`
	Hostname     string        `json:"hostname"`
	HubAddr      string        `json:"hub_addr"`
	ListenAddr   string        `json:"listen_addr"`    // 审计代理监听地址 (例如 0.0.0.0:13306)
	TargetDBAddr string        `json:"target_db_addr"` // 目标真实数据库地址 (例如 127.0.0.1:3306)
	Protocol     DBProtocol    `json:"protocol"`       // 审计目标协议 (MySQL / PostgreSQL)
	HeartbeatSec time.Duration `json:"heartbeat_sec"`
	Standalone   bool          `json:"standalone"`
	AuditLogPath string        `json:"audit_log_path"`
	TLSEnabled   bool          `json:"tls_enabled"`
	TLSCert      string        `json:"tls_cert"`
	TLSKey       string        `json:"tls_key"`
	TLSCA        string        `json:"tls_ca"`
	ServerName   string        `json:"server_name"`
}

// DBAuditAgent 数据库审计探针
type DBAuditAgent struct {
	cfg         *AgentConfig
	analyzer    *SQLAnalyzer
	mysqlParser *MySQLParser
	pgParser    *PGParser
	ctx         context.Context
	cancel      context.CancelFunc
	token       string
	policyVer   string
	listener    net.Listener
	wg          sync.WaitGroup

	// 指标
	totalQueries uint64
	threatCount  uint64
	connCount    int32

	// gRPC 客户端连接
	grpcConn      *grpc.ClientConn
	hubClient     pb.AlinkSecHubServiceClient
	eventStream   pb.AlinkSecHubService_ReportEventsClient
	eventStreamMu sync.Mutex

	// 审计事件回调 (用于测试与订阅)
	onAuditRecord func(record *AuditRecord)
}

// NewDBAuditAgent 创建数据库审计探针
func NewDBAuditAgent(cfg *AgentConfig) *DBAuditAgent {
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &DBAuditAgent{
		cfg:         cfg,
		analyzer:    NewSQLAnalyzer(),
		mysqlParser: NewMySQLParser(),
		pgParser:    NewPGParser(),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// SetAuditCallback 设置审计记录监听回调
func (a *DBAuditAgent) SetAuditCallback(fn func(record *AuditRecord)) {
	a.onAuditRecord = fn
}

// Start 启动数据库审计探针
func (a *DBAuditAgent) Start() error {
	logger.Info("Starting alinksec-dbaudit agent",
		"agent_id", a.cfg.AgentID,
		"protocol", a.cfg.Protocol,
		"listen", a.cfg.ListenAddr,
		"target_db", a.cfg.TargetDBAddr,
		"standalone", a.cfg.Standalone,
	)

	// 1. 若非脱机模式，连接安全中枢 gRPC
	if !a.cfg.Standalone && a.cfg.HubAddr != "" {
		if err := a.connectAndRegisterHub(); err != nil {
			logger.Error("Failed to register with alinksec-hub, switching to fallback offline mode", "err", err)
		} else {
			go a.heartbeatLoop()
		}
	}

	// 2. 启动透明审计网关代理
	if a.cfg.ListenAddr != "" && a.cfg.TargetDBAddr != "" {
		l, err := net.Listen("tcp", a.cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("failed to bind audit proxy on %s: %w", a.cfg.ListenAddr, err)
		}
		a.listener = l

		a.wg.Add(1)
		go a.acceptLoop()
	}

	return nil
}

// Stop 停止数据库审计探针
func (a *DBAuditAgent) Stop() {
	logger.Info("Stopping alinksec-dbaudit agent...")
	a.cancel()

	if a.listener != nil {
		_ = a.listener.Close()
	}

	a.eventStreamMu.Lock()
	if a.eventStream != nil {
		_, _ = a.eventStream.CloseAndRecv()
	}
	a.eventStreamMu.Unlock()

	if a.grpcConn != nil {
		_ = a.grpcConn.Close()
	}

	a.wg.Wait()
	logger.Info("alinksec-dbaudit agent terminated gracefully")
}

// GetMetrics 获取运行时指标
func (a *DBAuditAgent) GetMetrics() (queries, threats uint64, activeConns int32) {
	return atomic.LoadUint64(&a.totalQueries), atomic.LoadUint64(&a.threatCount), atomic.LoadInt32(&a.connCount)
}

// acceptLoop 处理客户端数据库连接
func (a *DBAuditAgent) acceptLoop() {
	defer a.wg.Done()
	for {
		clientConn, err := a.listener.Accept()
		if err != nil {
			select {
			case <-a.ctx.Done():
				return
			default:
				logger.Error("Accept error on audit proxy", "err", err)
				time.Sleep(50 * time.Millisecond)
				continue
			}
		}

		atomic.AddInt32(&a.connCount, 1)
		go a.handleConnection(clientConn)
	}
}

// handleConnection 代理双向流量并执行旁路审计解析
func (a *DBAuditAgent) handleConnection(clientConn net.Conn) {
	defer func() {
		_ = clientConn.Close()
		atomic.AddInt32(&a.connCount, -1)
	}()

	serverConn, err := net.DialTimeout("tcp", a.cfg.TargetDBAddr, 3*time.Second)
	if err != nil {
		logger.Error("Failed to connect to target database backend", "target", a.cfg.TargetDBAddr, "err", err)
		return
	}
	defer serverConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	serverAddr := serverConn.RemoteAddr().String()

	var clientUser string
	var currentDB string

	// 管道 1: 客户端 -> 服务端 (执行协议解析与 SQL 审查)
	go func() {
		defer func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		}()

		buf := make([]byte, 32*1024)
		for {
			n, err := clientConn.Read(buf)
			if err != nil {
				return
			}
			chunk := buf[:n]

			// 协议解析与审计记录生成
			a.inspectClientChunk(chunk, clientAddr, serverAddr, &clientUser, &currentDB)

			// 转发至目标数据库
			if _, wErr := serverConn.Write(chunk); wErr != nil {
				return
			}
		}
	}()

	// 管道 2: 服务端 -> 客户端 (透传响应)
	respBuf := make([]byte, 32*1024)
	for {
		n, err := serverConn.Read(respBuf)
		if err != nil {
			return
		}
		if _, wErr := clientConn.Write(respBuf[:n]); wErr != nil {
			return
		}
	}
}

// inspectClientChunk 解析客户端数据帧
func (a *DBAuditAgent) inspectClientChunk(data []byte, clientAddr, serverAddr string, user *string, db *string) {
	start := time.Now()

	switch a.cfg.Protocol {
	case ProtoMySQL:
		offset := 0
		for offset+4 <= len(data) {
			payloadLen := int(uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16)
			packetEnd := offset + 4 + payloadLen
			if packetEnd > len(data) {
				packetEnd = len(data)
			}
			packet := data[offset:packetEnd]

			// 检查握手响应认证
			if *user == "" && len(packet) > 4 && packet[3] == 1 {
				if u, d, ok := a.mysqlParser.ParseHandshakeResponse(packet); ok && u != "" {
					*user = u
					if d != "" {
						*db = d
					}
					logger.Info("MySQL Client authenticated", "user", *user, "db", *db, "client", clientAddr)
				}
			}

			cmd, query, newDB, ok := a.mysqlParser.ParseClientPacket(packet)
			if ok {
				if newDB != "" {
					*db = newDB
				}
				if query != "" && cmd == ComQuery {
					atomic.AddUint64(&a.totalQueries, 1)
					latency := time.Since(start).Milliseconds()
					record := a.analyzer.Analyze(clientAddr, serverAddr, *user, *db, query, ProtoMySQL, latency)
					a.processRecord(record)
				}
			}

			if packetEnd >= len(data) || payloadLen == 0 {
				break
			}
			offset = packetEnd
		}

	case ProtoPostgreSQL:
		offset := 0
		for offset+5 <= len(data) {
			msgLen := int(uint32(data[offset+1])<<24 | uint32(data[offset+2])<<16 | uint32(data[offset+3])<<8 | uint32(data[offset+4]))
			packetEnd := offset + 1 + msgLen
			if packetEnd > len(data) || packetEnd <= offset {
				packetEnd = len(data)
			}
			packet := data[offset:packetEnd]

			if *user == "" {
				if u, d, ok := a.pgParser.ParseStartupMessage(packet); ok {
					*user = u
					*db = d
					logger.Info("PostgreSQL Client connected", "user", *user, "db", *db, "client", clientAddr)
				}
			}

			msgType, query, ok := a.pgParser.ParseClientPacket(packet)
			if ok && query != "" && (msgType == PGMsgSimpleQuery || msgType == PGMsgParse) {
				atomic.AddUint64(&a.totalQueries, 1)
				latency := time.Since(start).Milliseconds()
				record := a.analyzer.Analyze(clientAddr, serverAddr, *user, *db, query, ProtoPostgreSQL, latency)
				a.processRecord(record)
			}

			if packetEnd >= len(data) || msgLen == 0 {
				break
			}
			offset = packetEnd
		}
	}
}

// ProcessManualQuery 供单元测试或外部离线抓包重放直接分析 SQL
func (a *DBAuditAgent) ProcessManualQuery(clientAddr, serverAddr, user, db, sql string, proto DBProtocol) *AuditRecord {
	atomic.AddUint64(&a.totalQueries, 1)
	record := a.analyzer.Analyze(clientAddr, serverAddr, user, db, sql, proto, 1)
	a.processRecord(record)
	return record
}

func (a *DBAuditAgent) processRecord(record *AuditRecord) {
	if record.IsThreat {
		atomic.AddUint64(&a.threatCount, 1)
		logger.Warn("DBAudit Rule Violation Intercepted",
			"risk_level", record.RiskLevel,
			"rule_id", record.RuleID,
			"threat_type", record.ThreatType,
			"db_user", record.DBUser,
			"sql", record.SQL,
		)
		// 异步上报至管理中枢
		go a.reportThreatEvent(record)
	}

	if a.onAuditRecord != nil {
		a.onAuditRecord(record)
	}
}

func (a *DBAuditAgent) connectAndRegisterHub() error {
	conn, err := tlsutil.DialHub(a.ctx, a.cfg.HubAddr, a.cfg.TLSEnabled, a.cfg.TLSCert, a.cfg.TLSKey, a.cfg.TLSCA, a.cfg.ServerName)
	if err != nil {
		return err
	}
	a.grpcConn = conn
	a.hubClient = pb.NewAlinkSecHubServiceClient(conn)

	regReq := &pb.RegisterRequest{
		AgentId:   a.cfg.AgentID,
		AgentType: pb.AgentType_AGENT_AUDIT,
		Hostname:  a.cfg.Hostname,
		Version:   "v1.0.0",
		Timestamp: time.Now().Unix(),
	}

	resp, err := a.hubClient.RegisterAgent(a.ctx, regReq)
	if err != nil {
		return err
	}
	a.token = resp.SessionToken
	logger.Info("Successfully registered with alinksec-hub", "token_prefix", a.token[:8])
	return nil
}

func (a *DBAuditAgent) heartbeatLoop() {
	ticker := time.NewTicker(a.cfg.HeartbeatSec)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			queries, threats, conns := a.GetMetrics()
			hb := &pb.HeartbeatRequest{
				AgentId:          a.cfg.AgentID,
				SessionToken:     a.token,
				Timestamp:        time.Now().Unix(),
				CpuUsage:         0.8,
				MemoryUsedBytes:  18 * 1024 * 1024,
				DiskUsedBytes:    50 * 1024 * 1024,
				ActiveRulesCount: 7,
			}
			resp, err := a.hubClient.SendHeartbeat(a.ctx, hb)
			if err != nil {
				logger.Error("Heartbeat to hub failed", "err", err)
			} else {
				logger.Debug("DBAudit Heartbeat ACK",
					"server_time", resp.ServerTime,
					"queries", queries,
					"threats", threats,
					"active_conns", conns,
				)
			}
		}
	}
}

func (a *DBAuditAgent) reportThreatEvent(record *AuditRecord) {
	if a.hubClient == nil || a.cfg.Standalone {
		return
	}

	payloadMap := map[string]interface{}{
		"incident_id":   record.ID,
		"protocol":      record.Protocol,
		"client_addr":   record.ClientAddr,
		"server_addr":   record.ServerAddr,
		"db_user":       record.DBUser,
		"database":      record.Database,
		"operation":     record.Operation,
		"sql":           record.SQL,
		"risk_level":    record.RiskLevel,
		"threat_type":   record.ThreatType,
		"threat_reason": record.ThreatReason,
		"rule_id":       record.RuleID,
	}
	payloadJSON, _ := json.Marshal(payloadMap)
	hash := sha256.Sum256(payloadJSON)

	var level pb.EventLevel
	switch record.RiskLevel {
	case RiskCritical:
		level = pb.EventLevel_LEVEL_CRITICAL
	case RiskHigh:
		level = pb.EventLevel_LEVEL_HIGH
	case RiskMedium:
		level = pb.EventLevel_LEVEL_WARN
	default:
		level = pb.EventLevel_LEVEL_INFO
	}

	evt := &pb.RawSecurityEvent{
		EventId:         record.ID,
		SourceAgentType: pb.AgentType_AGENT_AUDIT,
		AgentId:         a.cfg.AgentID,
		HostIp:          record.ClientAddr,
		Hostname:        a.cfg.Hostname,
		EventTime:       record.Timestamp.Unix(),
		Level:           level,
		Category:        "DB_AUDIT",
		RuleId:          record.RuleID,
		Message:         fmt.Sprintf("[%s] %s: %s", record.Protocol, record.ThreatType, record.ThreatReason),
		RawPayload:      payloadJSON,
		Signature:       hex.EncodeToString(hash[:]),
	}

	a.eventStreamMu.Lock()
	defer a.eventStreamMu.Unlock()

	var err error
	if a.eventStream == nil {
		a.eventStream, err = a.hubClient.ReportEvents(a.ctx)
		if err != nil {
			logger.Error("Failed to open report events stream", "err", err)
			return
		}
	}

	if sendErr := a.eventStream.Send(evt); sendErr != nil {
		logger.Error("Failed to send audit threat event", "err", sendErr)
		a.eventStream = nil
	} else {
		logger.Info("Reported DBAudit security event to hub", "event_id", record.ID, "rule_id", record.RuleID)
	}
}
