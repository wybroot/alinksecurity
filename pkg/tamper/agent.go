package tamper

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	pb "alinksec/api/proto/v1"
	"alinksec/pkg/crypto"
	"alinksec/pkg/crypto/tlsutil"
	"alinksec/pkg/logger"
	"google.golang.org/grpc"
)

// Agent 网页防篡改微探针
type Agent struct {
	cfg          Config
	vault        *BaselineVault
	watcher      *Watcher
	hubClient    pb.AlinkSecHubServiceClient
	grpcConn     *grpc.ClientConn
	sessionToken string
	eventStream  grpc.ClientStreamingClient[pb.RawSecurityEvent, pb.ReportAck]
	tamperCount  uint64
	revertCount  uint64
}

// NewAgent 创建网页防篡改微探针
func NewAgent(cfg Config) (*Agent, error) {
	if cfg.AgentID == "" {
		cfg.AgentID = "tamper-" + time.Now().Format("20060102150405")
	}
	if len(cfg.ProtectedExts) == 0 {
		cfg.ProtectedExts = []string{".html", ".htm", ".jsp", ".php", ".js", ".css", ".png", ".jpg", ".svg", ".json"}
	}
	if cfg.BackupDir == "" {
		cfg.BackupDir = cfg.WatchDir + "_safe_vault"
	}

	vault, err := NewBaselineVault(cfg.WatchDir, cfg.BackupDir, cfg.ProtectedExts)
	if err != nil {
		return nil, fmt.Errorf("init baseline vault failed: %w", err)
	}

	a := &Agent{
		cfg:   cfg,
		vault: vault,
	}

	watcher, err := NewWatcher(vault, cfg.WatchDir, cfg.AutoRevert, cfg.ProtectedExts, a.handleTamperEvent)
	if err != nil {
		return nil, fmt.Errorf("init fs watcher failed: %w", err)
	}
	a.watcher = watcher

	return a, nil
}

// Start 启动防篡改探针
func (a *Agent) Start(ctx context.Context) error {
	logger.Info("Building initial tamper baseline vault...", "watch_dir", a.cfg.WatchDir)
	if err := a.vault.BuildBaseline(); err != nil {
		return fmt.Errorf("build baseline failed: %w", err)
	}
	logger.Info("Tamper baseline built successfully", "total_files", len(a.vault.records))

	if a.cfg.HubAddr != "" {
		if err := a.connectHub(ctx); err != nil {
			logger.Warn("Failed to connect to Hub, running in standalone mode", "err", err)
		} else {
			go a.heartbeatLoop(ctx)
		}
	}

	if err := a.watcher.Start(ctx); err != nil {
		return fmt.Errorf("start watcher failed: %w", err)
	}

	logger.Info("AlinkSec Web Tamper-Proof Agent is running",
		"agent_id", a.cfg.AgentID,
		"watch_dir", a.cfg.WatchDir,
		"auto_revert", a.cfg.AutoRevert,
	)

	<-ctx.Done()
	return nil
}

// Stop 停止防篡改探针
func (a *Agent) Stop() {
	if a.watcher != nil {
		_ = a.watcher.Stop()
	}
	if a.grpcConn != nil {
		_ = a.grpcConn.Close()
	}
	logger.Info("Web Tamper-Proof Agent stopped safely")
}

// GetMetrics 获取篡改与自愈统计
func (a *Agent) GetMetrics() (tampers, reverts uint64) {
	return atomic.LoadUint64(&a.tamperCount), atomic.LoadUint64(&a.revertCount)
}

func (a *Agent) handleTamperEvent(evt TamperEvent) {
	atomic.AddUint64(&a.tamperCount, 1)
	if evt.Reverted {
		atomic.AddUint64(&a.revertCount, 1)
	}

	logger.Warn("Tampering Event Detected!",
		"action", evt.Action,
		"file", evt.FilePath,
		"reverted", evt.Reverted,
		"old_hash", evt.OldHash,
		"new_hash", evt.NewHash,
	)

	// 若连接中枢，流式上报安全事件
	if a.eventStream != nil {
		hostname, _ := os.Hostname()
		secEvt := &pb.RawSecurityEvent{
			EventId:         evt.EventID,
			SourceAgentType: pb.AgentType_AGENT_TAMPER,
			AgentId:         a.cfg.AgentID,
			HostIp:          getLocalIP(),
			Hostname:        hostname,
			EventTime:       evt.Timestamp,
			Level:           evt.Level,
			Category:        string(evt.Action),
			RuleId:          "TAMPER-GB22239-RECOVERY",
			Message:         fmt.Sprintf("Web Tamper Detected [%s] on %s (Reverted: %v)", evt.Action, evt.FilePath, evt.Reverted),
			RawPayload:      []byte(fmt.Sprintf("%s|%s|%s", evt.FilePath, evt.OldHash, evt.NewHash)),
			Signature:       crypto.SHA256String(fmt.Sprintf("%s|%s|%s", evt.EventID, evt.FilePath, evt.Action)),
		}

		_ = a.eventStream.Send(secEvt)
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = a.hubClient.SendHeartbeat(ctx, &pb.HeartbeatRequest{
				AgentId:          a.cfg.AgentID,
				SessionToken:     a.sessionToken,
				Timestamp:        time.Now().Unix(),
				CpuUsage:         1.5,
				MemoryUsedBytes:  32 * 1024 * 1024,
				DiskUsedBytes:    500 * 1024 * 1024,
				ActiveRulesCount: int32(len(a.vault.records)),
			})
		}
	}
}

func (a *Agent) connectHub(ctx context.Context) error {
	conn, err := tlsutil.DialHub(ctx, a.cfg.HubAddr, a.cfg.TLSEnabled, a.cfg.TLSCert, a.cfg.TLSKey, a.cfg.TLSCA, a.cfg.ServerName)
	if err != nil {
		return err
	}
	a.grpcConn = conn
	a.hubClient = pb.NewAlinkSecHubServiceClient(conn)

	hostname, _ := os.Hostname()

	regResp, err := a.hubClient.RegisterAgent(ctx, &pb.RegisterRequest{
		AgentId:   a.cfg.AgentID,
		AgentType: pb.AgentType_AGENT_TAMPER,
		Version:   "v1.0.0",
		Hostname:  hostname,
		Ip:        getLocalIP(),
		Os:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("register tamper agent failed: %w", err)
	}
	a.sessionToken = regResp.SessionToken

	stream, err := a.hubClient.ReportEvents(ctx)
	if err != nil {
		return fmt.Errorf("open report stream failed: %w", err)
	}
	a.eventStream = stream

	return nil
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil {
					return ipNet.IP.String()
				}
			}
		}
	}
	return "127.0.0.1"
}
