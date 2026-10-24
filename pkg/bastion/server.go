package bastion

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"

	"alinksec/pkg/logger"
)

// HookServer 生产级终端会话实时审计与高危拦截本地服务
type HookServer struct {
	agent    *BastionAgent
	listener net.Listener
	addr     string
}

// NewHookServer 创建 Shell 审计服务端
func NewHookServer(agent *BastionAgent, addr string) *HookServer {
	if addr == "" {
		addr = "127.0.0.1:9099"
	}
	return &HookServer{
		agent: agent,
		addr:  addr,
	}
}

// Start 启动 Socket 监听，接收 Bash / Zsh 或 PAM 审计插件的实时拦截查询
func (s *HookServer) Start(ctx context.Context) error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to bind bastion hook socket on %s: %w", s.addr, err)
	}
	s.listener = l
	logger.Info("AlinkSec Bastion 4A Shell Audit Hook Server listening", "addr", s.addr)

	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go s.handleConn(conn)
	}
}

// handleConn 协议格式:
// 客户端发送: USER <user>\nSESSION <session_id>\nCMD <command>\n
// 服务端返回: ALLOW\n 或 BLOCK <rule_id> <description>\n
func (s *HookServer) handleConn(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	var user, sessionID, cmd string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "USER ") {
			user = strings.TrimPrefix(line, "USER ")
		} else if strings.HasPrefix(line, "SESSION ") {
			sessionID = strings.TrimPrefix(line, "SESSION ")
		} else if strings.HasPrefix(line, "CMD ") {
			cmd = strings.TrimPrefix(line, "CMD ")
			break
		}
	}

	if cmd == "" {
		_, _ = fmt.Fprintln(conn, "ERROR EMPTY_COMMAND")
		return
	}

	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-local-%s", user)
	}

	// 评估指令安全性
	result := s.agent.engine.CheckCommand(cmd)
	if !result.Allowed {
		ruleID := "CMD-BLOCK"
		ruleDesc := result.Reason
		if result.MatchedRule != nil {
			ruleID = result.MatchedRule.RuleID
			ruleDesc = result.MatchedRule.Description
		}

		logger.Warn("Bastion 4A Intercepted High-Risk Command",
			"user", user,
			"session", sessionID,
			"cmd", cmd,
			"rule_id", ruleID,
		)
		_, _ = fmt.Fprintf(conn, "BLOCK %s %s\n", ruleID, ruleDesc)
	} else {
		_, _ = fmt.Fprintln(conn, "ALLOW")
	}
}
