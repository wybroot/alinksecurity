package bastion

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// SessionCommandRecord 运维指令单条审计记录
type SessionCommandRecord struct {
	Index        int64            `json:"index"`
	Command      string           `json:"command"`
	Action       BlockAction      `json:"action"`
	RiskLevel    CommandRiskLevel `json:"risk_level"`
	RuleID       string           `json:"rule_id,omitempty"`
	Timestamp    int64            `json:"timestamp"`
	PreviousHash string           `json:"previous_hash"`
	CurrentHash  string           `json:"current_hash"`
}

// Session 4A 运维审计会话
type Session struct {
	SessionID   string                  `json:"session_id"`
	Username    string                  `json:"username"`
	ClientIP    string                  `json:"client_ip"`
	TargetHost  string                  `json:"target_host"`
	TargetUser  string                  `json:"target_user"`
	Protocol    string                  `json:"protocol"` // SSH, RDP, TELNET
	StartTime   int64                   `json:"start_time"`
	EndTime     int64                   `json:"end_time"`
	Status      string                  `json:"status"` // ACTIVE, CLOSED, TERMINATED
	TotalCmds   int64                   `json:"total_commands"`
	BlockedCmds int64                   `json:"blocked_commands"`
	LastHash    string                  `json:"last_hash"`
	Commands    []*SessionCommandRecord `json:"commands"`
	mu          sync.RWMutex
}

// SessionCertificate 会话等保合规存证证书
type SessionCertificate struct {
	CertificateID string `json:"certificate_id"`
	SessionID     string `json:"session_id"`
	Username      string `json:"username"`
	TargetHost    string `json:"target_host"`
	TotalCommands int64  `json:"total_commands"`
	BlockedCount  int64  `json:"blocked_count"`
	FinalHash     string `json:"final_hash"`
	IntegrityPass bool   `json:"integrity_pass"`
	GeneratedAt   int64  `json:"generated_at"`
	Standard      string `json:"standard"`
}

// NewSession 创建新运维审计会话
func NewSession(sessionID, username, clientIP, targetHost, targetUser, protocol string) *Session {
	initialHash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%d", sessionID, username, targetHost, time.Now().UnixNano())))
	genesisHash := hex.EncodeToString(initialHash[:])

	return &Session{
		SessionID:   sessionID,
		Username:    username,
		ClientIP:    clientIP,
		TargetHost:  targetHost,
		TargetUser:  targetUser,
		Protocol:    protocol,
		StartTime:   time.Now().Unix(),
		Status:      "ACTIVE",
		TotalCmds:   0,
		BlockedCmds: 0,
		LastHash:    genesisHash,
		Commands:    make([]*SessionCommandRecord, 0),
	}
}

// RecordCommand 记录一条指令并执行防篡改哈希上链
func (s *Session) RecordCommand(cmd string, res *CommandCheckResult) *SessionCommandRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.TotalCmds++
	if !res.Allowed {
		s.BlockedCmds++
	}

	prevHash := s.LastHash
	ruleID := ""
	if res.MatchedRule != nil {
		ruleID = res.MatchedRule.RuleID
	}

	payload := fmt.Sprintf("%d:%s:%s:%s:%s:%d:%s",
		s.TotalCmds, cmd, res.Action, res.RiskLevel, ruleID, res.Timestamp, prevHash)
	sum := sha256.Sum256([]byte(payload))
	currHash := hex.EncodeToString(sum[:])

	record := &SessionCommandRecord{
		Index:        s.TotalCmds,
		Command:      cmd,
		Action:       res.Action,
		RiskLevel:    res.RiskLevel,
		RuleID:       ruleID,
		Timestamp:    res.Timestamp,
		PreviousHash: prevHash,
		CurrentHash:  currHash,
	}

	s.Commands = append(s.Commands, record)
	s.LastHash = currHash
	return record
}

// Close 关闭会话
func (s *Session) Close(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.EndTime = time.Now().Unix()
	s.Status = reason
}

// VerifyIntegrity 验证整条会话所有指令日志链是否被篡改
func (s *Session) VerifyIntegrity() (bool, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.Commands) == 0 {
		return true, 0
	}

	for i, rec := range s.Commands {
		var expectedPrev string
		if i == 0 {
			expectedPrev = rec.PreviousHash
		} else {
			expectedPrev = s.Commands[i-1].CurrentHash
		}

		if rec.PreviousHash != expectedPrev {
			return false, i
		}

		payload := fmt.Sprintf("%d:%s:%s:%s:%s:%d:%s",
			rec.Index, rec.Command, rec.Action, rec.RiskLevel, rec.RuleID, rec.Timestamp, rec.PreviousHash)
		sum := sha256.Sum256([]byte(payload))
		recalculated := hex.EncodeToString(sum[:])
		if recalculated != rec.CurrentHash {
			return false, i
		}
	}

	return true, len(s.Commands)
}

// GenerateCertificate 导出等保合规电子存证凭证
func (s *Session) GenerateCertificate() *SessionCertificate {
	valid, _ := s.VerifyIntegrity()
	s.mu.RLock()
	defer s.mu.RUnlock()

	certIDBytes := sha256.Sum256([]byte(fmt.Sprintf("CERT:%s:%s:%d", s.SessionID, s.LastHash, time.Now().UnixNano())))
	certID := "CERT-BASTION-" + hex.EncodeToString(certIDBytes[:8])

	return &SessionCertificate{
		CertificateID: certID,
		SessionID:     s.SessionID,
		Username:      s.Username,
		TargetHost:    s.TargetHost,
		TotalCommands: s.TotalCmds,
		BlockedCount:  s.BlockedCmds,
		FinalHash:     s.LastHash,
		IntegrityPass: valid,
		GeneratedAt:   time.Now().Unix(),
		Standard:      "GB/T 22239-2019 第三级 (S3A3G3) 8.1.4.2 安全审计要求",
	}
}

// SessionManager 运维会话管理器
type SessionManager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewSessionManager 初始化
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
	}
}

// AddSession 添加会话
func (sm *SessionManager) AddSession(s *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[s.SessionID] = s
}

// GetSession 获取会话
func (sm *SessionManager) GetSession(id string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.sessions[id]
	return s, ok
}

// ListSessions 获取全部会话
func (sm *SessionManager) ListSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	list := make([]*Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		list = append(list, s)
	}
	return list
}
