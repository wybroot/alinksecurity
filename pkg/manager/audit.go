package manager

import (
	"fmt"
	"sync"
	"time"

	"alinksec/pkg/auth"
	"alinksec/pkg/crypto"
)

// AdminAuditRecord 管理员操作审计记录 (等保合规要求 >= 365天留存)
type AdminAuditRecord struct {
	LogID          string    `json:"log_id"`
	AdminUser      string    `json:"admin_user"`
	Role           auth.Role `json:"role"`
	ClientIP       string    `json:"client_ip"`
	Action         string    `json:"action"`
	TargetResource string    `json:"target_resource"`
	RequestBody    string    `json:"request_body"`
	ResponseCode   int       `json:"response_code"`
	Status         string    `json:"status"` // "SUCCESS", "FAILED", "DENIED"
	CreatedAt      time.Time `json:"created_at"`
	PrevHash       string    `json:"prev_hash"`
	LogHash        string    `json:"log_hash"`
}

// AuditTrail 内存及持久化审计链管理器
type AuditTrail struct {
	mu       sync.RWMutex
	records  []AdminAuditRecord
	lastHash string
}

// NewAuditTrail 创建审计链管理器
func NewAuditTrail() *AuditTrail {
	return &AuditTrail{
		records:  make([]AdminAuditRecord, 0),
		lastHash: "0000000000000000000000000000000000000000000000000000000000000000",
	}
}

// Record 记录一次管理员审计事件并追加链式哈希
func (a *AuditTrail) Record(adminUser string, role auth.Role, clientIP, action, targetResource, requestBody string, code int, status string) AdminAuditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()

	logID, _ := crypto.GenerateSecureToken(16)
	now := time.Now()

	// 构造待哈希的防篡改凭据
	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%s|%d",
		logID, adminUser, role, clientIP, action, targetResource, code, status, now.UnixNano())

	// 链式哈希 H_n = SHA256(H_{n-1} + payload)
	currentHash := crypto.ComputeChainedHash(a.lastHash, []byte(payload))

	rec := AdminAuditRecord{
		LogID:          logID,
		AdminUser:      adminUser,
		Role:           role,
		ClientIP:       clientIP,
		Action:         action,
		TargetResource: targetResource,
		RequestBody:    requestBody,
		ResponseCode:   code,
		Status:         status,
		CreatedAt:      now,
		PrevHash:       a.lastHash,
		LogHash:        currentHash,
	}

	a.records = append(a.records, rec)
	a.lastHash = currentHash

	return rec
}

// VerifyIntegrity 全量核查审计链完整性，若有篡改立即返回篡改位置
func (a *AuditTrail) VerifyIntegrity() (bool, int, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	expectedPrev := "0000000000000000000000000000000000000000000000000000000000000000"
	for idx, rec := range a.records {
		if rec.PrevHash != expectedPrev {
			return false, idx, fmt.Errorf("integrity violation at index %d: prev_hash broken", idx)
		}

		payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%s|%d",
			rec.LogID, rec.AdminUser, rec.Role, rec.ClientIP, rec.Action, rec.TargetResource, rec.ResponseCode, rec.Status, rec.CreatedAt.UnixNano())

		computedHash := crypto.ComputeChainedHash(expectedPrev, []byte(payload))
		if computedHash != rec.LogHash {
			return false, idx, fmt.Errorf("integrity violation at index %d: log_hash mismatch (tamper detected)", idx)
		}

		expectedPrev = rec.LogHash
	}

	return true, -1, nil
}

// GetAllRecords 获取所有审计日志 (仅供审计管理员 audit_admin 调阅)
func (a *AuditTrail) GetAllRecords() []AdminAuditRecord {
	a.mu.RLock()
	defer a.mu.RUnlock()
	res := make([]AdminAuditRecord, len(a.records))
	copy(res, a.records)
	return res
}
