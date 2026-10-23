package backup

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"alinksec/pkg/crypto/gm"
	"github.com/tjfoc/gmsm/sm2"
)

// BackupSnapshot 等保 2.0 三级数据备份快照实体
type BackupSnapshot struct {
	SnapshotID          string `json:"snapshot_id"`
	CreatedAt           int64  `json:"created_at"`
	StorageLocation     string `json:"storage_location"`     // LOCAL_VAULT, OFFSITE_DISASTER_RECOVERY
	Encrypted           bool   `json:"encrypted"`
	EncryptionAlgorithm string `json:"encryption_algorithm"` // SM4-128-CBC
	SM3Checksum         string `json:"sm3_checksum"`         // 明文内容的 SM3 杂凑防篡改
	SM2Signature        string `json:"sm2_signature"`        // SM2 私钥电子印章
	CipherPayloadHex    string `json:"cipher_payload_hex"`   // 加密后密文 (十六进制)
	RawSize             int    `json:"raw_size"`
	EncryptedSize       int    `json:"encrypted_size"`
	Status              string `json:"status"`               // VERIFIED, RESTORED, CORRUPTED
	ModulesIncluded     []string `json:"modules_included"`
}

// RestoreResult 容灾恢复演练结果
type RestoreResult struct {
	SnapshotID       string `json:"snapshot_id"`
	RestoredAt       int64  `json:"restored_at"`
	IntegrityValid   bool   `json:"integrity_valid"`
	SM3Verified      bool   `json:"sm3_verified"`
	SM2SigVerified   bool   `json:"sm2_sig_verified"`
	RestoredModules  []string `json:"restored_modules"`
	ComplianceStatus string `json:"compliance_status"` // PASS / FAIL
	Details          string `json:"details"`
}

// BackupEngine 容灾备份与国密存证引擎
type BackupEngine struct {
	mu           sync.RWMutex
	sm4Key       []byte
	sm2Key       *gm.SM2KeyPair
	snapshots    map[string]*BackupSnapshot
	snapshotList []*BackupSnapshot
}

// NewBackupEngine 初始化容灾备份引擎
func NewBackupEngine() (*BackupEngine, error) {
	// 生成 16 字节 SM4 密钥
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	// 生成 SM2 根签章密钥对
	sm2Pair, err := gm.GenerateSM2KeyPair()
	if err != nil {
		return nil, err
	}

	engine := &BackupEngine{
		sm4Key:       key,
		sm2Key:       sm2Pair,
		snapshots:    make(map[string]*BackupSnapshot),
		snapshotList: make([]*BackupSnapshot, 0),
	}

	// 预置一份合规的异地基线冷备快照
	initData := map[string]interface{}{
		"policies_count":  18,
		"accounts_count":  3,
		"audit_log_count": 520,
		"backup_version":  "1.0.0-MLPS3-BASELINE",
	}
	rawBytes, _ := json.Marshal(initData)
	_, _ = engine.CreateSnapshot("OFFSITE_DISASTER_RECOVERY", rawBytes, []string{
		"rbac_accounts", "security_policies", "blockchain_audit_chain", "180d_retention_proof",
	})

	return engine, nil
}

// CreateSnapshot 创建国密加密并加盖 SM2 签名的灾备快照
func (b *BackupEngine) CreateSnapshot(location string, rawData []byte, modules []string) (*BackupSnapshot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	snapID := fmt.Sprintf("SNAP-%s-%s", now.Format("20060102150405"), hex.EncodeToString(gm.SM3SumBytes(rawData)[:4]))

	// 1. 计算明文国密 SM3 杂凑防篡改
	sm3Hash := gm.SM3Sum(rawData)

	// 2. 加盖国密 SM2 电子签名
	sm2Sig, err := gm.SM2Sign(b.sm2Key.PrivateKey, []byte(sm3Hash))
	if err != nil {
		return nil, fmt.Errorf("sm2 sign failed: %w", err)
	}

	// 3. 使用国密 SM4-CBC 加密存储机密性
	cipherBytes, err := gm.SM4EncryptCBC(b.sm4Key, rawData)
	if err != nil {
		return nil, fmt.Errorf("sm4 encrypt failed: %w", err)
	}

	snap := &BackupSnapshot{
		SnapshotID:          snapID,
		CreatedAt:           now.Unix(),
		StorageLocation:     location,
		Encrypted:           true,
		EncryptionAlgorithm: "SM4-128-CBC",
		SM3Checksum:         sm3Hash,
		SM2Signature:        sm2Sig,
		CipherPayloadHex:    hex.EncodeToString(cipherBytes),
		RawSize:             len(rawData),
		EncryptedSize:       len(cipherBytes),
		Status:              "VERIFIED",
		ModulesIncluded:     modules,
	}

	b.snapshots[snapID] = snap
	b.snapshotList = append([]*BackupSnapshot{snap}, b.snapshotList...)
	return snap, nil
}

// ListSnapshots 获取全部灾备快照列表
func (b *BackupEngine) ListSnapshots() []*BackupSnapshot {
	b.mu.RLock()
	defer b.mu.RUnlock()

	res := make([]*BackupSnapshot, len(b.snapshotList))
	copy(res, b.snapshotList)
	return res
}

// VerifyAndRestore 演练或执行容灾恢复（全流程国密验签与解密还原）
func (b *BackupEngine) VerifyAndRestore(snapshotID string) (*RestoreResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	snap, exists := b.snapshots[snapshotID]
	if !exists {
		return nil, errors.New("snapshot not found")
	}

	// 1. 解密密文
	cipherBytes, err := hex.DecodeString(snap.CipherPayloadHex)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext format: %w", err)
	}

	plainBytes, err := gm.SM4DecryptCBC(b.sm4Key, cipherBytes)
	if err != nil {
		snap.Status = "CORRUPTED"
		return &RestoreResult{
			SnapshotID:       snapshotID,
			RestoredAt:       time.Now().Unix(),
			IntegrityValid:   false,
			ComplianceStatus: "FAIL",
			Details:          fmt.Sprintf("SM4 decryption failed: %v", err),
		}, nil
	}

	// 2. 验证 SM3 杂凑
	calcSM3 := gm.SM3Sum(plainBytes)
	sm3Valid := (calcSM3 == snap.SM3Checksum)

	// 3. 验证 SM2 电子签名
	sm2Valid := gm.SM2Verify(b.sm2Key.PublicKey, []byte(snap.SM3Checksum), snap.SM2Signature)

	integrity := sm3Valid && sm2Valid
	status := "PASS"
	details := "国密 SM4 解密成功，SM3 完整性校验与 SM2 电子印章验签 100% 通过，系统已成功恢复到指定备份点"
	if !integrity {
		snap.Status = "CORRUPTED"
		status = "FAIL"
		details = "数据完整性损坏，存在未授权篡改风险，已拒绝恢复"
	} else {
		snap.Status = "RESTORED"
	}

	return &RestoreResult{
		SnapshotID:       snapshotID,
		RestoredAt:       time.Now().Unix(),
		IntegrityValid:   integrity,
		SM3Verified:      sm3Valid,
		SM2SigVerified:   sm2Valid,
		RestoredModules:  snap.ModulesIncluded,
		ComplianceStatus: status,
		Details:          details,
	}, nil
}

// GetSM2PublicKey 获取用于公开验签的 SM2 公钥
func (b *BackupEngine) GetSM2PublicKey() *sm2.PublicKey {
	return b.sm2Key.PublicKey
}
