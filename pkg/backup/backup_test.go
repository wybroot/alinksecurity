package backup

import (
	"encoding/json"
	"testing"
)

func TestBackupAndRestoreFlow(t *testing.T) {
	engine, err := NewBackupEngine()
	if err != nil {
		t.Fatalf("failed to init backup engine: %v", err)
	}

	// 1. 创建快照
	sampleData := map[string]interface{}{
		"system": "alinksec",
		"policies": []string{"waf-rule-1", "cfw-zone-crossing", "edr-baseline"},
		"timestamp": 1729780000,
	}
	rawBytes, _ := json.Marshal(sampleData)

	snap, err := engine.CreateSnapshot("LOCAL_VAULT", rawBytes, []string{"security_policies", "system_state"})
	if err != nil {
		t.Fatalf("create snapshot failed: %v", err)
	}

	if !snap.Encrypted || snap.EncryptionAlgorithm != "SM4-128-CBC" {
		t.Fatalf("expected SM4-128-CBC encryption")
	}
	if len(snap.SM3Checksum) != 64 {
		t.Fatalf("expected 64 chars SM3 checksum, got %d", len(snap.SM3Checksum))
	}
	if len(snap.SM2Signature) == 0 {
		t.Fatalf("expected non-empty SM2 digital signature")
	}

	// 2. 验证恢复演练
	res, err := engine.VerifyAndRestore(snap.SnapshotID)
	if err != nil {
		t.Fatalf("verify and restore failed: %v", err)
	}
	if !res.IntegrityValid || !res.SM3Verified || !res.SM2SigVerified {
		t.Fatalf("expected all integrity checks to pass, got %+v", res)
	}
	if res.ComplianceStatus != "PASS" {
		t.Fatalf("expected PASS status, got %s", res.ComplianceStatus)
	}

	// 3. 模拟篡改测试
	snap.CipherPayloadHex = "00112233445566778899aabbccddeeff"
	resTampered, err := engine.VerifyAndRestore(snap.SnapshotID)
	if err != nil {
		t.Fatalf("unexpected error during tampered restore: %v", err)
	}
	if resTampered.ComplianceStatus != "FAIL" {
		t.Fatalf("expected FAIL status on tampered payload, got %s", resTampered.ComplianceStatus)
	}
}
