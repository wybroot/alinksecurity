package gm

import (
	"bytes"
	"testing"
	"time"
)

func TestSM3AndChain(t *testing.T) {
	msg := []byte("等保2.0三级国密SM3合规测试")
	h1 := SM3Sum(msg)
	h2 := SM3Sum(msg)
	if h1 != h2 {
		t.Fatalf("expected identical SM3 hash, got %s and %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h1))
	}

	// 测试 SM3 防篡改链
	now := time.Now().Unix()
	b0 := SM3ChainBlock{
		Index:        0,
		Timestamp:    now,
		Payload:      "GENESIS_BLOCK",
		PreviousHash: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	b0.CurrentHash = CalculateSM3BlockHash(b0.PreviousHash, b0.Payload, b0.Timestamp)

	b1 := SM3ChainBlock{
		Index:        1,
		Timestamp:    now + 1,
		Payload:      "ADMIN_LOGIN_SUCCESS",
		PreviousHash: b0.CurrentHash,
	}
	b1.CurrentHash = CalculateSM3BlockHash(b1.PreviousHash, b1.Payload, b1.Timestamp)

	chain := []SM3ChainBlock{b0, b1}
	valid, badIdx := VerifySM3Chain(chain)
	if !valid || badIdx != -1 {
		t.Fatalf("expected valid SM3 chain, got valid=%v, badIdx=%d", valid, badIdx)
	}

	// 模拟篡改
	chain[1].Payload = "HACKER_TAMPERED"
	valid, badIdx = VerifySM3Chain(chain)
	if valid || badIdx != 1 {
		t.Fatalf("expected tamper detected at index 1, got valid=%v, badIdx=%d", valid, badIdx)
	}
}

func TestSM4Encryption(t *testing.T) {
	key := []byte("1234567890123456") // 16 字节密钥
	plain := []byte("GB/T 22239-2019 S3A3G3 核心敏感配置数据: db_password=TopSecret@2026")

	cipherText, err := SM4EncryptCBC(key, plain)
	if err != nil {
		t.Fatalf("SM4 encrypt failed: %v", err)
	}
	if bytes.Equal(cipherText, plain) {
		t.Fatalf("ciphertext equals plaintext")
	}

	decrypted, err := SM4DecryptCBC(key, cipherText)
	if err != nil {
		t.Fatalf("SM4 decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plain) {
		t.Fatalf("expected decrypted %s, got %s", string(plain), string(decrypted))
	}

	// 错误密钥测试：即使偶发符合 padding，解密内容也绝不等于原明文
	wrongKey := []byte("6543210987654321")
	wrongDec, err := SM4DecryptCBC(wrongKey, cipherText)
	if err == nil && bytes.Equal(wrongDec, plain) {
		t.Fatalf("expected decryption failure or wrong content with wrong key, got identical plain")
	}
}

func TestSM2Signature(t *testing.T) {
	pair, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key pair failed: %v", err)
	}

	data := []byte("MLPS3_COMPLIANCE_EVIDENCE_DIGITAL_STAMP_2026")
	sig, err := SM2Sign(pair.PrivateKey, data)
	if err != nil {
		t.Fatalf("SM2 sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("expected non-empty signature, got 0")
	}

	// 验签通过
	if !SM2Verify(pair.PublicKey, data, sig) {
		t.Fatalf("expected SM2 signature verification to pass")
	}

	// 篡改数据验签失败
	tampered := []byte("MLPS3_COMPLIANCE_EVIDENCE_DIGITAL_STAMP_TAMPERED")
	if SM2Verify(pair.PublicKey, tampered, sig) {
		t.Fatalf("expected SM2 signature verification to fail on tampered data")
	}
}
