package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// SHA256String 计算字符串的 SHA-256 哈希
func SHA256String(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// SHA256Bytes 计算字节切片的 SHA-256 哈希
func SHA256Bytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ComputeChainedHash 计算区块链式防篡改链式哈希: H_n = SHA256(H_{n-1} + raw_data)
func ComputeChainedHash(previousHash string, currentPayload []byte) string {
	h := sha256.New()
	if previousHash != "" {
		h.Write([]byte(previousHash))
	}
	h.Write(currentPayload)
	return hex.EncodeToString(h.Sum(nil))
}

// GenerateSecureToken 生成密码学安全的随机 Hex Token
func GenerateSecureToken(byteLength int) (string, error) {
	if byteLength <= 0 {
		byteLength = 32
	}
	buf := make([]byte, byteLength)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
