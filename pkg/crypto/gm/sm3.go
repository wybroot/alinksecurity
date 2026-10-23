package gm

import (
	"encoding/hex"
	"fmt"

	"github.com/tjfoc/gmsm/sm3"
)

// SM3Sum 计算数据的国密 SM3 256 位杂凑值（十六进制格式）
func SM3Sum(data []byte) string {
	h := sm3.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// SM3SumBytes 计算数据的国密 SM3 字节摘要
func SM3SumBytes(data []byte) []byte {
	h := sm3.New()
	h.Write(data)
	return h.Sum(nil)
}

// SM3ChainBlock 国密 SM3 链式防篡改结构
type SM3ChainBlock struct {
	Index        int64  `json:"index"`
	Timestamp    int64  `json:"timestamp"`
	Payload      string `json:"payload"`
	PreviousHash string `json:"previous_hash"`
	CurrentHash  string `json:"current_hash"`
}

// CalculateSM3BlockHash 根据上一区块哈希与当前负载计算当前区块 SM3
func CalculateSM3BlockHash(prevHash string, payload string, timestamp int64) string {
	content := fmt.Sprintf("%s|%d|%s", prevHash, timestamp, payload)
	return SM3Sum([]byte(content))
}

// VerifySM3Chain 验证国密 SM3 区块链完整性
func VerifySM3Chain(blocks []SM3ChainBlock) (bool, int) {
	for i, b := range blocks {
		expected := CalculateSM3BlockHash(b.PreviousHash, b.Payload, b.Timestamp)
		if expected != b.CurrentHash {
			return false, i
		}
		if i > 0 && b.PreviousHash != blocks[i-1].CurrentHash {
			return false, i
		}
	}
	return true, -1
}
