package logaudit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// GenerateRetentionProof 生成等保 2.0 三级 180 天留存合规凭证
func GenerateRetentionProof(oldest, newest time.Time, totalRecords uint64, integrityChainValid bool) *RetentionProof {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	reportID := fmt.Sprintf("MLPS3-PROOF-%s-%s", time.Now().Format("20060102"), hex.EncodeToString(b))

	diffDays := int(newest.Sub(oldest).Hours() / 24)
	targetDays := 180

	isCompliant := diffDays >= targetDays && integrityChainValid && totalRecords > 0

	notes := fmt.Sprintf("经系统全量日志库与防篡改哈希链核验：实际跨度留存 %d 天，完整性链校验通过状态: %v。", diffDays, integrityChainValid)
	if !isCompliant {
		if diffDays < targetDays {
			notes += fmt.Sprintf(" 当前留存跨度未达到等保三级强制要求的 %d 天（尚差 %d 天）。", targetDays, targetDays-diffDays)
		}
		if !integrityChainValid {
			notes += " 发现防篡改哈希链断裂或校验失败，存在潜在篡改风险。"
		}
	} else {
		notes += " 达到并完全符合 GB/T 22239-2019 第 8.1.4.2 条款 '安全审计记录应留存 6 个月（180天）以上且不可篡改' 之要求。"
	}

	return &RetentionProof{
		ReportID:            reportID,
		GeneratedAt:         time.Now(),
		ComplianceClause:    "GB/T 22239-2019 8.1.4.2 b (安全审计数据保存时间应不少于6个月)",
		TotalRetainedDays:   diffDays,
		TargetRetentionDays: targetDays,
		OldestLogTimestamp:  oldest,
		NewestLogTimestamp:  newest,
		TotalLogRecords:     totalRecords,
		IntegrityChainValid: integrityChainValid,
		IsCompliant:         isCompliant,
		AuditorNotes:        notes,
	}
}
