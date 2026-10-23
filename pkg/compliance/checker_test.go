package compliance

import (
	"strings"
	"testing"
)

func TestComplianceEvaluator(t *testing.T) {
	evaluator := NewEvaluator()
	report := evaluator.GenerateFullReport()

	if report == nil {
		t.Fatal("expected non-nil evaluation report")
	}

	if report.OverallScore < 95.0 {
		t.Fatalf("expected score >= 95.0 for standard configuration, got %.1f", report.OverallScore)
	}

	if report.ComplianceGrade != "优" {
		t.Fatalf("expected grade '优', got %s", report.ComplianceGrade)
	}

	if len(report.EvidenceHash) != 64 {
		t.Fatalf("expected 64 hex char SHA-256 evidence hash, got %d", len(report.EvidenceHash))
	}

	if report.CompliantItems != report.TotalItems {
		t.Fatalf("expected all items to be compliant, %d/%d", report.CompliantItems, report.TotalItems)
	}

	// 验证各维度得分
	domains := []string{"安全管理中心", "安全计算环境", "安全区域边界", "安全通信网络"}
	for _, d := range domains {
		score, ok := report.DomainScores[d]
		if !ok || score < 95.0 {
			t.Fatalf("domain %s missing or score < 95.0: %.1f", d, score)
		}
	}

	// 测试 Markdown 报表渲染
	md := evaluator.GenerateMarkdownReport(report)
	if !strings.Contains(md, "GB/T 22239-2019") {
		t.Fatalf("markdown report missing standard name")
	}
	if !strings.Contains(md, report.EvidenceHash) {
		t.Fatalf("markdown report missing evidence hash")
	}
}
