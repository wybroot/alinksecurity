package simulator

import (
	"testing"
)

func TestSimulationRunner(t *testing.T) {
	runner := NewRunner()
	report := runner.RunFullDrill()

	if report.TotalScenarios != 8 {
		t.Fatalf("Expected 8 scenarios, got %d", report.TotalScenarios)
	}

	if report.SuccessfulBlocks != 8 {
		t.Errorf("Expected 8/8 successful blocks/auto-heals, got %d", report.SuccessfulBlocks)
	}

	if report.InterceptionRate < 100.0 {
		t.Errorf("Expected 100%% interception rate, got %.1f%%", report.InterceptionRate)
	}

	if report.OverallVerdict != "PASS" {
		t.Errorf("Expected overall verdict PASS, got %s", report.OverallVerdict)
	}

	if report.ReportHash == "" {
		t.Errorf("Report hash must not be empty")
	}

	for _, res := range report.Results {
		if !res.Success {
			t.Errorf("Scenario %s (%s) failed to intercept: %s", res.Scenario.ID, res.Scenario.Name, res.InterceptReason)
		}
	}
}
