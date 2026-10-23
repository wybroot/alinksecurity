package alert

import (
	"testing"
	"time"
)

func TestAlertDispatcher(t *testing.T) {
	// Initialize with a short 2-second window for testing
	d := NewDispatcher(2 * time.Second)

	// 1. Initial seeded aggregations
	aggregations := d.ListAggregations()
	if len(aggregations) < 2 {
		t.Fatalf("expected at least 2 seeded aggregations, got %d", len(aggregations))
	}

	// 2. Test IngestEvent - first time should dispatch
	agg1, dispatched := d.IngestEvent("1.2.3.4", "WAF", "SQL_INJECTION", "CRITICAL", "union select attack")
	if !dispatched {
		t.Fatal("expected first event to be dispatched")
	}
	if agg1.Occurrences != 1 || agg1.SuppressedCnt != 0 {
		t.Fatalf("unexpected agg state: occurrences=%d, suppressed=%d", agg1.Occurrences, agg1.SuppressedCnt)
	}

	// 3. Test IngestEvent - same key within window should be suppressed
	agg2, dispatched2 := d.IngestEvent("1.2.3.4", "WAF", "SQL_INJECTION", "CRITICAL", "union select attack repeated")
	if dispatched2 {
		t.Fatal("expected second event to be suppressed within window")
	}
	if agg2.Occurrences != 2 || agg2.SuppressedCnt != 1 {
		t.Fatalf("expected 2 occurrences and 1 suppressed, got occ=%d, sup=%d", agg2.Occurrences, agg2.SuppressedCnt)
	}

	// 4. Test channels
	channels := d.ListChannels()
	if len(channels) < 4 {
		t.Fatalf("expected at least 4 channels, got %d", len(channels))
	}

	// 5. Test channel toggle
	err := d.ToggleChannel("CH-FEISHU", true)
	if err != nil {
		t.Fatalf("failed to toggle channel: %v", err)
	}

	// 6. Test channel test message
	msg, err := d.TestChannel("CH-FEISHU")
	if err != nil || msg == "" {
		t.Fatalf("failed to test channel: %v", err)
	}

	// 7. Test Stats
	stats := d.GetStats()
	if stats.NoiseReductionRate <= 0.0 {
		t.Fatalf("expected positive noise reduction rate, got %f", stats.NoiseReductionRate)
	}
	if stats.ActiveChannels < 3 {
		t.Fatalf("expected at least 3 active channels, got %d", stats.ActiveChannels)
	}
}
