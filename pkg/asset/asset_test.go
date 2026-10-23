package asset

import (
	"testing"
)

func TestAssetManager(t *testing.T) {
	mgr := NewManager()

	// 1. Check default seeded assets
	assets := mgr.ListAssets("", "")
	if len(assets) < 5 {
		t.Fatalf("expected at least 5 default assets, got %d", len(assets))
	}

	// 2. Zone filtering
	dmzAssets := mgr.ListAssets("DMZ", "")
	if len(dmzAssets) != 1 {
		t.Fatalf("expected 1 DMZ asset, got %d", len(dmzAssets))
	}

	// 3. Criticality filtering
	tier1Assets := mgr.ListAssets("", string(Tier1Critical))
	if len(tier1Assets) != 3 {
		t.Fatalf("expected 3 Tier 1 assets, got %d", len(tier1Assets))
	}

	// 4. Register new asset
	newAsset := &Asset{
		ID:              "AST-999",
		Hostname:        "test-edge-router.local",
		IP:              "192.168.10.1",
		Zone:            ZoneDMZ,
		Criticality:     Tier2Important,
		Owner:           "网络组",
		ProbesInstalled: []string{"CFW"},
	}
	if err := mgr.RegisterOrUpdate(newAsset); err != nil {
		t.Fatalf("failed to register asset: %v", err)
	}

	found, err := mgr.GetAssetByID("AST-999")
	if err != nil || found.Hostname != "test-edge-router.local" {
		t.Fatalf("failed to retrieve registered asset: %v", err)
	}

	// 5. Update classification
	err = mgr.UpdateClassification("AST-999", ZoneMGMT, Tier1Critical, "审计主管")
	if err != nil {
		t.Fatalf("failed to update classification: %v", err)
	}
	updated, _ := mgr.GetAssetByID("AST-999")
	if updated.Zone != ZoneMGMT || updated.Criticality != Tier1Critical || updated.Owner != "审计主管" {
		t.Fatalf("unexpected updated asset fields: %+v", updated)
	}

	// 6. Test Stats
	stats := mgr.GetStats()
	if stats.TotalAssets != 6 {
		t.Fatalf("expected 6 total assets, got %d", stats.TotalAssets)
	}
	if stats.Tier1CriticalCount < 3 {
		t.Fatalf("unexpected Tier 1 count: %d", stats.Tier1CriticalCount)
	}
	if stats.AvgComplianceScore < 90.0 {
		t.Fatalf("unexpected avg compliance score: %f", stats.AvgComplianceScore)
	}
}
