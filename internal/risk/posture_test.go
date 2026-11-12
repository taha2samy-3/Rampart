package risk_test

import (
	"testing"

	"rampart/internal/risk"
)

func TestCalculatePostureScore(t *testing.T) {
	// Clean slate -> 1000
	if got := risk.CalculatePostureScore(nil, 0, nil, 0); got != 1000 {
		t.Fatalf("clean slate: got %d, want 1000", got)
	}

	empty := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	if got := risk.CalculatePostureScore(empty, 5, nil, 0); got != 1000 {
		t.Fatalf("no open findings: got %d, want 1000", got)
	}

	// 1 critical on 1 asset -> 1000 - 250 = 750
	oneCrit := map[string]int{"critical": 1, "high": 0, "medium": 0, "low": 0}
	if got := risk.CalculatePostureScore(oneCrit, 1, nil, 0); got != 750 {
		t.Fatalf("one critical: got %d, want 750", got)
	}

	// SLA penalty test: adherence 50% -> (1 - 0.5) * 150 = 75 penalty
	adh50 := 0.5
	if got := risk.CalculatePostureScore(oneCrit, 1, &adh50, 0); got != 675 {
		t.Fatalf("with 50%% SLA: got %d, want 675", got)
	}

	// Coverage gaps test: 2 gaps -> 40 penalty
	if got := risk.CalculatePostureScore(oneCrit, 1, nil, 2); got != 710 {
		t.Fatalf("with 2 gaps: got %d, want 710", got)
	}

	// Clamping test: massive risk cannot go below 0
	manyCrit := map[string]int{"critical": 1000, "high": 500}
	adh0 := 0.0
	if got := risk.CalculatePostureScore(manyCrit, 1, &adh0, 10); got != 0 {
		t.Fatalf("floor clamped: got %d, want 0", got)
	}
}
