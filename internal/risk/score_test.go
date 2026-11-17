package risk_test

import (
	"testing"
	"time"

	"rampart/internal/domain"
	"rampart/internal/risk"
)

func TestCalculateSLADueDate(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if due := risk.CalculateSLADueDate(domain.SeverityCritical, "critical", start, nil); !due.Equal(start.AddDate(0, 0, 3)) {
		t.Fatalf("critical on a critical application: %v", due)
	}
	if due := risk.CalculateSLADueDate(domain.SeverityCritical, "low", start, nil); !due.Equal(start.AddDate(0, 0, 30)) {
		t.Fatalf("critical on a low application: %v", due)
	}
	kev := start.AddDate(0, 0, 2)
	if due := risk.CalculateSLADueDate(domain.SeverityCritical, "critical", start, &kev); !due.Equal(kev.Add(24 * time.Hour)) {
		t.Fatalf("an earlier CISA due date wins, and it is due by the end of that day: %v", due)
	}
	late := start.AddDate(0, 0, 3) // CISA's day is the same day as the matrix allowance: the later of the two does not win
	if due := risk.CalculateSLADueDate(domain.SeverityCritical, "critical", start, &late); !due.Equal(start.AddDate(0, 0, 3)) {
		t.Fatalf("the matrix wins when CISA's end of day is not earlier: %v", due)
	}
}
