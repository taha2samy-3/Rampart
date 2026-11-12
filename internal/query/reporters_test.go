package query

import (
	"testing"
	"time"

	"rampart/internal/domain"
)

func TestReportersOfFoldsByToolInOrderOfFirstReport(t *testing.T) {
	d := func(day int) time.Time { return time.Date(2026, 11, day, 0, 0, 0, 0, time.UTC) }
	occs := []*domain.Occurrence{
		{ScannerFamily: "grype", ScannerName: "grype", ScannerVersion: "0.80", FirstSeen: d(5), LastSeen: d(9), SeenCount: 3, Present: false, ToolSeverity: "high"},
		{ScannerFamily: "trivy", ScannerName: "trivy", ScannerVersion: "0.57", FirstSeen: d(1), LastSeen: d(4), SeenCount: 2, Present: true, ToolSeverity: "critical"},
		{ScannerFamily: "trivy", ScannerName: "trivy", ScannerVersion: "0.58", FirstSeen: d(2), LastSeen: d(11), SeenCount: 6, Present: true, ToolSeverity: "critical"},
	}
	got := reportersOf(occs)
	if len(got) != 2 || got[0].Scanner != "trivy" || got[1].Scanner != "grype" {
		t.Fatalf("order/fold = %+v", got)
	}
	tr := got[0]
	if tr.Reports != 8 || tr.Locations != 2 || !tr.Present || tr.Version != "0.58" || !tr.FirstSeen.Equal(d(1)) || !tr.LastSeen.Equal(d(11)) {
		t.Fatalf("trivy = %+v", tr)
	}
	if got[1].Present {
		t.Fatalf("grype stopped reporting but is shown as present: %+v", got[1])
	}
	if reportersOf(nil) == nil {
		t.Fatal("an empty list must be [] in JSON, not null")
	}
}
