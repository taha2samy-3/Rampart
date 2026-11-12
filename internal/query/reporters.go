package query

import (
	"sort"
	"time"

	"github.com/google/uuid"

	"rampart/internal/domain"
)

// Reporter is one tool's view of a finding: the occurrences of that tool folded into a line the finding
// panel can show ("Trivy 0.58, first reported 3 Nov, last 11 Nov, 9 reports, still reporting").
// Several scan sources can feed the same tool; they are folded together.
type Reporter struct {
	Scanner      string    `json:"scanner"` // the family: trivy, grype, semgrep
	Name         string    `json:"name"`
	Version      string    `json:"version,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Reports      int       `json:"reports"`       // how many scans of this tool saw it
	Present      bool      `json:"present"`       // the latest scan of this tool still reports it
	ToolSeverity string    `json:"tool_severity"` // what the tool itself said, before any override
	LatestRunID  uuid.UUID `json:"latest_run_id"`
	Locations    int       `json:"locations"` // distinct occurrences of this tool
}

// reportersOf folds occurrences by tool family. The tool that reported first comes first, so the list
// reads as "found by Trivy, later confirmed by Grype".
func reportersOf(occs []*domain.Occurrence) []Reporter {
	by := map[string]*Reporter{}
	var order []string
	for _, o := range occs {
		r, ok := by[o.ScannerFamily]
		if !ok {
			r = &Reporter{Scanner: o.ScannerFamily, FirstSeen: o.FirstSeen}
			by[o.ScannerFamily] = r
			order = append(order, o.ScannerFamily)
		}
		if o.FirstSeen.Before(r.FirstSeen) {
			r.FirstSeen = o.FirstSeen
		}
		if !o.LastSeen.Before(r.LastSeen) {
			r.LastSeen, r.Name, r.Version, r.ToolSeverity, r.LatestRunID = o.LastSeen, o.ScannerName, o.ScannerVersion, o.ToolSeverity, o.IngestRunID
		}
		r.Reports += o.SeenCount
		r.Locations++
		r.Present = r.Present || o.Present
	}
	out := make([]Reporter, 0, len(order))
	for _, k := range order {
		out = append(out, *by[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].FirstSeen.Before(out[j].FirstSeen) })
	return out
}
