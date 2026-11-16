package domain

import (
	"strings"
	"testing"
	"time"
)

// D92: the ScanSource's dependencyTrack block accepts what is built and refuses, by name, what is not.
func TestParseDTrackSourceSpec(t *testing.T) {
	s, err := ParseDTrackSourceSpec([]byte(`{"projects":{"onlyActive":true,"tags":["team"],"nameRegex":"^pay","classifiers":["APPLICATION"],"versions":"latest"},
		"mapping":{"tagPrefix":"app:","rules":[{"when":"project.name.startsWith(\"pay\")","application":"payments"}],"defaultApplication":""},
		"pull":{"findings":true,"includeSuppressed":true},"webhook":{"enabled":true},"triageSync":{"mode":"import","trustUpstreamDecisions":false}}`))
	if err != nil || s.Versions() != "latest" || !s.Webhook.Enabled || s.TriageMode() != "import" {
		t.Fatalf("%+v %v", s, err)
	}
	refused := map[string]string{
		`{"pull":{"policyViolations":true}}`:                   "policyViolations",
		`{"sbomForwarding":{"enabled":true}}`:                  "sbomForwarding",
		`{"webhook":{"manage":true}}`:                          "manage",
		`{"triageSync":{"mode":"bidirectional"}}`:              "bidirectional",
		`{"projects":{"versions":"some"}}`:                     "versions",
		`{"projects":{"nameRegex":"("}}`:                       "nameRegex",
		`{"projects":{"classifiers":["SPACESHIP"]}}`:           "classifier",
		`{"mapping":{"rules":[{"when":"","application":""}]}}`: "rules[0]",
		`{"pull":{"findings":false}}`:                          "findings",
		`{"unknownField":1}`:                                   "unknown",
	}
	for spec, want := range refused {
		if _, err := ParseDTrackSourceSpec([]byte(spec)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want an error naming %q, got %v", spec, want, err)
		}
	}
	for in, want := range map[string]time.Duration{"": 30 * time.Minute, "45m": 45 * time.Minute, "*/15 * * * *": 15 * time.Minute} {
		if d, err := ParseDTrackSchedule(in); err != nil || d != want {
			t.Errorf("schedule %q: %v %v", in, d, err)
		}
	}
	for _, bad := range []string{"1m", "0 3 * * *", "soon"} {
		if _, err := ParseDTrackSchedule(bad); err == nil {
			t.Errorf("schedule %q must be refused", bad)
		}
	}
	if _, _, _, err := (DTrackSourceInput{Schedule: "30m"}).Check(); err == nil {
		t.Error("a schedule without a connector is refused")
	}
	if _, _, ok, err := (DTrackSourceInput{Connector: "dtrack", Type: "upload"}).Check(); !ok || err == nil {
		t.Error("a connector on a non-apiPull source is refused")
	}
}
