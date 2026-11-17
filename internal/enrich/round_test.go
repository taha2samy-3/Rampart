package enrich

import (
	"errors"
	"strings"
	"testing"
)

func TestSummarize(t *testing.T) {
	title, body, failed := Summarize([]FeedResult{{Feed: "first_epss", Records: 407165}, {Feed: "cisa_kev", Records: 1781}})
	if failed || title != "Vulnerability feeds synced: CISA KEV, FIRST EPSS" || !strings.Contains(body, "CISA KEV: 1781 records") {
		t.Fatalf("all well: %q %q %v", title, body, failed)
	}
	title, body, failed = Summarize([]FeedResult{{Feed: "cisa_kev", Records: 3}, {Feed: "nvd", Err: errors.New("GET x: 429")}})
	if !failed || title != "Vulnerability feeds synced; NVD failed" || !strings.Contains(body, "NVD: failed: GET x: 429") {
		t.Fatalf("one failed: %q %q %v", title, body, failed)
	}
	if title, _, failed = Summarize([]FeedResult{{Feed: "nvd", Err: errors.New("x")}}); !failed || title != "Vulnerability feed sync failed: NVD" {
		t.Fatalf("all failed: %q", title)
	}
}

func TestFeedSyncer_NotesResultsOfARound(t *testing.T) {
	s := &FeedSyncer{}
	s.note(FeedResult{Feed: "a"})
	s.note(FeedResult{Feed: "b", Err: errors.New("x")})
	if len(s.results) != 2 {
		t.Fatalf("results: %+v", s.results)
	}
}

func TestFeedConfig_Wants(t *testing.T) {
	if !(FeedConfig{}).wants("nvd") || !(FeedConfig{Only: "nvd"}).wants("nvd") || (FeedConfig{Only: "nvd"}).wants("osv") {
		t.Fatal("Only limits a round to one feed; empty runs all")
	}
}
