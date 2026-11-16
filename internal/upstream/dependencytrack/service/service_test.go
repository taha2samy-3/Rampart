package service_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/store"
	"rampart/internal/upstream/dependencytrack/service"
)

// A source is due when it was never synced or its schedule has passed since the last portfolio sync.
func TestDue(t *testing.T) {
	now := time.Now()
	recent, old := now.Add(-10*time.Minute), now.Add(-40*time.Minute)
	sources := []store.DTrackSource{
		{ID: uuid.New(), Name: "never", Schedule: 30 * time.Minute},
		{ID: uuid.New(), Name: "recent", Schedule: 30 * time.Minute, LastPortfolioSync: &recent},
		{ID: uuid.New(), Name: "old", Schedule: 30 * time.Minute, LastPortfolioSync: &old},
		{ID: uuid.New(), Name: "hourly", Schedule: time.Hour, LastPortfolioSync: &old},
	}
	got := map[string]bool{}
	for _, s := range service.Due(sources, now) {
		got[s.Name] = true
	}
	if !got["never"] || got["recent"] || !got["old"] || got["hourly"] || len(got) != 2 {
		t.Fatalf("due: %v", got)
	}
}
