package query

import (
	"testing"
	"time"

	"rampart/internal/store"

	"github.com/google/uuid"
)

// An attestation for the application is more specific than one for the whole tenant, but an expired one must not
// hide one that still holds.
func TestAttestationFor_ExpiredSpecificDoesNotHideValidTenantWide(t *testing.T) {
	now := time.Now()
	app := uuid.New()
	at := func(id string, a *uuid.UUID, exp time.Duration) store.Attestation {
		return store.Attestation{Note: id, ControlID: "TM-1", ApplicationID: a, ExpiresAt: now.Add(exp)}
	}
	cases := []struct {
		name string
		atts []store.Attestation // newest first
		want string
	}{
		{"specific in force wins over a newer tenant-wide", []store.Attestation{at("wide", nil, time.Hour), at("specific", &app, time.Hour)}, "specific"},
		{"expired specific yields to a tenant-wide in force", []store.Attestation{at("specific", &app, -time.Hour), at("wide", nil, time.Hour)}, "wide"},
		{"nothing in force: the specific one, so the reading says it expired", []store.Attestation{at("wide", nil, -2*time.Hour), at("specific", &app, -time.Hour)}, "specific"},
		{"only a tenant-wide one", []store.Attestation{at("wide", nil, time.Hour)}, "wide"},
		{"another application's is not this one's", []store.Attestation{at("other", ptr(uuid.New()), time.Hour)}, ""},
	}
	for _, c := range cases {
		got := attestationFor(c.atts, "TM-1", &app, now)
		switch {
		case c.want == "" && got != nil:
			t.Errorf("%s: got %q", c.name, got.Note)
		case c.want != "" && (got == nil || got.Note != c.want):
			t.Errorf("%s: got %+v, want %q", c.name, got, c.want)
		}
	}
	// a control with no application asked about: only a whole-tenant one counts
	if got := attestationFor([]store.Attestation{at("specific", &app, time.Hour)}, "TM-1", nil, now); got != nil {
		t.Errorf("tenant-wide reading must not use an application's attestation: %+v", got)
	}
	if got := attestationFor([]store.Attestation{at("wide", nil, time.Hour)}, "OTHER", &app, now); got != nil {
		t.Errorf("another control: %+v", got)
	}
}

func ptr[T any](v T) *T { return &v }
