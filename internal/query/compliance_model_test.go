package query_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"rampart/internal/ingest"
	"rampart/internal/query"
	"rampart/internal/store"
)

// A reading says which rule made its statuses, and one kept before D120 says that it did not use today's rule, so the
// history is not read across the change as if nothing had changed.
func TestComplianceReading_SaysItsModel(t *testing.T) {
	s := &fwStore{MemoryStore: ingest.NewMemoryStore(), specs: []store.StoredFramework{spec("acme-policy", "", "", sastControl)}}
	mux, token, _ := setup(t, s)
	var now query.TaxonomyStatus
	if rec := getAs(mux, token, "/api/v1/taxonomies/acme-policy/status"); rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &now) != nil || now.Model == "" || strings.Contains(now.Note, "D120") {
		t.Fatalf("today's reading names its model and needs no warning: %d %+v", rec.Code, now)
	}
	// a reading kept before D120 has no model
	s.snapshot = []byte(`{"id":"acme-policy","status":[{"id":"SC-1","name":"x","status":"open","open":3,"bands":{}}]}`)
	var old query.TaxonomyStatus
	rec := getAs(mux, token, "/api/v1/taxonomies/acme-policy/status?at=2026-06-30")
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &old) != nil || !old.Historical || !strings.Contains(old.Note, "before controls were read by deadline") {
		t.Fatalf("an older reading warns that its rule was stricter: %d %s", rec.Code, rec.Body.String())
	}
	// one kept with today's model does not
	s.snapshot = []byte(`{"id":"acme-policy","model":"` + now.Model + `","status":[]}`)
	var cur query.TaxonomyStatus
	rec = getAs(mux, token, "/api/v1/taxonomies/acme-policy/status?at=2026-11-20")
	if json.Unmarshal(rec.Body.Bytes(), &cur) != nil || strings.Contains(cur.Note, "D120") {
		t.Fatalf("a reading kept by today's rule needs no warning: %s", rec.Body.String())
	}
}
