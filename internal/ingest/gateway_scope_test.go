package ingest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/ingest"
)

func sarifFrom(tool, rule string) string {
	return fmt.Sprintf(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":%q,"rules":[{"id":%q}]}},
"results":[{"ruleId":%q,"level":"error","message":{"text":"m"},
"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/a.go"},"region":{"startLine":3}}}]}]}]}`, tool, rule, rule)
}

// D13: the close scope is per scanner. A Trivy SARIF upload on the same asset, source and
// track must not close what Semgrep reported, even though both use the SARIF parser.
func TestSARIFFromAnotherToolDoesNotCloseFindings(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenant := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenant)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	up := func(doc string) ingest.DirectReportResponse {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		_ = w.WriteField("repository", "https://github.com/acme/shop")
		_ = w.WriteField("branch", "main")
		part, _ := w.CreateFormFile("file", "r.sarif")
		_, _ = part.Write([]byte(doc))
		_ = w.Close()
		req := httptest.NewRequest("POST", "/ingest/v1/reports", &b)
		req.Header.Set("Content-Type", w.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
		}
		var out ingest.DirectReportResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}

	up(sarifFrom("semgrep", "go.sqli"))
	res := up(sarifFrom("trivy", "DS002"))
	if res.Closed != 0 {
		t.Fatalf("a trivy report closed %d semgrep finding(s)", res.Closed)
	}
	fs, _ := gw.Store().ListFindings(context.Background(), tenant)
	open := 0
	for _, f := range fs {
		if f.State == "open" {
			open++
		}
	}
	if len(fs) != 2 || open != 2 {
		t.Fatalf("want 2 open findings (one per tool), got %d total / %d open", len(fs), open)
	}
	families := map[string]bool{}
	for _, f := range fs {
		families[f.RuleScannerFamily] = true
	}
	if !families["semgrep"] || !families["trivy"] {
		t.Fatalf("findings must carry their scanner family, got %v", families)
	}
}

// docs/51 step 2.7: a clean rescan closes what the same scanner reported before. A report with no findings has no tool to read
// the family from; the scope was the parser id (`cluster:semgrep`) while the findings carry the family `semgrep`, so nothing closed.
func TestCleanRescanClosesWhatTheSameScannerReported(t *testing.T) {
	gw := ingest.NewGateway(nil)
	tenant := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenant)
	gw.SetAuthenticator(authn)
	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)

	report, err := os.ReadFile("../testdata/reports/semgrep/scan-1.45.json")
	if err != nil {
		t.Fatal(err)
	}
	up := func(doc []byte) ingest.DirectReportResponse {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		_ = w.WriteField("repository", "https://github.com/acme/shop")
		_ = w.WriteField("branch", "main")
		_ = w.WriteField("parser", "semgrep")
		part, _ := w.CreateFormFile("file", "semgrep.json")
		_, _ = part.Write(doc)
		_ = w.Close()
		req := httptest.NewRequest("POST", "/ingest/v1/reports", &b)
		req.Header.Set("Content-Type", w.FormDataContentType())
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
		}
		var out ingest.DirectReportResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	first := up(report)
	if first.Created == 0 {
		t.Fatalf("the first report created no finding: %+v", first)
	}
	clean := up([]byte(`{"results":[],"errors":[],"paths":{"scanned":[]}}`))
	if clean.Closed != first.Created {
		t.Fatalf("a clean rescan closed %d of the %d findings the same scanner reported", clean.Closed, first.Created)
	}
}
