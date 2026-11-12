package store_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"rampart/internal/auth"
	"rampart/internal/query"
)

func TestCompliance_StatusPerControl(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	viewer := h.tokenFor(auth.RoleViewer, "viewer@acme.example")
	seedFindings(t, ctx, h.store, h.tenant, 8) // SAST findings with CWE-89, some open, none from a real run

	code, list := getJSON[struct{ Items []query.TaxonomyInfo }](t, h, viewer, "/api/v1/taxonomies")
	if code != http.StatusOK || len(list.Items) != 5 {
		t.Fatalf("frameworks: %d %+v", code, list.Items)
	}
	if code, _ := h.callAs("", "GET", "/api/v1/taxonomies", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", code)
	}
	status := func(id string) map[string]query.ControlStatus {
		code, st := getJSON[query.TaxonomyStatus](t, h, viewer, "/api/v1/taxonomies/"+id+"/status")
		if code != http.StatusOK {
			t.Fatalf("%s: %d", id, code)
		}
		out := map[string]query.ControlStatus{}
		for _, c := range st.Controls {
			out[c.ID] = c
		}
		return out
	}

	// Findings with CWE-89 are open under A03 (injection). A control no finding bears on is not "clear": no scan has run.
	o := status("owasp-top10-2021")
	if a03 := o["A03:2021"]; a03.Status != "open" || a03.Open == 0 || a03.Query == "" {
		t.Fatalf("A03: %+v", a03)
	}
	if a10 := o["A10:2021"]; a10.Status != "not_assessed" || a10.Open != 0 {
		t.Fatalf("A10 with no scan at all must be not_assessed: %+v", a10)
	}
	// The filter the control carries finds the findings it counted.
	code, found := getJSON[struct {
		Items []struct{} `json:"items"`
		Total int        `json:"total"`
	}](t, h, viewer, "/api/v1/findings?q="+strings.ReplaceAll(o["A03:2021"].Query, " ", "+"))
	if code != http.StatusOK || found.Total != o["A03:2021"].Open {
		t.Fatalf("the control's filter finds %d, the control counts %d", found.Total, o["A03:2021"].Open)
	}
	// By category: SAST findings are open under secure coding; DAST evidence was never produced.
	pci := status("pci-dss-4.0.1-req6")
	if pci["6.2.4"].Status != "open" || pci["6.4.1"].Status != "not_assessed" {
		t.Fatalf("pci: %+v / %+v", pci["6.2.4"], pci["6.4.1"])
	}

	// A completed scan makes a control without findings "clear" and names the scanner.
	ingestRules(t, h, map[string]string{"rule.z": "2.0"}, "main")
	pci = status("pci-dss-4.0.1-req6")
	if pci["6.3.3"].Status != "not_assessed" { // sca/container: this scan was SAST
		t.Fatalf("a SAST scan is no evidence for patching: %+v", pci["6.3.3"])
	}
	if c := pci["6.2.3"]; c.Status != "open" || len(c.Evidence) == 0 {
		t.Fatalf("6.2.3 has findings and evidence: %+v", c)
	}

	// An application filter and the evidence export.
	if code, _ := h.callAs(viewer, "GET", "/api/v1/taxonomies/nope/status", nil, nil); code != http.StatusNotFound {
		t.Fatalf("unknown framework: %d", code)
	}
	if code, _ := h.callAs(viewer, "GET", "/api/v1/taxonomies/cwe-top25/status?application=zzz", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("bad application: %d", code)
	}
	c, csv := h.callAs(viewer, "GET", "/api/v1/taxonomies/cwe-top25/status?format=csv", nil, nil)
	if c != http.StatusOK || !strings.HasPrefix(string(csv), "framework,version,application,control,") || !strings.Contains(string(csv), "CWE-89") {
		t.Fatalf("csv: %d %.200s", c, csv)
	}
}
