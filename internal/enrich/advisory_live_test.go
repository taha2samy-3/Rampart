package enrich_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/enrich"
)

func TestAdvisoryClient_FetchOSVLive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/vulns/CVE-2026-2359" || r.URL.Path == "/v1/vulns/GHSA-v52c-386h-88mc" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"id": "GHSA-v52c-386h-88mc",
				"summary": "Multer vulnerable to Denial of Service (DoS)",
				"details": "### Impact\n\nA vulnerability in Multer allows DoS.\n\n### Patches\nUpgrade to 2.1.0.",
				"aliases": ["CVE-2026-2359"],
				"published": "2026-02-27T00:00:00Z",
				"modified": "2026-07-15T00:00:00Z",
				"severity": [
					{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
				],
				"references": [
					{"type": "ADVISORY", "url": "https://github.com/expressjs/multer/security/advisories/GHSA-v52c-386h-88mc"}
				]
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := enrich.NewAdvisoryClient()
	client.OSVURL = server.URL + "/v1/vulns"

	rec, err := client.FetchOSVLive(context.Background(), "CVE-2026-2359")
	if err != nil {
		t.Fatalf("FetchOSVLive failed: %v", err)
	}
	if rec == nil {
		t.Fatal("expected non-nil OSVRecord")
	}
	if rec.ID != "GHSA-v52c-386h-88mc" {
		t.Errorf("got ID %q, want GHSA-v52c-386h-88mc", rec.ID)
	}
	if rec.Summary != "Multer vulnerable to Denial of Service (DoS)" {
		t.Errorf("got Summary %q", rec.Summary)
	}
	if len(rec.Details) == 0 {
		t.Error("expected non-empty Details")
	}

	// 404 test
	notFound, err := client.FetchOSVLive(context.Background(), "CVE-9999-9999")
	if err != nil {
		t.Fatalf("unexpected error on 404: %v", err)
	}
	if notFound != nil {
		t.Errorf("expected nil on 404, got %+v", notFound)
	}
}

func TestAdvisoryClient_FetchNVDLive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cveId") == "CVE-2026-1111" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"vulnerabilities": [
					{
						"cve": {
							"id": "CVE-2026-1111",
							"descriptions": [
								{"lang": "en", "value": "Official NVD narrative for CVE-2026-1111"}
							],
							"metrics": {
								"cvssMetricV31": [
									{
										"cvssData": {
											"version": "3.1",
											"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
											"baseScore": 9.8
										}
									}
								]
							},
							"weaknesses": [
								{
									"description": [
										{"lang": "en", "value": "CWE-89"}
									]
								}
							],
							"references": [
								{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1111"}
							]
						}
					}
				]
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := enrich.NewAdvisoryClient()
	client.NVDURL = server.URL

	entry, err := client.FetchNVDLive(context.Background(), "CVE-2026-1111", "")
	if err != nil {
		t.Fatalf("FetchNVDLive failed: %v", err)
	}
	if entry == nil {
		t.Fatal("expected non-nil NVDEntry")
	}
	if entry.CVEID != "CVE-2026-1111" {
		t.Errorf("got CVEID %q, want CVE-2026-1111", entry.CVEID)
	}
	if entry.Description != "Official NVD narrative for CVE-2026-1111" {
		t.Errorf("got description %q", entry.Description)
	}
	if entry.CVSSv3Score != 9.8 {
		t.Errorf("got CVSSv3Score %v, want 9.8", entry.CVSSv3Score)
	}
	if len(entry.CWEIDs) == 0 || entry.CWEIDs[0] != "89" {
		t.Errorf("got CWEs %v, want [89]", entry.CWEIDs)
	}
}

func TestFeedSyncer_AdvisoryMode_StoredVsLive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "GHSA-live-1234",
			"details": "Live fetched markdown advisory",
			"summary": "Live advisory"
		}`))
	}))
	defer server.Close()

	client := enrich.NewAdvisoryClient()
	client.OSVURL = server.URL

	syncer := enrich.NewFeedSyncer(nil)
	syncer.SetAdvisoryClient(client)

	// In Stored mode: must not fetch from network and must return nil without DB pool
	syncer.SetAdvisoryMode(domain.AdvisoryModeStored)
	rec, err := syncer.Record(context.Background(), "GHSA-live-1234")
	if err != nil {
		t.Fatalf("unexpected error in stored mode: %v", err)
	}
	if rec != nil {
		t.Errorf("expected nil in stored mode without DB, got %+v", rec)
	}

	// In Hybrid mode: missing in DB triggers live fetch and returns synthesized advisory
	syncer.SetAdvisoryMode(domain.AdvisoryModeHybrid)
	recHybrid, err := syncer.Record(context.Background(), "GHSA-live-1234")
	if err != nil {
		t.Fatalf("unexpected error in hybrid mode: %v", err)
	}
	if recHybrid == nil {
		t.Fatal("expected non-nil in hybrid mode")
	}
	if recHybrid.Description != "Live fetched markdown advisory" {
		t.Errorf("got description %q", recHybrid.Description)
	}
}
