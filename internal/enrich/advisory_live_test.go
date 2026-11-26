package enrich_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

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

// docs/51 step 1.5: a page view (Record) never calls upstream, in any mode; the refresh does, except in stored mode.
func TestAdvisory_RecordNeverFetchesLive_RefreshHonoursStoredMode(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
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
	live := enrich.NewLiveAdvisory(syncer, nil, "", nil)

	for _, mode := range []domain.AdvisoryMode{domain.AdvisoryModeStored, domain.AdvisoryModeHybrid, domain.AdvisoryModeLive} {
		syncer.SetAdvisoryMode(mode)
		rec, err := live.Record(context.Background(), "GHSA-live-1234")
		if err != nil || rec != nil {
			t.Fatalf("%s: Record must read the database only: rec=%+v err=%v", mode, rec, err)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("Record called upstream %d times", n)
	}

	syncer.SetAdvisoryMode(domain.AdvisoryModeStored)
	if _, err := live.Refresh(context.Background(), "GHSA-live-1234"); !errors.Is(err, enrich.ErrLiveFetchOff) {
		t.Fatalf("stored mode: err = %v, want ErrLiveFetchOff", err)
	}
	syncer.SetAdvisoryMode(domain.AdvisoryModeHybrid)
	rec, err := live.Refresh(context.Background(), "GHSA-live-1234")
	if err != nil || rec == nil || rec.Description != "Live fetched markdown advisory" {
		t.Fatalf("hybrid refresh: rec=%+v err=%v", rec, err)
	}
	if live.Persists() {
		t.Fatalf("no system pool was given: nothing may be stored")
	}

	// The cooldown: the same id again is refused with how long to wait; after it, it is fetched again.
	now := time.Now()
	live.SetClock(func() time.Time { return now })
	var cool *enrich.RefreshCooldownError
	if _, err := live.Refresh(context.Background(), "ghsa-live-1234"); !errors.As(err, &cool) || cool.RetryAfter <= 0 {
		t.Fatalf("within the cooldown: err = %v", err)
	}
	live.SetClock(func() time.Time { return now.Add(enrich.DefaultRefreshCooldown + time.Second) })
	if _, err := live.Refresh(context.Background(), "GHSA-live-1234"); err != nil {
		t.Fatalf("after the cooldown: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("upstream calls = %d, want 2", n)
	}
}

// The live NVD call sends the scheduled sync's key, keeps a 4.0 score out of the v3 fields and prefers NVD's Primary.
func TestAdvisoryClient_FetchNVDLive_KeyPrimaryAndNoV4InV3(t *testing.T) {
	var gotKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("apiKey")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("cveId") {
		case "CVE-2026-0004": // only a 4.0 metric
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2026-0004","metrics":{
				"cvssMetricV40":[{"type":"Primary","cvssData":{"version":"4.0","baseScore":8.7,"vectorString":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}}]}}}]}`))
		case "CVE-2026-0031": // a CNA's Secondary first, NVD's Primary second
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2026-0031","metrics":{
				"cvssMetricV31":[
					{"type":"Secondary","cvssData":{"version":"3.1","baseScore":5.3,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}},
					{"type":"Primary","cvssData":{"version":"3.1","baseScore":9.8,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := enrich.NewAdvisoryClient()
	client.NVDURL = server.URL

	e, err := client.FetchNVDLive(context.Background(), "CVE-2026-0004", "the-key")
	if err != nil || e == nil {
		t.Fatalf("v4 only: %+v %v", e, err)
	}
	if gotKey != "the-key" {
		t.Errorf("apiKey header = %q, want the configured key", gotKey)
	}
	if e.CVSSv3Score != 0 || e.CVSSv3Vector != "" {
		t.Errorf("a 4.0 score was stored in the v3 fields: %v %q", e.CVSSv3Score, e.CVSSv3Vector)
	}
	e, err = client.FetchNVDLive(context.Background(), "CVE-2026-0031", "")
	if err != nil || e == nil || e.CVSSv3Score != 9.8 {
		t.Fatalf("Primary must be preferred over Secondary: %+v %v", e, err)
	}
	if gotKey != "" {
		t.Errorf("no key configured, yet apiKey = %q", gotKey)
	}
}
