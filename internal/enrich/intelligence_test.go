package enrich_test

import (
	"strings"
	"testing"
	"time"

	"rampart/internal/enrich"
)

func TestFeedStoreKEV(t *testing.T) {
	store := enrich.NewFeedStore()

	dueDate := time.Date(2023, 1, 15, 0, 0, 0, 0, time.UTC)
	store.SetKEV(enrich.KEVEntry{
		CVEID:             "CVE-2021-44228",
		VendorProject:     "Apache",
		Product:           "Log4j",
		VulnerabilityName: "Log4Shell",
		DueDate:           &dueDate,
	})

	entry, ok := store.GetKEV("cve-2021-44228")
	if !ok {
		t.Fatalf("expected to find KEV entry for CVE-2021-44228")
	}
	if entry.Product != "Log4j" {
		t.Errorf("expected product Log4j, got %q", entry.Product)
	}
	if entry.DueDate == nil || !entry.DueDate.Equal(dueDate) {
		t.Errorf("expected due date %v, got %v", dueDate, entry.DueDate)
	}

	_, okNotFound := store.GetKEV("CVE-9999-9999")
	if okNotFound {
		t.Errorf("expected false for unknown CVE")
	}
}

func TestFeedStoreLoadKEVJSON(t *testing.T) {
	store := enrich.NewFeedStore()
	sampleJSON := `{
		"vulnerabilities": [
			{
				"cveID": "CVE-2023-1234",
				"vendorProject": "TestVendor",
				"product": "TestProduct",
				"vulnerabilityName": "Test Vuln",
				"dateAdded": "2023-05-01",
				"dueDate": "2023-05-22",
				"knownRansomwareCampaignUse": "Known"
			}
		]
	}`

	count, err := store.LoadKEVJSON(strings.NewReader(sampleJSON))
	if err != nil {
		t.Fatalf("failed to load KEV JSON: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 entry loaded, got %d", count)
	}

	entry, ok := store.GetKEV("CVE-2023-1234")
	if !ok {
		t.Fatalf("expected CVE-2023-1234 to be found")
	}
	if !entry.KnownRansomwareCampaignUse {
		t.Errorf("expected ransomware campaign flag true")
	}
}

func TestFeedStoreLoadEPSSCSV(t *testing.T) {
	store := enrich.NewFeedStore()
	sampleCSV := `#model_version:v2023.03.01,date:2023-11-01T00:00:00Z
cve,epss,percentile
CVE-2021-44228,0.975,0.999
CVE-2020-28168,0.125,0.850
`

	count, err := store.LoadEPSSCSV(strings.NewReader(sampleCSV))
	if err != nil {
		t.Fatalf("failed to load EPSS CSV: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 entries loaded, got %d", count)
	}

	score, ok := store.GetEPSS("cve-2021-44228")
	if !ok {
		t.Fatalf("expected to find EPSS for CVE-2021-44228")
	}
	if score.EPSS != 0.975 {
		t.Errorf("expected epss 0.975, got %f", score.EPSS)
	}
	if score.Percentile != 0.999 {
		t.Errorf("expected percentile 0.999, got %f", score.Percentile)
	}
}
