package enrich

import (
	"strings"
	"testing"
)

func TestFeedStore_NVD(t *testing.T) {
	sampleNVD := `{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2023-1234",
        "descriptions": [
          {"lang": "en", "value": "A buffer overflow flaw was found in the example service."}
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "cvssData": {
                "baseScore": 8.8,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
              }
            }
          ]
        },
        "weaknesses": [
          {
            "description": [
              {"lang": "en", "value": "CWE-120"}
            ]
          }
        ],
        "references": [
          {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"}
        ]
      }
    }
  ]
}`

	fs := NewFeedStore()
	count, err := fs.LoadNVD(strings.NewReader(sampleNVD))
	if err != nil {
		t.Fatalf("failed to load NVD: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}

	entry, ok := fs.GetNVD("cve-2023-1234")
	if !ok {
		t.Fatalf("failed to find CVE-2023-1234")
	}

	if entry.CVSSv3Score != 8.8 {
		t.Errorf("expected score 8.8, got %f", entry.CVSSv3Score)
	}
	if entry.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("vector = %s", entry.CVSSv3Vector)
	}
	if len(entry.CWEIDs) != 1 || entry.CWEIDs[0] != "CWE-120" {
		t.Errorf("cwes = %+v", entry.CWEIDs)
	}
}
