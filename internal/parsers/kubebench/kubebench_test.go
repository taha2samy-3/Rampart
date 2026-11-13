package kubebench

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/domain"
)

const sampleKubeBenchJSON = `{
  "Controls": [
    {
      "id": "1",
      "version": "cis-1.7",
      "text": "Control Plane Security Configuration",
      "node_type": "master",
      "tests": [
        {
          "section": "1.1",
          "type": "master",
          "desc": "Control Plane Node Configuration Files",
          "results": [
            {
              "test_number": "1.1.1",
              "test_desc": "Ensure that the API server pod specification file permissions are set to 600 or more restrictive",
              "remediation": "chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml",
              "status": "FAIL",
              "scored": true
            },
            {
              "test_number": "1.1.2",
              "test_desc": "Ensure that the API server pod specification file ownership is set to root:root",
              "status": "PASS",
              "scored": true
            }
          ]
        }
      ]
    }
  ]
}`

func TestKubeBenchParser(t *testing.T) {
	p := NewParser()

	// 1. Detect
	score := p.Detect([]byte(sampleKubeBenchJSON), "kube-bench.json", "application/json")
	if score < 80 {
		t.Errorf("detection score = %d, expected >= 80", score)
	}

	// 2. Parse
	var findings []domain.RawFinding
	for f, err := range p.Parse(context.Background(), strings.NewReader(sampleKubeBenchJSON), domain.ParseContext{}) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings = append(findings, f)
	}

	// Only FAIL should be emitted
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "1.1.1" {
		t.Errorf("rule_id = %s", f.RuleID)
	}
	if f.Category != domain.CategoryCompliance {
		t.Errorf("category = %s", f.Category)
	}
	if f.Severity != domain.SeverityHigh {
		t.Errorf("severity = %s", f.Severity)
	}
	if f.Location.Resource == nil || f.Location.Resource.Address != "k8s-node/master" {
		t.Errorf("resource location = %+v", f.Location.Resource)
	}
}
