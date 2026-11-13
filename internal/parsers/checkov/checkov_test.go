package checkov

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/domain"
)

const sampleCheckovJSON = `{
  "check_type": "terraform",
  "results": {
    "passed_checks": [],
    "failed_checks": [
      {
        "check_id": "CKV_AWS_20",
        "check_name": "Ensure S3 bucket has an S3 bucket policy",
        "check_result": {
          "result": "FAILED"
        },
        "file_path": "/modules/s3/main.tf",
        "file_line_range": [10, 25],
        "resource": "aws_s3_bucket.data",
        "severity": "HIGH",
        "guideline": "https://docs.bridgecrew.io/docs/s3_1-acl-read-permissions-everyone"
      }
    ]
  }
}`

func TestCheckovParser(t *testing.T) {
	p := NewParser()

	// 1. Detect
	score := p.Detect([]byte(sampleCheckovJSON), "checkov.json", "application/json")
	if score < 80 {
		t.Errorf("detection score = %d, expected >= 80", score)
	}

	// 2. Parse
	var findings []domain.RawFinding
	for f, err := range p.Parse(context.Background(), strings.NewReader(sampleCheckovJSON), domain.ParseContext{}) {
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		findings = append(findings, f)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "CKV_AWS_20" {
		t.Errorf("rule_id = %s", f.RuleID)
	}
	if f.Category != domain.CategoryIaC {
		t.Errorf("category = %s", f.Category)
	}
	if f.Severity != domain.SeverityHigh {
		t.Errorf("severity = %s", f.Severity)
	}
	if f.Location.Code == nil || f.Location.Code.FilePath != "/modules/s3/main.tf" {
		t.Errorf("file path = %+v", f.Location.Code)
	}
	if f.Location.Resource == nil || f.Location.Resource.Address != "aws_s3_bucket.data" {
		t.Errorf("resource = %+v", f.Location.Resource)
	}
}
