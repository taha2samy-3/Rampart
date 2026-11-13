package prowler

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/domain"
)

const sampleProwlerJSON = `[
  {
    "CheckID": "s3_bucket_default_encryption",
    "CheckTitle": "S3 Bucket Default Encryption",
    "Status": "FAIL",
    "Severity": "high",
    "ServiceName": "s3",
    "Region": "us-east-1",
    "ResourceId": "company-data-lake",
    "ResourceArn": "arn:aws:s3:::company-data-lake",
    "Description": "S3 bucket does not have default encryption enabled.",
    "Risk": "Data at rest is not encrypted.",
    "Remediation": {
      "Recommendation": {
        "Text": "Enable AES256 or AWS KMS encryption on the S3 bucket.",
        "Url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"
      }
    }
  },
  {
    "CheckID": "iam_root_mfa_enabled",
    "CheckTitle": "IAM Root MFA Enabled",
    "Status": "PASS",
    "Severity": "critical",
    "ServiceName": "iam"
  }
]`

func TestProwlerParser(t *testing.T) {
	p := NewParser()

	// 1. Detect
	score := p.Detect([]byte(sampleProwlerJSON), "prowler-output.json", "application/json")
	if score < 80 {
		t.Errorf("detection score = %d, expected >= 80", score)
	}

	// 2. Parse
	var findings []domain.RawFinding
	for f, err := range p.Parse(context.Background(), strings.NewReader(sampleProwlerJSON), domain.ParseContext{}) {
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
	if f.RuleID != "s3_bucket_default_encryption" {
		t.Errorf("rule_id = %s", f.RuleID)
	}
	if f.Category != domain.CategoryCSPM {
		t.Errorf("category = %s", f.Category)
	}
	if f.Severity != domain.SeverityHigh {
		t.Errorf("severity = %s", f.Severity)
	}
	if f.Location.Resource == nil || f.Location.Resource.Address != "company-data-lake" {
		t.Errorf("resource address = %+v", f.Location.Resource)
	}
	if f.Location.Resource.Key != "arn:aws:s3:::company-data-lake" {
		t.Errorf("resource arn = %+v", f.Location.Resource)
	}
}
