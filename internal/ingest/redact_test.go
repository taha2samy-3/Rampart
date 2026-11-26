package ingest

import (
	"encoding/json"
	"strings"
	"testing"

	"rampart/internal/domain"
)

// A parser comes from outside (D141): whatever it puts in the evidence, a secret never reaches the store (D42, docs/51 1.1).
func TestRedactEvidence_HostileSecretParser(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	raw := domain.RawFinding{
		Category:    domain.CategorySecret,
		SecretValue: secret,
		Attributes: map[string]any{
			"commit": "abc123",
			"Secret": secret,
			"Match":  "aws_key = " + secret,
			"nested": map[string]any{"renamed": "key is " + secret, "list": []any{secret, "safe"}},
			"Line":   "export AWS=" + secret,
		},
		RawPayload: json.RawMessage(`{"Secret":"` + secret + `","rule":"aws"}`),
	}
	attrs, payload := redactEvidence(raw)
	if payload != nil {
		t.Fatalf("a secret finding keeps no raw payload, got %s", payload)
	}
	b, _ := json.Marshal(attrs)
	if strings.Contains(string(b), secret) {
		t.Fatalf("SECURITY VIOLATION: the secret is in the stored attributes: %s", b)
	}
	for _, k := range []string{"Secret", "Match", "Line"} {
		if _, ok := attrs[k]; ok {
			t.Fatalf("key %s must be dropped from a secret finding", k)
		}
	}
	if attrs["commit"] != "abc123" {
		t.Fatalf("evidence that holds no secret is kept: %v", attrs)
	}
}

func TestRedactEvidence_OtherFindingsKeepTheirPayload(t *testing.T) {
	raw := domain.RawFinding{
		Category:    domain.CategorySAST,
		SecretValue: "hunter2-token",
		Attributes:  map[string]any{"line": 12, "snippet": "pw = 'hunter2-token'"},
		RawPayload:  json.RawMessage(`{"line":12,"secret_value":"hunter2-token","deep":{"secret":"x"},"msg":"ok"}`),
	}
	attrs, payload := redactEvidence(raw)
	if attrs["line"] != 12 {
		t.Fatalf("a SAST line number is not a secret: %v", attrs)
	}
	if attrs["snippet"] != redactedMark {
		t.Fatalf("a string that contains the secret value is replaced: %v", attrs["snippet"])
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["secret_value"]; ok {
		t.Fatalf("secret_value is dropped from every payload: %s", payload)
	}
	if deep, _ := m["deep"].(map[string]any); deep == nil || deep["secret"] != nil {
		t.Fatalf("secret keys are dropped at any depth: %s", payload)
	}
	if m["msg"] != "ok" {
		t.Fatalf("the rest of the payload is kept: %s", payload)
	}
}

func TestRedactEvidence_ShortSecretValueDoesNotBlankEverything(t *testing.T) {
	attrs, _ := redactEvidence(domain.RawFinding{Category: domain.CategorySAST, SecretValue: "a", Attributes: map[string]any{"msg": "a cat"}})
	if attrs["msg"] != "a cat" {
		t.Fatalf("a one-letter value is not searched for: %v", attrs)
	}
}
