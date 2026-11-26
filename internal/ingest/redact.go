package ingest

import (
	"encoding/json"
	"strings"

	"rampart/internal/domain"
)

// Secrets are never stored (D42), whatever a parser emits. Parsers are supplied from outside (D141), so the core cannot rely on
// them to redact: the evidence a parser attaches to a finding (Attributes, RawPayload, D147) passes through here before it reaches
// the merge. docs/51 step 1.1.

// minSecretLen is the shortest secret value searched for inside strings; secret keys are dropped whatever the value's length.
const minSecretLen = 4

// redactedMark replaces a string that carried the secret value.
const redactedMark = "[redacted]"

// secretKeys are removed at any depth from the evidence of every finding.
var secretKeys = map[string]bool{"secret": true, "secret_value": true, "secretvalue": true}

// secretFindingKeys are also removed from the evidence of a secret finding: the fields in which Gitleaks (Secret, Match, Line) and
// TruffleHog (Raw, RawV2) put the credential or the text around it.
var secretFindingKeys = map[string]bool{"match": true, "line": true, "raw": true, "rawv2": true, "raw_v2": true}

// redactEvidence returns the attributes and the raw payload that may be stored for one finding. A secret finding keeps no raw
// payload at all; for every finding, secret keys are dropped at any depth and any string that contains the secret value is replaced.
func redactEvidence(raw domain.RawFinding) (map[string]any, json.RawMessage) {
	isSecret := raw.Category == domain.CategorySecret
	secret := raw.SecretValue
	if len(secret) < minSecretLen {
		secret = "" // a one- or two-character value would blank every string that contains the letter
	}
	clean := func(v any) any { return redactValue(v, secret, isSecret) }

	var attrs map[string]any
	if len(raw.Attributes) > 0 {
		if m, ok := clean(raw.Attributes).(map[string]any); ok && len(m) > 0 {
			attrs = m
		}
	}
	if isSecret || len(raw.RawPayload) == 0 {
		return attrs, nil
	}
	var decoded any
	if err := json.Unmarshal(raw.RawPayload, &decoded); err != nil {
		// Not JSON: keep it only if it cannot hold the secret.
		if secret != "" && strings.Contains(string(raw.RawPayload), secret) {
			return attrs, nil
		}
		return attrs, raw.RawPayload
	}
	out, err := json.Marshal(clean(decoded))
	if err != nil {
		return attrs, nil
	}
	return attrs, out
}

func redactValue(v any, secret string, isSecret bool) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			lk := strings.ToLower(k)
			if secretKeys[lk] || (isSecret && secretFindingKeys[lk]) {
				continue
			}
			out[k] = redactValue(val, secret, isSecret)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactValue(val, secret, isSecret)
		}
		return out
	case string:
		if secret != "" && strings.Contains(t, secret) {
			return redactedMark
		}
		return t
	default:
		return v
	}
}
