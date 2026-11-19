package integrations_test

import (
	"context"
	"io"
	"iter"
	"testing"

	"rampart/internal/domain"
	"rampart/internal/integrations"
)

type mockParser struct {
	desc  integrations.Descriptor
	score int
}

func (m *mockParser) Descriptor() integrations.Descriptor {
	return m.desc
}

func (m *mockParser) Detect(head []byte, filename string, contentType string) int {
	return m.score
}

func (m *mockParser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {}
}

func TestRegistry(t *testing.T) {
	reg := integrations.NewRegistry()

	p1 := &mockParser{
		desc: integrations.Descriptor{
			ID:           "builtin:sarif",
			Name:         "SARIF 2.1.0 Parser",
			Kind:         integrations.KindParser,
			Version:      "1.0.0",
			SupportLevel: integrations.SupportBuiltin,
		},
		score: 80,
	}

	if err := reg.RegisterParser(p1); err != nil {
		t.Fatalf("failed to register parser: %v", err)
	}

	// Duplicate check
	if err := reg.RegisterParser(p1); err == nil {
		t.Error("expected error on duplicate parser registration")
	}

	// Get parser
	got, err := reg.GetParser("builtin:sarif")
	if err != nil || got.Descriptor().ID != "builtin:sarif" {
		t.Errorf("failed to get parser: %v", err)
	}

	// Detect parser
	matched, score := reg.DetectParser([]byte{}, "scan.sarif", "")
	if matched == nil || score != 80 {
		t.Errorf("expected matched parser with score 80, got %v with score %d", matched, score)
	}
}

// An SBOM is assets, not findings, so the readers of SBOM formats are not report parsers: they are SBOMParser resources,
// registered by the ingest parser set, and their detection is tested there (internal/ingest, TestSBOMParsersAreDetected).
func TestDefaultRegistryDetect(t *testing.T) {
	reg := integrations.DefaultRegistry()

	tests := []struct {
		name        string
		head        []byte
		filename    string
		contentType string
		wantID      string
	}{
		{
			name:     "SARIF file",
			head:     []byte(`{"$schema": "https://docs.oasis-open.org/sarif/sarif-schema-2.1.0.json"}`),
			filename: "semgrep.sarif",
			wantID:   "builtin:sarif",
		},
		{
			name:     "OpenVEX",
			head:     []byte(`{"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}`),
			filename: "triage.vex.json",
			wantID:   "builtin:openvex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, score := reg.DetectParser(tt.head, tt.filename, tt.contentType)
			if p == nil || score < 50 {
				t.Fatalf("failed to detect parser for %s, score: %d", tt.name, score)
			}
			if p.Descriptor().ID != tt.wantID {
				t.Errorf("got parser %q, want %q", p.Descriptor().ID, tt.wantID)
			}
		})
	}
}
