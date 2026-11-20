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
			ID:           "cluster:sarif",
			Name:         "SARIF 2.1.0 Parser",
			Kind:         integrations.KindParser,
			Version:      "1.0.0",
			SupportLevel: integrations.SupportCluster,
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

	// Get parser by canonical cluster ID
	got, err := reg.GetParser("cluster:sarif")
	if err != nil || got.Descriptor().ID != "cluster:sarif" {
		t.Errorf("failed to get parser by cluster id: %v", err)
	}

	// Get parser by clean name
	gotClean, err := reg.GetParser("sarif")
	if err != nil || gotClean.Descriptor().ID != "cluster:sarif" {
		t.Errorf("failed to get parser by clean name: %v", err)
	}

	p2 := &mockParser{
		desc: integrations.Descriptor{
			ID:           "cluster:sbom-cyclonedx",
			Name:         "CycloneDX SBOM Parser",
			Kind:         integrations.KindParser,
			Version:      "1.6",
			SupportLevel: integrations.SupportCluster,
		},
		score: 0,
	}
	if err := reg.RegisterParser(p2); err != nil {
		t.Fatalf("failed to register sbom parser: %v", err)
	}

	// Get parser by cluster SBOM ID
	gotSBOM, err := reg.GetParser("cluster:sbom-cyclonedx")
	if err != nil || gotSBOM.Descriptor().ID != "cluster:sbom-cyclonedx" {
		t.Errorf("failed to get parser by cluster sbom id: %v", err)
	}

	// Get parser by format name
	gotFormat, err := reg.GetParser("cyclonedx")
	if err != nil || gotFormat.Descriptor().ID != "cluster:sbom-cyclonedx" {
		t.Errorf("failed to get parser by clean sbom format name: %v", err)
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
			wantID:   "cluster:sarif",
		},
		{
			name:     "OpenVEX",
			head:     []byte(`{"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}`),
			filename: "triage.vex.json",
			wantID:   "cluster:openvex",
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
