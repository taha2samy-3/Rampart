package sbom

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"rampart/internal/domain"
)

func TestReadEvents(t *testing.T) {
	good := strings.Join([]string{
		`{"type":"metadata","format":"CycloneDX","spec_version":"1.5","serial_number":"urn:uuid:1","root_ref":"app"}`,
		`{"type":"component","ref":"app","name":"app","version":"1","purl":"pkg:npm/app@1","is_root":true}`,
		`{"type":"component","ref":"lodash","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21","licenses":["MIT",""],"hashes":{"SHA-256":"ab"}}`,
		``,
		`{"type":"edge","from":"app","to":"lodash","direct":true}`,
		`{"type":"somethingnew","x":1}`,
	}, "\n")
	res, err := readEvents(strings.NewReader(good), Limits{})
	if err != nil {
		t.Fatalf("a well-formed stream failed: %v", err)
	}
	if res.SBOM.Format != "CycloneDX" || res.SBOM.SpecVersion != "1.5" || res.SBOM.RootComponent != "app" || res.SBOM.ComponentCount != 2 {
		t.Errorf("metadata or count wrong: %+v", res.SBOM)
	}
	if len(res.Edges) != 1 || len(res.SBOM.Dependencies) != 1 {
		t.Errorf("edges = %d, document edges = %d, want 1 and 1", len(res.Edges), len(res.SBOM.Dependencies))
	}
	lodash := res.Components[1]
	if !lodash.Direct {
		t.Error("the target of a direct edge must be marked direct")
	}
	if len(lodash.Licenses) != 1 || lodash.Licenses[0] != "MIT" {
		t.Errorf("empty licence strings must be dropped, got %v", lodash.Licenses)
	}
}

// What a module says about vulnerabilities is read only when the run asked for it (options.extractVulnerabilities).
func TestReadEventsIgnoresVulnerabilityEventsUnlessAsked(t *testing.T) {
	in := `{"type":"metadata","format":"CycloneDX"}` + "\n" +
		`{"type":"vulnerability","id":"CVE-2024-0001","severity":"high","affected_ref":"pkg:npm/x@1"}` + "\n"
	res, err := readEvents(strings.NewReader(in), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Components) != 0 || len(res.Vulnerabilities) != 0 {
		t.Errorf("components = %d, vulnerabilities = %d, want 0 and 0", len(res.Components), len(res.Vulnerabilities))
	}
}

func TestReadEventsReadsVulnerabilitiesWhenAsked(t *testing.T) {
	in := strings.Join([]string{
		`{"type":"metadata","format":"CycloneDX"}`,
		`{"type":"component","ref":"pkg:npm/x@1","name":"x","version":"1","purl":"pkg:npm/x@1"}`,
		`{"type":"vulnerability","id":"CVE-2024-0001","severity":"high","score":7.5,"vector":"CVSS:3.1/AV:N","cwes":[79],"affected_ref":"pkg:npm/x@1","aliases":["GHSA-aaaa-bbbb-cccc",""]}`,
	}, "\n")
	res, err := readEvents(strings.NewReader(in), Limits{ExtractVulnerabilities: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want 1", len(res.Vulnerabilities))
	}
	if v := res.Vulnerabilities[0]; v.ID != "CVE-2024-0001" || v.Score != 7.5 || len(v.Aliases) != 1 || v.CWEs[0] != 79 {
		t.Errorf("unexpected vulnerability: %+v", v)
	}
	for name, bad := range map[string]string{
		"no id":        `{"type":"vulnerability","affected_ref":"x"}`,
		"no component": `{"type":"vulnerability","id":"CVE-1"}`,
	} {
		if _, err := readEvents(strings.NewReader(`{"type":"metadata"}`+"\n"+bad), Limits{ExtractVulnerabilities: true}); err == nil {
			t.Errorf("%s: a vulnerability that names no id or no component must fail the run", name)
		}
	}
}

func TestReadEventsReadsVEXStatementsWhenAsked(t *testing.T) {
	in := strings.Join([]string{
		`{"type":"metadata","format":"OpenVEX","spec_version":"0.2.0"}`,
		`{"type":"vex_statement","vulnerability":"CVE-2023-4911","purl":"pkg:deb/debian/glibc@2.38","status":"not_affected","justification":"vulnerable_code_not_in_execute_path","impact_statement":"runtime disabled"}`,
	}, "\n")

	// 1. When extractVEX is off: vex_statement is ignored
	off, err := readEvents(strings.NewReader(in), Limits{ExtractVEX: false})
	if err != nil {
		t.Fatalf("reading with extractVEX false failed: %v", err)
	}
	if len(off.VEXStatements) != 0 {
		t.Errorf("expected 0 vex statements when off, got %d", len(off.VEXStatements))
	}

	// 2. When extractVEX is on: vex_statement is extracted
	on, err := readEvents(strings.NewReader(in), Limits{ExtractVEX: true})
	if err != nil {
		t.Fatalf("reading with extractVEX true failed: %v", err)
	}
	if len(on.VEXStatements) != 1 {
		t.Fatalf("expected 1 vex statement, got %d", len(on.VEXStatements))
	}
	st := on.VEXStatements[0]
	if st.VulnerabilityID != "CVE-2023-4911" || st.PurlBase != "pkg:deb/debian/glibc" || st.Status != domain.StateNotAffected || st.Justification != "vulnerable_code_not_in_execute_path" || st.Impact != "runtime disabled" {
		t.Errorf("unexpected vex statement: %+v", st)
	}
}

// A statement becomes a finding of its own family, with the best of what the document says; one that names no component
// of the document is a record error and no finding; a CPE is never read.
func TestFindingsOfAStatement(t *testing.T) {
	res := &Result{
		Components: []domain.SBOMComponent{
			{Ref: "ref-x", Name: "x", Version: "1.2.3", Purl: "pkg:npm/x@1.2.3", PurlBase: "pkg:npm/x"},
		},
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2024-0001", Severity: "high", Score: 7.5, Vector: "CVSS:3.1/AV:N", CWEs: []int{79}, AffectedRef: "ref-x", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Description: "d", Detail: "more"},
			{ID: "CVE-2024-0002", Score: 9.8, AffectedRef: "pkg:npm/x@1.2.3"}, // found by purl, severity from the score
			{ID: "CVE-2024-0003", Severity: "low", AffectedRef: "not-in-the-document"},
		},
	}
	var recErrs []domain.RecordError
	got := findingsOf(res, "cyclonedx", domain.ParseContext{RecordError: func(e domain.RecordError) { recErrs = append(recErrs, e) }})
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2", len(got))
	}
	f := got[0]
	if f.ScannerFamily != "sbom-cyclonedx" || f.Category != domain.CategorySCA || f.RuleID != "CVE-2024-0001" || f.Severity != domain.SeverityHigh {
		t.Errorf("unexpected finding: %+v", f)
	}
	if len(f.VulnIDs) != 2 || f.VulnIDs[1] != "GHSA-aaaa-bbbb-cccc" || f.CVSSVector != "CVSS:3.1/AV:N" || !strings.Contains(f.Description, "more") {
		t.Errorf("ids, vector or description lost: %+v", f)
	}
	if p := f.Location.Package; p == nil || p.PurlBase != "pkg:npm/x" || p.InstalledVersion != "1.2.3" || p.ComponentName != "x" {
		t.Errorf("package location: %+v", f.Location.Package)
	}
	if got[1].Severity != domain.SeverityCritical {
		t.Errorf("a statement with no severity word takes the band of its score, got %q", got[1].Severity)
	}
	if len(recErrs) != 1 || !strings.Contains(recErrs[0].Where, "CVE-2024-0003") {
		t.Errorf("an unresolved reference must be one record error, got %+v", recErrs)
	}
	// with no callback the unresolved statement is only left out
	if n := len(findingsOf(res, "cyclonedx", domain.ParseContext{})); n != 2 {
		t.Errorf("findings without a RecordError callback = %d, want 2", n)
	}
}

func TestReadEventsRejectsBadOutput(t *testing.T) {
	cases := map[string]string{
		"not JSON":                  `{"type":"metadata"}` + "\n" + `this is not json`,
		"component with no name":    `{"type":"metadata"}` + "\n" + `{"type":"component","version":"1"}`,
		"edge without a target":     `{"type":"metadata"}` + "\n" + `{"type":"edge","from":"a"}`,
		"nothing recognised at all": `{"type":"vulnerability","id":"CVE-1"}`,
		"empty output":              ``,
	}
	for name, in := range cases {
		if _, err := readEvents(strings.NewReader(in), Limits{}); err == nil {
			t.Errorf("%s: no error, the run must fail instead of storing a part of the document", name)
		}
	}
}

func TestReadEventsAllowsAnEmptyInventory(t *testing.T) {
	res, err := readEvents(strings.NewReader(`{"type":"metadata","format":"SPDX","spec_version":"2.3"}`), Limits{})
	if err != nil {
		t.Fatalf("an SBOM with no components is a valid inventory: %v", err)
	}
	if len(res.Components) != 0 || res.SBOM.Format != "SPDX" {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestRunWithoutAModule(t *testing.T) {
	_, err := run(context.Background(), nil, strings.NewReader("{}"), "sbom-missing", Limits{})
	if !errors.Is(err, ErrNoModule) {
		t.Fatalf("err = %v, want ErrNoModule", err)
	}
}

// A document that is not in the format the module reads fails the run with the module's own message.
func TestShippedModuleFailsOnADocumentOfAnotherFormat(t *testing.T) {
	for _, format := range []string{"cyclonedx", "spdx"} {
		_, _, _, err := ParseSBOMStream(context.Background(), format, strings.NewReader("this is not an SBOM"))
		if err == nil {
			t.Errorf("%s: plain text was accepted as an SBOM", format)
		}
	}
}

func TestTailBufferKeepsTheEnd(t *testing.T) {
	var b tailBuffer
	_, _ = b.Write([]byte(strings.Repeat("a", stderrTail)))
	_, _ = b.Write([]byte("END"))
	if got := b.String(); len(got) != stderrTail || !strings.HasSuffix(got, "END") {
		t.Errorf("tail = %d bytes ending %q", len(got), got[len(got)-3:])
	}
}

func TestIsReader(t *testing.T) {
	p, err := NewWasmSBOMParserFromSpec("cyclonedx", []byte("spec:\n  format: cyclonedx\n"), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	if !IsReader(p) {
		t.Error("an SBOM parser must be an SBOM reader")
	}
}

// Syft is an SBOM reader like CycloneDX and SPDX: assets only, with the same direct-dependency rule.
func TestShippedSyftReaderGivesAssetsOnly(t *testing.T) {
	data, err := os.ReadFile("../testdata/reports/sbom-syft/report.syft.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, comps, edges, err := ParseSBOMStream(context.Background(), "syft", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseSBOMStream: %v", err)
	}
	if doc.Format != "Syft" || doc.SpecVersion != "16.0.0" || doc.RootComponent != "pkg:npm/ecommerce-api@1.0.0" {
		t.Errorf("document = %+v", doc)
	}
	if len(comps) != 4 || len(edges) != 3 {
		t.Fatalf("components = %d, edges = %d, want 4 and 3", len(comps), len(edges))
	}
	direct := map[string]bool{}
	for _, c := range comps {
		direct[c.Name] = c.Direct
	}
	if !direct["express"] || !direct["busybox"] || direct["debug"] {
		t.Errorf("direct flags = %v: express and busybox hang off the root, debug is transitive", direct)
	}
}

func TestSyftIsDetectedAndIsAReader(t *testing.T) {
	raw, err := os.ReadFile("../testdata/parsers/sbom/syft.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewWasmSBOMParserFromSpec("sbom-syft", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !IsReader(p) {
		t.Fatal("syft must be an SBOM reader")
	}
	syft := []byte(`{"artifacts":[{"id":"1","name":"a","foundBy":"x"}],"artifactRelationships":[],"descriptor":{"name":"syft"}}`)
	if s := p.Detect(syft, "", ""); s < 40 {
		t.Errorf("a Syft document scores %d, below the auto-select threshold", s)
	}
	// Documents of the other SBOM formats must never be taken for Syft.
	for name, doc := range map[string]string{
		"cyclonedx": `{"bomFormat":"CycloneDX","components":[{"artifacts":1}]}`,
		"spdx":      `{"spdxVersion":"SPDX-2.3","packages":[]}`,
		"sarif":     `{"runs":[{"results":[]}]}`,
	} {
		if s := p.Detect([]byte(doc), "", ""); s >= 40 {
			t.Errorf("%s document scores %d as Syft", name, s)
		}
	}
}
