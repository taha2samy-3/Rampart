package ingest_test

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/jobs"
	"rampart/internal/objectstore"
	"rampart/internal/sbom"
)

func sbomProcessor(t *testing.T) (*ingest.Processor, *ingest.MemoryStore, *sbom.WasmSBOMParser) {
	t.Helper()
	st := ingest.NewMemoryStore()
	proc := ingest.NewProcessor(st, nil, objectstore.NewMemory(), nil)
	p, err := sbom.NewWasmSBOMParserFromSpec("cyclonedx", []byte("spec:\n  format: cyclonedx\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return proc, st, p
}

func openString(s string) ingest.StreamSource {
	return func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(s)), nil }
}

func sbomRun() *domain.IngestRun {
	return &domain.IngestRun{ID: domain.NewID(), TenantID: domain.NewID(), AssetID: domain.NewID(), ApplicationID: domain.NewID(), ScanSourceID: domain.NewID(), Track: "main"}
}

// An SBOM run stores the inventory and takes no part in the findings pipeline (docs/34 C8): no scope is recorded, no
// finding is merged, and nothing a scanner reported is closed by it.
func TestProcessSBOMStoresAssetsAndTouchesNoFindings(t *testing.T) {
	ctx := context.Background()
	proc, st, parser := sbomProcessor(t)
	run := sbomRun()

	// A finding another scanner reported on the same asset must survive an SBOM upload.
	other := ingest.CloseScope{TenantID: run.TenantID, ScanSourceID: run.ScanSourceID, ScannerFamily: "trivy", AssetID: run.AssetID, Track: "main"}
	eng := ingest.NewEngine(st)
	if _, err := eng.MergeBatch(ctx, other, domain.NewID(), run.ApplicationID, []ingest.StagedRecord{rec("keep-me")}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile("../testdata/reports/sbom-cyclonedx/sample.cdx.xml")
	if err != nil {
		t.Fatal(err)
	}
	res, err := proc.Process(ctx, ingest.ProcessParams{Run: run, Parser: parser, IsSBOM: true, ScanFinished: time.Now().UTC(), Open: openString(string(data))})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res.Status != domain.RunCompleted || res.Components != 1 {
		t.Fatalf("result = %+v, want completed with 1 component", res)
	}
	if res.Stats.Created+res.Stats.Updated+res.Stats.Closed != 0 {
		t.Errorf("an SBOM run touched findings: %+v", res.Stats)
	}
	if fams, _ := st.ListRunScopes(ctx, run.TenantID, run.ID); len(fams) != 0 {
		t.Errorf("an SBOM run recorded close scopes %v", fams)
	}
	if _, comps, err := st.GetSBOM(ctx, run.TenantID, run.AssetID); err != nil || len(comps) != 1 {
		t.Errorf("stored components = %d, err = %v, want 1", len(comps), err)
	}
	fs, _ := st.GetFindingsByKeys(ctx, run.TenantID, []string{"keep-me"})
	if fs["keep-me"] == nil || fs["keep-me"].State != domain.StateOpen {
		t.Error("an SBOM upload closed a finding another scanner reported")
	}
}

// A document the module cannot read fails the run with parse_error. It used to be logged and the run completed.
func TestProcessSBOMFailsOnAnUnreadableDocument(t *testing.T) {
	proc, st, parser := sbomProcessor(t)
	run := sbomRun()
	_, err := proc.Process(context.Background(), ingest.ProcessParams{Run: run, Parser: parser, IsSBOM: true, Open: openString("this is not an SBOM")})
	var perm *jobs.PermanentError
	if !errors.As(err, &perm) || perm.Code != ingest.ErrCodeParse {
		t.Fatalf("err = %v, want a permanent parse_error", err)
	}
	if sb, _, _ := st.GetSBOM(context.Background(), run.TenantID, run.AssetID); sb != nil {
		t.Error("an SBOM that could not be read was stored")
	}
}

// An ephemeral run (a pull request) changes nothing in the inventory (D10).
func TestProcessSBOMEphemeralStoresNothing(t *testing.T) {
	proc, st, parser := sbomProcessor(t)
	run := sbomRun()
	data, _ := os.ReadFile("../testdata/reports/sbom-cyclonedx/sample.cdx.xml")
	res, err := proc.Process(context.Background(), ingest.ProcessParams{Run: run, Parser: parser, IsSBOM: true, IsEphemeral: true, Open: openString(string(data))})
	if err != nil || res.Components != 0 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if sb, _, _ := st.GetSBOM(context.Background(), run.TenantID, run.AssetID); sb != nil {
		t.Error("an ephemeral SBOM run stored an SBOM")
	}
}

const vdrDocument = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5",
  "components": [
    {"bom-ref": "pkg:npm/lodash@4.17.20", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
    {"bom-ref": "pkg:npm/clean@1.0.0", "name": "clean", "version": "1.0.0", "purl": "pkg:npm/clean@1.0.0"}
  ],
  "vulnerabilities": [
    {"id": "CVE-2021-23337", "ratings": [{"severity": "high", "score": 7.2}], "cwes": [78],
     "affects": [{"ref": "pkg:npm/lodash@4.17.20"}]}
  ]
}`

func vdrParser(t *testing.T, extract string) *sbom.WasmSBOMParser {
	t.Helper()
	p, err := sbom.NewWasmSBOMParserFromSpec("cyclonedx", []byte("spec:\n  format: cyclonedx\n  options:\n    extractVulnerabilities: "+extract+"\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// With options.extractVulnerabilities the vulnerabilities a document states become findings of the family
// "sbom-cyclonedx", from the same read that fills the inventory. A later upload that no longer states one closes it, and
// never touches what a scanner reported.
func TestProcessSBOMExtractsVulnerabilitiesWhenTheOptionIsOn(t *testing.T) {
	ctx := context.Background()
	proc, st, _ := sbomProcessor(t)
	parser := vdrParser(t, "true")
	if !parser.ExtractsVulnerabilities() {
		t.Fatal("the spec option was not read")
	}
	run := sbomRun()

	other := ingest.CloseScope{TenantID: run.TenantID, ScanSourceID: run.ScanSourceID, ScannerFamily: "trivy", AssetID: run.AssetID, Track: "main"}
	if _, err := ingest.NewEngine(st).MergeBatch(ctx, other, domain.NewID(), run.ApplicationID, []ingest.StagedRecord{rec("keep-me")}); err != nil {
		t.Fatal(err)
	}

	res, err := proc.Process(ctx, ingest.ProcessParams{Run: run, Parser: parser, IsSBOM: true, ScanFinished: time.Now().UTC(), Open: openString(vdrDocument)})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res.Components != 2 || res.Stats.Created != 1 {
		t.Fatalf("result = %+v, want 2 components and 1 finding created", res)
	}
	if _, comps, _ := st.GetSBOM(ctx, run.TenantID, run.AssetID); len(comps) != 2 {
		t.Errorf("stored components = %d, want 2", len(comps))
	}
	var got *domain.Finding
	all, _ := st.ListFindings(ctx, run.TenantID)
	for _, f := range all {
		if f.RuleScannerFamily == "sbom-cyclonedx" {
			got = f
		}
	}
	if got == nil || got.RuleID != "CVE-2021-23337" || got.Severity != domain.SeverityHigh || got.State != domain.StateOpen {
		t.Fatalf("the statement is not an open high finding of the family sbom-cyclonedx: %+v", got)
	}

	// the same component set, without the statement: the finding it made is closed, the scanner's is not
	clean := strings.Replace(vdrDocument, `"affects": [{"ref": "pkg:npm/lodash@4.17.20"}]`, `"affects": []`, 1)
	run2 := *run
	run2.ID = domain.NewID()
	res, err = proc.Process(ctx, ingest.ProcessParams{Run: &run2, Parser: parser, IsSBOM: true, ScanFinished: time.Now().UTC().Add(time.Minute), Open: openString(clean)})
	if err != nil {
		t.Fatalf("second Process: %v", err)
	}
	if res.Stats.Closed != 1 {
		t.Errorf("a document that no longer states the vulnerability must close its finding: %+v", res.Stats)
	}
	if fs, _ := st.GetFindingsByKeys(ctx, run.TenantID, []string{"keep-me"}); fs["keep-me"] == nil || fs["keep-me"].State != domain.StateOpen {
		t.Error("closing a statement's finding touched a scanner's finding")
	}
}

// With the option off, which is the default, the same document creates no finding.
func TestProcessSBOMDoesNotExtractByDefault(t *testing.T) {
	for _, extract := range []string{"false", ""} {
		proc, st, _ := sbomProcessor(t)
		parser := vdrParser(t, extract)
		if extract == "" {
			parser, _ = sbom.NewWasmSBOMParserFromSpec("cyclonedx", []byte("spec:\n  format: cyclonedx\n"), nil)
		}
		run := sbomRun()
		res, err := proc.Process(context.Background(), ingest.ProcessParams{Run: run, Parser: parser, IsSBOM: true, ScanFinished: time.Now().UTC(), Open: openString(vdrDocument)})
		if err != nil {
			t.Fatalf("extract=%q: %v", extract, err)
		}
		if res.Components != 2 || res.Stats.Created != 0 {
			t.Errorf("extract=%q: result = %+v, want 2 components and no finding", extract, res)
		}
		if all, _ := st.ListFindings(context.Background(), run.TenantID); len(all) != 0 {
			t.Errorf("extract=%q: %d findings were created", extract, len(all))
		}
	}
}

// A statement about a component the document does not contain is not attached to a guess: the run ends with record errors
// and closes nothing.
func TestProcessSBOMStatementOfAnUnknownComponentIsARecordError(t *testing.T) {
	proc, _, _ := sbomProcessor(t)
	doc := strings.Replace(vdrDocument, `"affects": [{"ref": "pkg:npm/lodash@4.17.20"}]`, `"affects": [{"ref": "urn:somewhere:else"}]`, 1)
	res, err := proc.Process(context.Background(), ingest.ProcessParams{Run: sbomRun(), Parser: vdrParser(t, "true"), IsSBOM: true, ScanFinished: time.Now().UTC(), Open: openString(doc)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stats.Created != 0 || res.Status != domain.RunCompletedWithErrors {
		t.Errorf("result = %+v, want completed with errors and no finding", res)
	}
}

const sampleOpenVEX = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-2023-001",
  "author": "Security Team",
  "timestamp": "2023-10-15T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2023-44487",
        "aliases": ["GHSA-m425-mq94-257g"]
      },
      "products": [
        {
          "@id": "pkg:golang/google.golang.org/grpc@v1.58.2",
          "subcomponents": []
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "HTTP/2 rapid reset attack mitigated by fronting Envoy proxy."
    }
  ]
}`

func TestProcessSBOM_OpenVEX_AppliesVEXStatements(t *testing.T) {
	ctx := context.Background()
	proc, st, _ := sbomProcessor(t)
	run := sbomRun()
	run.Context.VEXDecider = "user:triager@acme.example" // uploaded by a triager (docs/51 step 1.2)

	vulnID := "CVE-2023-44487"
	purl := "pkg:golang/google.golang.org/grpc@v1.58.2"
	initialFinding := &domain.Finding{
		ID:              domain.NewID(),
		TenantID:        run.TenantID,
		ApplicationID:   run.ApplicationID,
		AssetID:         run.AssetID,
		FindingKey:      "finding-grpc-cve",
		RuleID:          vulnID,
		VulnerabilityID: &vulnID,
		Location: domain.Location{
			Package: &domain.PackageLocation{
				Purl:             purl,
				PurlBase:         "pkg:golang/google.golang.org/grpc",
				InstalledVersion: "v1.58.2",
			},
		},
		Severity: domain.SeverityCritical,
		State:    domain.StateOpen,
		Version:  1,
	}
	if err := st.UpsertFindings(ctx, run.TenantID, []*domain.Finding{initialFinding}); err != nil {
		t.Fatal(err)
	}

	parser, err := sbom.NewWasmSBOMParserFromSpec("openvex", []byte("spec:\n  format: openvex\n  options:\n    extractVEX: true\n"), nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := proc.Process(ctx, ingest.ProcessParams{
		Run:          run,
		Parser:       parser,
		IsSBOM:       true,
		ScanFinished: time.Now().UTC(),
		Open:         openString(sampleOpenVEX),
	})
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if res.Status != domain.RunCompleted {
		t.Fatalf("run status = %s, want %s", res.Status, domain.RunCompleted)
	}

	// Verify finding transitioned to not_affected and triage fields were populated
	findings, err := st.GetFindingsByKeys(ctx, run.TenantID, []string{"finding-grpc-cve"})
	if err != nil {
		t.Fatal(err)
	}
	f := findings["finding-grpc-cve"]
	if f == nil {
		t.Fatal("finding missing in store")
	}
	if f.State != domain.StateNotAffected {
		t.Errorf("expected state not_affected, got %s", f.State)
	}
	if f.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("expected justification vulnerable_code_not_in_execute_path, got %s", f.Justification)
	}
	if f.ImpactStatement != "HTTP/2 rapid reset attack mitigated by fronting Envoy proxy." {
		t.Errorf("expected impact statement, got %s", f.ImpactStatement)
	}
}

func TestProcessSBOM_VEXOptionDisabled_DoesNotApplyVEX(t *testing.T) {
	ctx := context.Background()
	proc, st, _ := sbomProcessor(t)
	run := sbomRun()

	vulnID := "CVE-2023-44487"
	purl := "pkg:golang/google.golang.org/grpc@v1.58.2"
	initialFinding := &domain.Finding{
		ID:              domain.NewID(),
		TenantID:        run.TenantID,
		ApplicationID:   run.ApplicationID,
		AssetID:         run.AssetID,
		FindingKey:      "finding-grpc-cve-2",
		RuleID:          vulnID,
		VulnerabilityID: &vulnID,
		Location: domain.Location{
			Package: &domain.PackageLocation{
				Purl:             purl,
				PurlBase:         "pkg:golang/google.golang.org/grpc",
				InstalledVersion: "v1.58.2",
			},
		},
		Severity: domain.SeverityCritical,
		State:    domain.StateOpen,
		Version:  1,
	}
	if err := st.UpsertFindings(ctx, run.TenantID, []*domain.Finding{initialFinding}); err != nil {
		t.Fatal(err)
	}

	// Parser with extractVEX: false
	parser, err := sbom.NewWasmSBOMParserFromSpec("openvex", []byte("spec:\n  format: openvex\n  options:\n    extractVEX: false\n"), nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := proc.Process(ctx, ingest.ProcessParams{
		Run:          run,
		Parser:       parser,
		IsSBOM:       true,
		ScanFinished: time.Now().UTC(),
		Open:         openString(sampleOpenVEX),
	})
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if res.Status != domain.RunCompleted {
		t.Fatalf("run status = %s, want %s", res.Status, domain.RunCompleted)
	}

	// Verify finding remains open
	findings, err := st.GetFindingsByKeys(ctx, run.TenantID, []string{"finding-grpc-cve-2"})
	if err != nil {
		t.Fatal(err)
	}
	f := findings["finding-grpc-cve-2"]
	if f == nil {
		t.Fatal("finding missing in store")
	}
	if f.State != domain.StateOpen {
		t.Errorf("expected state open, got %s", f.State)
	}
}

func TestProcessSBOM_CycloneDX_EmbeddedVEX_AppliesStatements(t *testing.T) {
	ctx := context.Background()
	proc, st, _ := sbomProcessor(t)
	run := sbomRun()
	run.Context.VEXDecider = "user:triager@acme.example" // uploaded by a triager (docs/51 step 1.2)

	vulnID := "CVE-2021-44228"
	purl := "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	initialFinding := &domain.Finding{
		ID:              domain.NewID(),
		TenantID:        run.TenantID,
		ApplicationID:   run.ApplicationID,
		AssetID:         run.AssetID,
		FindingKey:      "finding-log4j-cve",
		RuleID:          vulnID,
		VulnerabilityID: &vulnID,
		Location: domain.Location{
			Package: &domain.PackageLocation{
				Purl:             purl,
				PurlBase:         "pkg:maven/org.apache.logging.log4j/log4j-core",
				InstalledVersion: "2.14.1",
			},
		},
		Severity: domain.SeverityCritical,
		State:    domain.StateOpen,
		Version:  1,
	}
	if err := st.UpsertFindings(ctx, run.TenantID, []*domain.Finding{initialFinding}); err != nil {
		t.Fatal(err)
	}

	cdxWithVEX := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "bom-ref": "log4j-ref",
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "JndiLookup class stripped at build time"
      },
      "affects": [{"ref": "log4j-ref"}]
    }
  ]
}`

	parser, err := sbom.NewWasmSBOMParserFromSpec("cyclonedx", []byte("spec:\n  format: cyclonedx\n  options:\n    extractVulnerabilities: false\n    extractVEX: true\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !parser.ExtractsVEX() {
		t.Fatal("expected ExtractsVEX() to be true")
	}

	res, err := proc.Process(ctx, ingest.ProcessParams{
		Run:          run,
		Parser:       parser,
		IsSBOM:       true,
		ScanFinished: time.Now().UTC(),
		Open:         openString(cdxWithVEX),
	})
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if res.Status != domain.RunCompleted || res.Components != 1 {
		t.Fatalf("result = %+v, want completed with 1 component", res)
	}

	findings, err := st.GetFindingsByKeys(ctx, run.TenantID, []string{"finding-log4j-cve"})
	if err != nil {
		t.Fatal(err)
	}
	f := findings["finding-log4j-cve"]
	if f == nil {
		t.Fatal("finding missing in store")
	}
	if f.State != domain.StateNotAffected {
		t.Errorf("expected state not_affected, got %s", f.State)
	}
	if f.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("expected justification vulnerable_code_not_in_execute_path, got %s", f.Justification)
	}
	if f.ImpactStatement != "JndiLookup class stripped at build time" {
		t.Errorf("expected impact statement, got %q", f.ImpactStatement)
	}
}

func TestProcessSBOM_VEX_PreservesNewerHumanDecision(t *testing.T) {
	ctx := context.Background()
	proc, st, _ := sbomProcessor(t)
	run := sbomRun()

	vulnID := "CVE-2023-44487"
	purl := "pkg:golang/google.golang.org/grpc@v1.58.2"
	initialFinding := &domain.Finding{
		ID:              domain.NewID(),
		TenantID:        run.TenantID,
		ApplicationID:   run.ApplicationID,
		AssetID:         run.AssetID,
		FindingKey:      "finding-grpc-human",
		RuleID:          vulnID,
		VulnerabilityID: &vulnID,
		Location: domain.Location{
			Package: &domain.PackageLocation{
				Purl:             purl,
				PurlBase:         "pkg:golang/google.golang.org/grpc",
				InstalledVersion: "v1.58.2",
			},
		},
		Severity: domain.SeverityCritical,
		State:    domain.StateOpen,
		Version:  1,
	}
	if err := st.UpsertFindings(ctx, run.TenantID, []*domain.Finding{initialFinding}); err != nil {
		t.Fatal(err)
	}

	// Simulate a human triager marking the finding under_investigation in 2026 (after the 2023 OpenVEX timestamp).
	humanAt := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	evs, err := domain.ApplyTriage(initialFinding, domain.TriageRequest{
		State: domain.StateUnderInvestigation,
		Note:  "Investigating exposure manually",
	}, "user:sara@acme.example", humanAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateFindingTriage(ctx, run.TenantID, initialFinding, initialFinding.Version, evs); err != nil {
		t.Fatal(err)
	}

	parser, err := sbom.NewWasmSBOMParserFromSpec("openvex", []byte("spec:\n  format: openvex\n  options:\n    extractVEX: true\n"), nil)
	if err != nil {
		t.Fatal(err)
	}

	// sampleOpenVEX has timestamp 2023-10-15T00:00:00Z, which is older than humanAt.
	res, err := proc.Process(ctx, ingest.ProcessParams{
		Run:          run,
		Parser:       parser,
		IsSBOM:       true,
		ScanFinished: time.Now().UTC(),
		Open:         openString(sampleOpenVEX),
	})
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if res.Status != domain.RunCompleted {
		t.Fatalf("run status = %s, want %s", res.Status, domain.RunCompleted)
	}

	findings, err := st.GetFindingsByKeys(ctx, run.TenantID, []string{"finding-grpc-human"})
	if err != nil {
		t.Fatal(err)
	}
	f := findings["finding-grpc-human"]
	if f == nil {
		t.Fatal("finding missing in store")
	}
	if f.State != domain.StateUnderInvestigation {
		t.Errorf("newer human decision was overwritten: state = %s, want %s", f.State, domain.StateUnderInvestigation)
	}
}

// docs/51 step 1.2: the same OpenVEX document uploaded with an ingest or CI token decides nothing. Before, any token that could
// upload set findings to not_affected, which the gate and the SLA then ignored. A finding of another asset is never touched.
func TestProcessSBOM_OpenVEX_FromACITokenDecidesNothing(t *testing.T) {
	ctx := context.Background()
	proc, st, _ := sbomProcessor(t)
	run := sbomRun() // no VEXDecider: the gateway sets it only for the triager role and higher

	vulnID := "CVE-2023-44487"
	f := &domain.Finding{
		ID: domain.NewID(), TenantID: run.TenantID, ApplicationID: run.ApplicationID, AssetID: run.AssetID,
		FindingKey: "finding-grpc-cve", RuleID: vulnID, VulnerabilityID: &vulnID,
		Location: domain.Location{Package: &domain.PackageLocation{Purl: "pkg:golang/google.golang.org/grpc@v1.58.2",
			PurlBase: "pkg:golang/google.golang.org/grpc", InstalledVersion: "v1.58.2"}},
		Severity: domain.SeverityCritical, State: domain.StateOpen, Version: 1,
	}
	other := *f
	other.ID, other.FindingKey, other.AssetID = domain.NewID(), "finding-grpc-other-asset", domain.NewID()
	if err := st.UpsertFindings(ctx, run.TenantID, []*domain.Finding{f, &other}); err != nil {
		t.Fatal(err)
	}
	parser, err := sbom.NewWasmSBOMParserFromSpec("openvex", []byte("spec:\n  format: openvex\n  options:\n    extractVEX: true\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	process := func() ingest.Result {
		res, err := proc.Process(ctx, ingest.ProcessParams{Run: run, Parser: parser, IsSBOM: true, ScanFinished: time.Now().UTC(), Open: openString(sampleOpenVEX)})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	res := process()
	if res.Stats.VEXApplied != 0 || res.Stats.VEXSkipped == 0 {
		t.Fatalf("an upload without the triager role must apply nothing and say so: %+v", res.Stats)
	}
	got, _ := st.GetFindingsByKeys(ctx, run.TenantID, []string{"finding-grpc-cve"})
	if got["finding-grpc-cve"].State != domain.StateOpen {
		t.Fatalf("SECURITY: a CI token decided a finding: %s", got["finding-grpc-cve"].State)
	}

	run.Context.VEXDecider = "user:triager@acme.example"
	if res := process(); res.Stats.VEXApplied != 1 {
		t.Fatalf("a triager's upload decides the asset's finding, and only it: %+v", res.Stats)
	}
	got, _ = st.GetFindingsByKeys(ctx, run.TenantID, []string{"finding-grpc-cve", "finding-grpc-other-asset"})
	if got["finding-grpc-cve"].State != domain.StateNotAffected {
		t.Fatalf("the asset's finding: %s", got["finding-grpc-cve"].State)
	}
	if got["finding-grpc-other-asset"].State != domain.StateOpen {
		t.Fatalf("a finding of another asset was decided by this asset's VEX: %s", got["finding-grpc-other-asset"].State)
	}
}
