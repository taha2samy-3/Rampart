package ingest_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// Embedded VEX inside a CycloneDX SBOM document applies exploitability decisions to existing findings.
func TestProcessSBOM_EmbeddedVEXAppliesDecisions(t *testing.T) {
	ctx := context.Background()
	proc, st, parser := sbomProcessor(t)
	run := sbomRun()

	vulnID := "CVE-2021-23337"
	purl := "pkg:npm/lodash@4.17.20"
	base := "pkg:npm/lodash"
	f := &domain.Finding{
		ID: domain.NewID(), TenantID: run.TenantID, FindingKey: "k-1",
		ApplicationID: run.ApplicationID, AssetID: run.AssetID, Track: "main",
		RuleScannerFamily: "trivy", RuleID: vulnID, VulnerabilityID: &vulnID,
		Location: domain.Location{Package: &domain.PackageLocation{Purl: purl, PurlBase: base}},
		State: domain.StateOpen, Version: 1,
	}
	if err := st.UpsertFindings(ctx, run.TenantID, []*domain.Finding{f}); err != nil {
		t.Fatal(err)
	}

	doc := `{
	  "bomFormat": "CycloneDX", "specVersion": "1.5",
	  "components": [
	    {"bom-ref": "pkg:npm/lodash@4.17.20", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}
	  ],
	  "vulnerabilities": [
	    {
	      "id": "CVE-2021-23337",
	      "affects": [{"ref": "pkg:npm/lodash@4.17.20"}],
	      "analysis": {
	        "state": "not_affected",
	        "justification": "code_not_reachable",
	        "detail": "Function is never called"
	      }
	    }
	  ]
	}`

	res, err := proc.Process(ctx, ingest.ProcessParams{
		Run: run, Parser: parser, IsSBOM: true, ScanFinished: time.Now().UTC(),
		Open: openString(doc),
	})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res.Components != 1 {
		t.Fatalf("res.Components = %d, want 1", res.Components)
	}

	findings, err := st.GetFindingsByKeys(ctx, run.TenantID, []string{"k-1"})
	if err != nil || findings["k-1"] == nil {
		t.Fatalf("lookup finding: %v", err)
	}
	got := findings["k-1"]
	if got.State != domain.StateNotAffected {
		t.Fatalf("finding state = %s, want not_affected", got.State)
	}
	if got.Justification != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("finding justification = %s, want vulnerable_code_not_in_execute_path", got.Justification)
	}
}

func TestProcessRun_StandaloneOpenVEXUpload(t *testing.T) {
	ctx := context.Background()
	st := ingest.NewMemoryStore()
	objs := objectstore.NewMemory()
	proc := ingest.NewProcessor(st, nil, objs, nil)

	run := sbomRun()
	cve := "CVE-2024-1234"
	purl := "pkg:golang/github.com/gin-gonic/gin@v1.9.0"
	base := "pkg:golang/github.com/gin-gonic/gin"
	f := &domain.Finding{
		ID: domain.NewID(), TenantID: run.TenantID, ApplicationID: run.ApplicationID, AssetID: run.AssetID,
		FindingKey: "k-gin", RuleScannerFamily: "trivy", RuleID: cve, VulnerabilityID: &cve,
		Location: domain.Location{Package: &domain.PackageLocation{Purl: purl, PurlBase: base}},
		State: domain.StateOpen, Version: 1,
	}
	if err := st.UpsertFindings(ctx, run.TenantID, []*domain.Finding{f}); err != nil {
		t.Fatal(err)
	}

	vexContent := `{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://rampart.aspm.dev/vex/test-ci",
		"author": "CI Pipeline",
		"timestamp": "2026-11-21T09:00:00Z",
		"version": 1,
		"statements": [
			{
				"vulnerability": {"name": "CVE-2024-1234"},
				"products": [{"@id": "pkg:golang/github.com/gin-gonic/gin@v1.9.0"}],
				"status": "not_affected",
				"justification": "component_not_present",
				"impact_statement": "Gin package is not included in binary"
			}
		]
	}`

	h := sha256.Sum256([]byte(vexContent))
	sha := hex.EncodeToString(h[:])
	objKey := "uploads/test-openvex.json"
	if err := objs.Write(ctx, objKey, []byte(vexContent), "application/json"); err != nil {
		t.Fatal(err)
	}

	uploadID := domain.NewID()
	upload := &domain.Upload{
		ID:           uploadID,
		TenantID:     run.TenantID,
		ScanSourceID: run.ScanSourceID,
		ObjectRef:    objKey,
		SizeBytes:    int64(len(vexContent)),
		SHA256:       sha,
		FormatHint:   "openvex",
	}
	if err := st.CreateUpload(ctx, upload); err != nil {
		t.Fatal(err)
	}

	run.UploadID = &uploadID
	run.Status = domain.RunQueued
	if err := st.CreateIngestRun(ctx, run); err != nil {
		t.Fatal(err)
	}

	if err := proc.HandleParse(ctx, jobs.ParseJobArgs{TenantID: run.TenantID, IngestRunID: run.ID}, 1); err != nil {
		t.Fatalf("HandleParse failed: %v", err)
	}

	updatedRun, err := st.GetIngestRun(ctx, run.TenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updatedRun.Status != domain.RunCompleted {
		t.Fatalf("expected RunCompleted, got %s (error: %s)", updatedRun.Status, updatedRun.Error)
	}
	if updatedRun.Stats.Parsed != 1 || updatedRun.Stats.Updated != 1 {
		t.Errorf("expected stats parsed=1, updated=1, got %+v", updatedRun.Stats)
	}

	// Verify finding updated in store
	findings, err := st.GetFindingsByKeys(ctx, run.TenantID, []string{"k-gin"})
	if err != nil || findings["k-gin"] == nil {
		t.Fatalf("finding lookup failed: %v", err)
	}
	updatedFinding := findings["k-gin"]
	if updatedFinding.State != domain.StateNotAffected {
		t.Errorf("expected state not_affected, got %s", updatedFinding.State)
	}
	if updatedFinding.Justification != "component_not_present" {
		t.Errorf("expected justification component_not_present, got %s", updatedFinding.Justification)
	}
}

func TestProcessRun_StandaloneCSAFUpload(t *testing.T) {
	ctx := context.Background()
	st := ingest.NewMemoryStore()
	objs := objectstore.NewMemory()
	proc := ingest.NewProcessor(st, nil, objs, nil)

	run := sbomRun()
	cve := "CVE-2024-8888"
	purl := "pkg:npm/express@4.18.2"
	base := "pkg:npm/express"
	f := &domain.Finding{
		ID: domain.NewID(), TenantID: run.TenantID, ApplicationID: run.ApplicationID, AssetID: run.AssetID,
		FindingKey: "k-exp", RuleScannerFamily: "trivy", RuleID: cve, VulnerabilityID: &cve,
		Location: domain.Location{Package: &domain.PackageLocation{Purl: purl, PurlBase: base}},
		State: domain.StateOpen, Version: 1,
	}
	if err := st.UpsertFindings(ctx, run.TenantID, []*domain.Finding{f}); err != nil {
		t.Fatal(err)
	}

	csafContent := `{
		"document": {
			"category": "csaf_vex",
			"csaf_version": "2.0",
			"title": "Advisory for Express",
			"publisher": {"category": "vendor", "name": "Security Team"},
			"tracking": {"id": "CSAF-TEST-1", "current_release_date": "2026-11-21T09:00:00Z"}
		},
		"product_tree": {
			"full_product_names": [
				{"product_id": "P-1", "name": "express", "product_identification_helper": {"purl": "pkg:npm/express@4.18.2"}}
			]
		},
		"vulnerabilities": [
			{
				"cve": "CVE-2024-8888",
				"product_status": {"known_not_affected": ["P-1"]},
				"flags": [{"label": "vulnerable_code_not_in_execute_path", "product_ids": ["P-1"]}]
			}
		]
	}`

	h := sha256.Sum256([]byte(csafContent))
	sha := hex.EncodeToString(h[:])
	objKey := "uploads/test-csaf.json"
	if err := objs.Write(ctx, objKey, []byte(csafContent), "application/json"); err != nil {
		t.Fatal(err)
	}

	uploadID := domain.NewID()
	upload := &domain.Upload{
		ID:           uploadID,
		TenantID:     run.TenantID,
		ScanSourceID: run.ScanSourceID,
		ObjectRef:    objKey,
		SizeBytes:    int64(len(csafContent)),
		SHA256:       sha,
		FormatHint:   "csaf",
	}
	if err := st.CreateUpload(ctx, upload); err != nil {
		t.Fatal(err)
	}

	run.UploadID = &uploadID
	run.Status = domain.RunQueued
	if err := st.CreateIngestRun(ctx, run); err != nil {
		t.Fatal(err)
	}

	if err := proc.HandleParse(ctx, jobs.ParseJobArgs{TenantID: run.TenantID, IngestRunID: run.ID}, 1); err != nil {
		t.Fatalf("HandleParse failed: %v", err)
	}

	updatedRun, err := st.GetIngestRun(ctx, run.TenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updatedRun.Status != domain.RunCompleted {
		t.Fatalf("expected RunCompleted, got %s (error: %s)", updatedRun.Status, updatedRun.Error)
	}

	// Verify finding updated in store
	findings, err := st.GetFindingsByKeys(ctx, run.TenantID, []string{"k-exp"})
	if err != nil || findings["k-exp"] == nil {
		t.Fatalf("finding lookup failed: %v", err)
	}
	updatedFinding := findings["k-exp"]
	if updatedFinding.State != domain.StateNotAffected {
		t.Errorf("expected state not_affected, got %s", updatedFinding.State)
	}
	if updatedFinding.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("expected justification vulnerable_code_not_in_execute_path, got %s", updatedFinding.Justification)
	}
}
