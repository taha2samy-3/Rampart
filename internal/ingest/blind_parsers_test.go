package ingest

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"rampart/internal/domain"
	"rampart/internal/integrations"
	"rampart/internal/parsertest"
)

// blindSet is a server that was given no parser: an empty registry, and the parsers a control plane installed in the store.
func blindSet(t *testing.T) (*parserSet, *MemoryStore, uuid.UUID) {
	t.Helper()
	st := NewMemoryStore()
	for _, m := range parsertest.Manifests(t) {
		st.SaveClusterParser(m.Name, m.Stored)
	}
	reg := integrations.NewRegistry()
	if len(reg.ListParsers()) != 0 {
		t.Fatal("the registry of a server that was given nothing must be empty")
	}
	return newParserSet(reg, st), st, uuid.New()
}

func TestBlindServerFindsEveryInstalledParserByNameWithTheStableID(t *testing.T) {
	set, _, tid := blindSet(t)
	ctx := context.Background()
	n := 0
	for _, m := range parsertest.Manifests(t) {
		hint := strings.TrimPrefix(m.Name, "sbom-") // a client names "spdx" or "trivy"
		p := set.byName(ctx, tid, hint)
		if p == nil {
			t.Errorf("%s is installed and %q finds nothing", m.Name, hint)
			continue
		}
		want := "cluster:" + m.Name
		if m.Kind == "ClusterSBOMParser" {
			want = "cluster:" + m.Name // cluster:sbom-spdx
		}
		if got := p.Descriptor().ID; got != want {
			t.Errorf("%s has id %q, the runs and the compliance report read %q", m.Name, got, want)
		}
		n++
	}
	if n != 20 {
		t.Errorf("checked %d parsers, want 17 report parsers and 3 SBOM readers", n)
	}
	if got := set.byName(ctx, tid, "nonexistent"); got != nil {
		t.Errorf("a name nobody installed finds %v", got.Descriptor())
	}
}

func TestBlindServerDetectsAndReadsRealReportsFromWhatTheStoreHolds(t *testing.T) {
	set, _, tid := blindSet(t)
	ctx := context.Background()
	for _, c := range []struct {
		file, want string
		reads      bool // a report parser: read it and expect findings
	}{
		{"trivy/image-0.50.json", "cluster:trivy", true},
		{"grype/image-0.74.json", "cluster:grype", true},
		{"semgrep/scan-1.45.json", "cluster:semgrep", true},
		{"gitleaks/repo-8.18.json", "cluster:gitleaks", true},
		{"sarif/semgrep.sarif", "cluster:sarif", true},
		{"gitlab/gl-sast-report-15.json", "cluster:gitlab", true},
		{"genericjson/rampart-generic-v1.json", "cluster:genericjson", true}, // lua
		{"sbom-cyclonedx/sample.cdx.xml", "cluster:sbom-cyclonedx", false},
		{"sbom-spdx/sample.spdx", "cluster:sbom-spdx", false},
		{"sbom-syft/report.syft.json", "cluster:sbom-syft", false},
	} {
		path := filepath.Join("..", "testdata", "reports", c.file)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		head := data
		if len(head) > 64<<10 {
			head = head[:64<<10]
		}
		p, score := set.detect(ctx, tid, head, filepath.Base(c.file), "")
		if p == nil || p.Descriptor().ID != c.want || score < 40 {
			got := "none"
			if p != nil {
				got = p.Descriptor().ID
			}
			t.Errorf("%s: detected %s (score %d), want %s", c.file, got, score, c.want)
			continue
		}
		if !c.reads {
			continue
		}
		found := 0
		for f, err := range p.Parse(ctx, bytes.NewReader(data), domain.ParseContext{}) {
			if err != nil {
				t.Errorf("%s: parse error %v", c.file, err)
				break
			}
			_ = f
			found++
		}
		if found == 0 {
			t.Errorf("%s: parsed by %s and found nothing", c.file, c.want)
		}
	}
}

// A name an administrator installed for the cluster is reserved: a tenant's mapping parser of the same name must not take
// the uploads (it could not when the shipped parsers were compiled in, and it must not now that they are installed).
func TestAClusterParserNameIsReservedAgainstATenantParser(t *testing.T) {
	set, st, tid := blindSet(t)
	ctx := context.Background()
	mapping := `{"kind":"parser","runtime":"mapping","version":"1.0.0","family":"mine","category":"sca",
	  "detect":{"probes":[{"jsonHasKeys":["dependencies"]}]},"input":{"format":"json","records":"$.dependencies[*].vulns[*]","parent":"dep"},
	  "map":{"ruleId":"rec.id","title":"rec.id"}}`
	st.SaveTenantParser(tid, "trivy", []byte(mapping))
	st.SaveTenantParser(tid, "only-mine", []byte(mapping))

	if p := set.byName(ctx, tid, "trivy"); p == nil || p.Descriptor().ID != "cluster:trivy" {
		t.Fatalf("the cluster's trivy must win over the tenant's parser of the same name, got %+v", p)
	}
	if p := set.byName(ctx, tid, "only-mine"); p == nil || !strings.Contains(p.Descriptor().ID, "only-mine") {
		t.Fatalf("a name only the tenant installed still resolves to the tenant's parser, got %+v", p)
	}
	if p := set.byName(ctx, uuid.New(), "only-mine"); p != nil {
		t.Fatalf("another tenant must not see it, got %+v", p.Descriptor())
	}
}
