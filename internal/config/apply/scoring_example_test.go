package apply_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/risk"
)

// docs/examples/payments-scoring/ is the worked example of docs/36 section 15: one application and every resource that
// decides its score. The server accepts every document, and the scores and deadlines the document states are the ones the
// policies in it give. The numbers are asserted here, so the example and the text cannot drift from the code.
func TestPaymentsScoringExample(t *testing.T) {
	raw := readExample(t)
	ctx := context.Background()
	if _, err := apply.NewApplier(apply.NewMemoryConfigStore()).ApplyMultiDocument(ctx, raw); err != nil {
		t.Fatalf("the server refuses the example: %v", err)
	}

	spec := map[string][]byte{}
	for _, doc := range strings.Split(string(raw), "\n---") {
		var d struct {
			Kind string         `yaml:"kind"`
			Spec map[string]any `yaml:"spec"`
		}
		if err := yaml.Unmarshal([]byte(doc), &d); err != nil || d.Kind == "" {
			continue
		}
		b, _ := json.Marshal(d.Spec)
		spec[d.Kind] = b
	}

	var as domain.ApplicationSpec
	if err := json.Unmarshal(spec["Application"], &as); err != nil {
		t.Fatal(err)
	}
	app, err := as.ToApplication(uuid.New(), uuid.New(), "payments-api")
	if err != nil {
		t.Fatal(err)
	}
	in := risk.AppInput{Criticality: app.BusinessCriticality, InternetFacing: app.InternetFacing, DataClassification: app.DataClassification, CompensatingControls: app.CompensatingControls}

	mine, err := risk.ParseRiskPolicySpec(spec["RiskPolicy"])
	if err != nil {
		t.Fatalf("the risk policy of the example: %v", err)
	}
	builtin := risk.Builtin()
	sla, err := domain.ParseSLAPolicySpec(spec["SLAPolicy"])
	if err != nil {
		t.Fatalf("the SLA policy of the example: %v", err)
	}
	built := domain.DefaultSLAPolicy()

	scan := risk.Input{
		Finding: risk.FindingInput{Severity: "high", Category: "sca", RuleID: "CVE-2024-0001", Scanner: "trivy", Track: "main"},
		Vuln:    risk.VulnInput{ID: "CVE-2024-0001", EPSS: 0.2},
		App:     in,
	}
	onDevelop := scan
	onDevelop.Finding.Track = "develop"
	dast := risk.Input{
		Finding: risk.FindingInput{Severity: "medium", Category: "dast", RuleID: "xss", Scanner: "zap", Track: "main"},
		App:     in,
	}

	type want struct {
		in          risk.Input
		builtin     int
		builtinBand string
		builtinDays int
		mine        int
		mineBand    string
		mineDays    int
	}
	for name, w := range map[string]want{
		"a high dependency finding, EPSS 20%, on main":    {scan, 740, "high", 7, 850, "critical", 2},
		"the same finding on develop":                     {onDevelop, 740, "high", 7, 730, "high", 7},
		"a medium finding of a dynamic scan behind a WAF": {dast, 400, "medium", 30, 510, "medium", 30},
	} {
		b := builtin.Evaluate(w.in)
		m := mine.Evaluate(w.in)
		if b.TotalScore != w.builtin || string(b.Band) != w.builtinBand || built.Days(b.Band, in.Criticality) != w.builtinDays {
			t.Errorf("%s, built-in policy: score %d band %s days %d; want %d %s %d", name, b.TotalScore, b.Band, built.Days(b.Band, in.Criticality), w.builtin, w.builtinBand, w.builtinDays)
		}
		if m.TotalScore != w.mine || string(m.Band) != w.mineBand || sla.Days(m.Band, in.Criticality) != w.mineDays {
			t.Errorf("%s, the example's policy: score %d band %s days %d; want %d %s %d", name, m.TotalScore, m.Band, sla.Days(m.Band, in.Criticality), w.mine, w.mineBand, w.mineDays)
		}
	}

	// The two caps of the SLA policy. maxDays: a low finding of a low-criticality application has 365 days in the default
	// matrix and the example's matrix, and 90 once capped. kevDueDate: a finding on the CISA list is due by the end of the
	// CISA due date when that is earlier than its matrix deadline.
	if got := sla.Days(domain.SeverityLow, "low"); got != 90 {
		t.Errorf("maxDays 90 should cap a 365 day allowance: got %d", got)
	}
	if got := built.Days(domain.SeverityLow, "low"); got != 365 {
		t.Errorf("the built-in policy has no such cap: got %d", got)
	}
	start := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	cisa := time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC) // the work is due by the end of 3 March, before 4 March 09:00
	if got, want := sla.Due(domain.SeverityCritical, "critical", start, &cisa), cisa.Add(24*time.Hour); !got.Equal(want) {
		t.Errorf("CISA due date should win over the 2 day matrix deadline when it is earlier: got %s want %s", got, want)
	}
	cisaLate := time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC)
	if got, want := sla.Due(domain.SeverityCritical, "critical", start, &cisaLate), start.Add(48*time.Hour); !got.Equal(want) {
		t.Errorf("the matrix deadline should stand when the CISA date is later: got %s want %s", got, want)
	}
}

// readExample joins the files of the example, in the order of their names (the tenant is 01): the same text a person gets by
// applying them one after the other.
func readExample(t *testing.T) []byte {
	t.Helper()
	files, err := filepath.Glob("../../../docs/examples/payments-scoring/*.yaml")
	if err != nil || len(files) != 5 {
		t.Fatalf("the example is five files (tenant, cluster feed, application, risk policy, SLA policy): got %d, %v", len(files), err)
	}
	sort.Strings(files)
	var all []byte
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, b...)
		all = append(all, []byte("\n---\n")...)
	}
	return all
}

// The example restates the built-in factors, and says which three it changed or added. The others must stay the built-in ones,
// condition and points, or the file would say "as the built-in policy has them" about something that is not.
func TestPaymentsExampleRestatesTheBuiltinFactors(t *testing.T) {
	var doc struct {
		Kind string         `yaml:"kind"`
		Spec map[string]any `yaml:"spec"`
	}
	for _, d := range strings.Split(string(readExample(t)), "\n---") {
		var x struct {
			Kind string         `yaml:"kind"`
			Spec map[string]any `yaml:"spec"`
		}
		if yaml.Unmarshal([]byte(d), &x) == nil && x.Kind == "RiskPolicy" {
			doc = x
		}
	}
	raw, _ := json.Marshal(doc.Spec)
	var mine risk.RiskPolicySpec
	if err := json.Unmarshal(raw, &mine); err != nil {
		t.Fatal(err)
	}
	builtin := map[string]risk.FactorSpec{}
	for _, f := range risk.BuiltinSpec().Factors {
		builtin[f.Name] = f
	}
	changed := map[string]bool{"INTERNET_FACING": true, "PRODUCTION_ENV": true}
	added := map[string]bool{"NON_PRODUCTION": true}
	seen := map[string]bool{}
	for _, f := range mine.Factors {
		seen[f.Name] = true
		b, ok := builtin[f.Name]
		switch {
		case added[f.Name]:
			if ok {
				t.Errorf("%s is marked new but the built-in policy has it", f.Name)
			}
		case changed[f.Name]:
			if !ok || (b.When == f.When && b.Points == f.Points) {
				t.Errorf("%s is marked changed but is the built-in factor", f.Name)
			}
		default:
			if !ok || b.When != f.When || b.Points != f.Points {
				t.Errorf("%s should be the built-in factor (condition and points): example %q %d, built-in %q %d", f.Name, f.When, f.Points, b.When, b.Points)
			}
		}
	}
	for name := range builtin {
		if !seen[name] {
			t.Errorf("the example leaves out the built-in factor %s: a policy that lists factors replaces the whole list", name)
		}
	}
	if len(mine.Factors) != 13 {
		t.Errorf("the file says thirteen factors (ten as built in, two changed, one new): got %d", len(mine.Factors))
	}
}

// The RiskPolicy example of docs/04 is the shape the server accepts. It used to show variables that do not exist, and the
// server refused it; this keeps the page honest.
func TestRiskPolicyExampleOfDocs04IsAccepted(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/04-crds.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	at := strings.Index(text, "### `RiskPolicy` / `ClusterRiskPolicy`")
	if at < 0 {
		t.Fatal("docs/04 has no RiskPolicy section")
	}
	rest := text[at:]
	open := strings.Index(rest, "```yaml\n")
	end := strings.Index(rest[open+8:], "```")
	if open < 0 || end < 0 {
		t.Fatal("the RiskPolicy section of docs/04 has no yaml block")
	}
	block := rest[open+8 : open+8+end]
	var doc struct {
		Kind string         `yaml:"kind"`
		Spec map[string]any `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte(block), &doc); err != nil || doc.Kind != "RiskPolicy" {
		t.Fatalf("the block does not parse as a RiskPolicy: %v", err)
	}
	spec, _ := json.Marshal(doc.Spec)
	p, err := risk.ParseRiskPolicySpec(spec)
	if err != nil {
		t.Fatalf("the server refuses the RiskPolicy example of docs/04: %v", err)
	}
	// With the built-in numbers restated, it scores like the built-in policy.
	in := risk.Input{
		Finding: risk.FindingInput{Severity: "high", Category: "sca"},
		Vuln:    risk.VulnInput{ID: "CVE-2024-0001", EPSS: 0.2},
		App:     risk.AppInput{Criticality: "critical", InternetFacing: true, DataClassification: []string{"pci"}},
	}
	if got, want := p.Evaluate(in).TotalScore, risk.Builtin().Evaluate(in).TotalScore; got != want {
		t.Errorf("the docs/04 example scores %d, the built-in policy %d", got, want)
	}
}

// A person applies the files one after the other, in the order of their names; each must be accepted when the ones before it are in.
func TestPaymentsExampleAppliesFileByFile(t *testing.T) {
	files, err := filepath.Glob("../../../docs/examples/payments-scoring/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no example files: %v", err)
	}
	sort.Strings(files)
	applier := apply.NewApplier(apply.NewMemoryConfigStore())
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := applier.ApplyMultiDocument(context.Background(), b); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
	}
}
