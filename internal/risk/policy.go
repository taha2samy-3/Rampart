package risk

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/cel-go/cel"
	"rampart/internal/domain"
)

// RiskPolicySpec is the spec of a RiskPolicy or ClusterRiskPolicy (docs/04, docs/06 section 2, D62): base points
// by severity, factors whose condition is a CEL expression, and the lower bounds of the bands. What is left out
// takes the built-in value, so `spec: {}` is the built-in policy.
type RiskPolicySpec struct {
	Base    map[string]int `json:"base,omitempty"`
	Factors []FactorSpec   `json:"factors,omitempty"`
	Bands   map[string]int `json:"bands,omitempty"`
}

// FactorSpec is one factor: when the condition holds, the points are added (or removed, when negative).
type FactorSpec struct {
	Name   string `json:"name"`
	When   string `json:"when"`
	Points int    `json:"points"`
	Reason string `json:"reason,omitempty"`
	// Group places the factor in the score bar (docs/13 section 6): severity, threat, context or reduction.
	// Empty: reduction for negative points, context otherwise.
	Group string `json:"group,omitempty"`
}

// Input is what a factor may read (the CEL environment). There is no clock: a stored score has no
// time-dependent factor (D28), so a policy cannot express one.
type Input struct {
	Finding FindingInput
	Vuln    VulnInput
	App     AppInput
}

// FindingInput: `finding.severity`, `.category`, `.rule_id`, `.scanner`, `.cwes`, `.secret_verified`, `.track`.
type FindingInput struct {
	Severity       string
	Category       string
	RuleID         string
	Scanner        string
	CWEs           []int
	SecretVerified bool
	Track          string
}

// VulnInput: `vuln.id`, `.kev`, `.epss`.
type VulnInput struct {
	ID   string
	KEV  bool
	EPSS float64
}

// AppInput: `app.criticality`, `.internet_facing`, `.data_classification`, `.compensating_controls`.
type AppInput struct {
	Criticality          string
	InternetFacing       bool
	DataClassification   []string
	CompensatingControls []string
}

func (in Input) activation() map[string]any {
	cwes := make([]int64, 0, len(in.Finding.CWEs))
	for _, c := range in.Finding.CWEs {
		cwes = append(cwes, int64(c))
	}
	str := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	return map[string]any{
		"finding": map[string]any{
			"severity": in.Finding.Severity, "category": in.Finding.Category, "rule_id": in.Finding.RuleID,
			"scanner": in.Finding.Scanner, "cwes": cwes, "secret_verified": in.Finding.SecretVerified, "track": in.Finding.Track,
		},
		"vuln": map[string]any{"id": in.Vuln.ID, "kev": in.Vuln.KEV, "epss": in.Vuln.EPSS},
		"app": map[string]any{
			"criticality": in.App.Criticality, "internet_facing": in.App.InternetFacing,
			"data_classification": str(in.App.DataClassification), "compensating_controls": str(in.App.CompensatingControls),
		},
	}
}

// BuiltinSpec is the policy of docs/06 section 2, as data. It gives exactly the numbers the code gave before
// D62 (a test compares them), so a tenant without a policy sees no change.
func BuiltinSpec() RiskPolicySpec {
	return RiskPolicySpec{
		Base: map[string]int{"critical": 600, "high": 400, "medium": 200, "low": 80, "info": 10},
		Factors: []FactorSpec{
			{Name: "KEV", When: "vuln.kev", Points: 300, Group: "threat", Reason: "Vulnerability listed in CISA Known Exploited Vulnerabilities catalog"},
			{Name: "EPSS_HIGH", When: "vuln.epss >= 0.5", Points: 150, Group: "threat", Reason: "EPSS exploitation probability is >= 50%"},
			{Name: "EPSS_MODERATE", When: "vuln.epss >= 0.1 && vuln.epss < 0.5", Points: 60, Group: "threat", Reason: "EPSS exploitation probability is >= 10%"},
			{Name: "SECRET_VERIFIED", When: "finding.secret_verified", Points: 250, Group: "threat", Reason: "Secret credential verified live against upstream provider"},
			{Name: "INTERNET_FACING", When: "app.internet_facing", Points: 100, Group: "context", Reason: "Asset or application is internet-facing"},
			{Name: "SENSITIVE_DATA", When: `app.data_classification.exists(d, d in ["pci", "pii", "phi"])`, Points: 80, Group: "context", Reason: "Application handles sensitive data (PCI, PII, or PHI)"},
			{Name: "APP_CRITICAL", When: `app.criticality == "critical"`, Points: 100, Group: "context", Reason: "Application business criticality is rated Critical"},
			{Name: "APP_HIGH", When: `app.criticality == "high"`, Points: 50, Group: "context", Reason: "Application business criticality is rated High"},
			{Name: "PRODUCTION_ENV", When: `finding.track in ["production", "prod"]`, Points: 60, Group: "context", Reason: "Finding detected in production environment"},
			{Name: "COMPENSATING_CONTROL", When: `finding.category == "dast" && app.compensating_controls.exists(c, c in ["waf", "api_gateway"])`, Points: -80, Group: "reduction",
				Reason: "The application is behind a web application firewall or an API gateway, which inspects the HTTP requests this finding needs"},
		},
		Bands: map[string]int{"critical": 800, "high": 600, "medium": 300},
	}
}

// Policy is a compiled risk policy.
type Policy struct {
	Spec    RiskPolicySpec
	base    map[string]int
	bands   map[string]int
	factors []compiledFactor
}

type compiledFactor struct {
	spec FactorSpec
	prog cel.Program
}

// Limits (D62): a policy is small and cheap to evaluate, because it runs for every finding of every scan.
const (
	MaxFactors   = 50
	MaxWhenLen   = 1024
	CELCostLimit = 1000 // per factor evaluation; the built-in factors cost under 30
)

var factorName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

var (
	celEnv     *cel.Env
	celEnvErr  error
	severities = []string{"critical", "high", "medium", "low", "info"}
)

func init() {
	celEnv, celEnvErr = cel.NewEnv(
		cel.Variable("finding", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("vuln", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("app", cel.MapType(cel.StringType, cel.DynType)),
	)
}

// ErrPolicy is a policy refused, with the reason in its message.
var ErrPolicy = errors.New("risk policy refused")

// ParseRiskPolicySpec reads a spec as JSON (the CRD's spec) and compiles it.
func ParseRiskPolicySpec(raw []byte) (*Policy, error) {
	var spec RiskPolicySpec
	if len(raw) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&spec); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPolicy, err)
		}
	}
	return Compile(spec)
}

// Compile validates a spec, fills what it leaves out from the built-in policy, and compiles every condition.
// A condition must be boolean, within the cost limit, and use only the fields of Input: each one is also run
// once against an input where every field is set, so a misspelt field is refused here instead of silently
// never matching at scoring time.
func Compile(spec RiskPolicySpec) (*Policy, error) {
	if celEnvErr != nil {
		return nil, celEnvErr
	}
	builtin := BuiltinSpec()
	p := &Policy{Spec: spec, base: map[string]int{}, bands: map[string]int{}}
	for _, s := range severities {
		p.base[s] = builtin.Base[s]
	}
	for k, v := range spec.Base {
		if !contains(severities, k) {
			return nil, fmt.Errorf("%w: base.%s is not a severity (critical, high, medium, low, info)", ErrPolicy, k)
		}
		if v < 0 || v > 1000 {
			return nil, fmt.Errorf("%w: base.%s must be between 0 and 1000", ErrPolicy, k)
		}
		p.base[k] = v
	}
	for k, v := range builtin.Bands {
		p.bands[k] = v
	}
	for k, v := range spec.Bands {
		if k != "critical" && k != "high" && k != "medium" {
			return nil, fmt.Errorf("%w: bands.%s: the bands are critical, high and medium (low starts at 0)", ErrPolicy, k)
		}
		p.bands[k] = v
	}
	if !(p.bands["critical"] > p.bands["high"] && p.bands["high"] > p.bands["medium"] && p.bands["medium"] > 0 && p.bands["critical"] <= 1000) {
		return nil, fmt.Errorf("%w: bands must satisfy 1000 >= critical > high > medium > 0", ErrPolicy)
	}
	factors := spec.Factors
	if factors == nil {
		factors = builtin.Factors
	}
	if len(factors) > MaxFactors {
		return nil, fmt.Errorf("%w: at most %d factors", ErrPolicy, MaxFactors)
	}
	seen := map[string]bool{}
	probe := fullInput().activation()
	for _, f := range factors {
		if !factorName.MatchString(f.Name) || seen[f.Name] {
			return nil, fmt.Errorf("%w: factor name %q must be unique, start with a letter and use letters, digits, _ or -", ErrPolicy, f.Name)
		}
		seen[f.Name] = true
		if f.Points < -1000 || f.Points > 1000 || f.Points == 0 {
			return nil, fmt.Errorf("%w: factor %s: points must be between -1000 and 1000 and not 0", ErrPolicy, f.Name)
		}
		if f.Group != "" && !contains([]string{"severity", "threat", "context", "reduction"}, f.Group) {
			return nil, fmt.Errorf("%w: factor %s: group must be severity, threat, context or reduction", ErrPolicy, f.Name)
		}
		if strings.TrimSpace(f.When) == "" || len(f.When) > MaxWhenLen {
			return nil, fmt.Errorf("%w: factor %s: when must be a CEL condition of at most %d characters", ErrPolicy, f.Name, MaxWhenLen)
		}
		ast, iss := celEnv.Compile(f.When)
		if iss != nil && iss.Err() != nil {
			return nil, fmt.Errorf("%w: factor %s: %v", ErrPolicy, f.Name, iss.Err())
		}
		if ast.OutputType() != cel.BoolType && ast.OutputType() != cel.DynType {
			return nil, fmt.Errorf("%w: factor %s: when must be true or false, not %s", ErrPolicy, f.Name, ast.OutputType())
		}
		prog, err := celEnv.Program(ast, cel.CostLimit(CELCostLimit))
		if err != nil {
			return nil, fmt.Errorf("%w: factor %s: %v", ErrPolicy, f.Name, err)
		}
		out, _, err := prog.Eval(probe)
		if err != nil {
			return nil, fmt.Errorf("%w: factor %s: %v (the fields are finding.severity, .category, .rule_id, .scanner, .cwes, .secret_verified, .track; vuln.id, .kev, .epss; app.criticality, .internet_facing, .data_classification, .compensating_controls)", ErrPolicy, f.Name, err)
		}
		if _, ok := out.Value().(bool); !ok {
			return nil, fmt.Errorf("%w: factor %s: when must be true or false", ErrPolicy, f.Name)
		}
		p.factors = append(p.factors, compiledFactor{spec: f, prog: prog})
	}
	return p, nil
}

// fullInput sets every field, so a condition that reads a field that does not exist fails at compile time.
func fullInput() Input {
	return Input{
		Finding: FindingInput{Severity: "high", Category: "sast", RuleID: "r", Scanner: "s", CWEs: []int{79}, SecretVerified: true, Track: "main"},
		Vuln:    VulnInput{ID: "CVE-0000-0000", KEV: true, EPSS: 0.5},
		App:     AppInput{Criticality: "high", InternetFacing: true, DataClassification: []string{"pii"}, CompensatingControls: []string{"waf"}},
	}
}

var builtinPolicy *Policy

// Builtin is the compiled built-in policy.
func Builtin() *Policy {
	if builtinPolicy == nil {
		p, err := Compile(RiskPolicySpec{})
		if err != nil {
			panic("risk: the built-in policy does not compile: " + err.Error())
		}
		builtinPolicy = p
	}
	return builtinPolicy
}

// Evaluate scores one input. A condition that fails at run time (it should not, after the probe at compile time)
// counts as false and is reported in Errors: a policy error never makes a score higher (D25).
func (p *Policy) Evaluate(in Input) ScoreBreakdown {
	sev := strings.ToLower(in.Finding.Severity)
	base, ok := p.base[sev]
	if !ok {
		base = p.base["low"] // an unknown severity weighs as low, as before D62
	}
	b := ScoreBreakdown{BaseSeverity: domain.Severity(sev), BasePoints: base, Factors: []Factor{}, HasKEV: in.Vuln.KEV, EPSSScore: in.Vuln.EPSS}
	total := base
	act := in.activation()
	for _, f := range p.factors {
		out, _, err := f.prog.Eval(act)
		if err != nil {
			b.Errors = append(b.Errors, f.spec.Name+": "+err.Error())
			continue
		}
		if hit, ok := out.Value().(bool); ok && hit {
			b.Factors = append(b.Factors, Factor{Name: f.spec.Name, Points: f.spec.Points, Reason: f.spec.Reason, Group: groupOf(f.spec)})
			total += f.spec.Points
		}
	}
	b.TotalScore = max(0, min(1000, total))
	switch {
	case b.TotalScore >= p.bands["critical"]:
		b.Band = domain.SeverityCritical
	case b.TotalScore >= p.bands["high"]:
		b.Band = domain.SeverityHigh
	case b.TotalScore >= p.bands["medium"]:
		b.Band = domain.SeverityMedium
	default:
		b.Band = domain.SeverityLow
	}
	return b
}

func groupOf(f FactorSpec) string {
	switch {
	case f.Group != "":
		return f.Group
	case f.Points < 0:
		return "reduction"
	}
	return "context"
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
