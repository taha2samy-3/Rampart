package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DTrackSourceSpec is the `dependencyTrack` block of a ScanSource of type apiPull (docs/10 §8, docs/16 D92). Only
// what this version does is accepted: a field of doc 10 §8 that is not built (policy violations, SBOM pull,
// SBOM forwarding, a managed DT notification rule, export of decisions) is refused by name rather than accepted
// and ignored, so a configuration never claims what the server does not do.
type DTrackSourceSpec struct {
	Projects   DTrackProjectFilter `json:"projects,omitempty"`
	Mapping    DTrackMappingSpec   `json:"mapping,omitempty"`
	Pull       DTrackPullSpec      `json:"pull,omitempty"`
	Webhook    DTrackWebhookSpec   `json:"webhook,omitempty"`
	TriageSync DTrackTriageSpec    `json:"triageSync,omitempty"`
}

// DTrackProjectFilter chooses the projects a source syncs.
type DTrackProjectFilter struct {
	OnlyActive  *bool    `json:"onlyActive,omitempty"` // default true
	Tags        []string `json:"tags,omitempty"`       // a project needs one of them
	NameRegex   string   `json:"nameRegex,omitempty"`
	Classifiers []string `json:"classifiers,omitempty"`
	Versions    string   `json:"versions,omitempty"` // latest (default) | all
}

// DTrackMappingSpec is the seven mapping rules of docs/10 §3.
type DTrackMappingSpec struct {
	UseProjectProperties *bool           `json:"useProjectProperties,omitempty"` // default true
	TagPrefix            string          `json:"tagPrefix,omitempty"`            // default "rampart-app:"
	MatchExistingAssets  *bool           `json:"matchExistingAssets,omitempty"`  // default true
	ParentAsApplication  bool            `json:"parentAsApplication,omitempty"`
	Rules                []DTrackMapRule `json:"rules,omitempty"`
	DefaultApplication   string          `json:"defaultApplication,omitempty"`
}

// DTrackMapRule maps the projects a CEL condition matches to an application slug.
type DTrackMapRule struct {
	When        string `json:"when"`
	Application string `json:"application"`
}

// DTrackPullSpec is what is read from Dependency-Track.
type DTrackPullSpec struct {
	Findings          *bool `json:"findings,omitempty"`          // default true; false is refused (nothing else is pulled)
	IncludeSuppressed *bool `json:"includeSuppressed,omitempty"` // default true: a suppressed finding carries DT's decision
}

// DTrackWebhookSpec turns on /hooks/dependency-track/{scanSourceId}. The bearer secret is the ScanSource's
// secretRef with key "webhook".
type DTrackWebhookSpec struct {
	Enabled bool `json:"enabled,omitempty"`
}

// DTrackTriageSpec says what happens to the analysis Dependency-Track carries on a finding (docs/23 DT5).
type DTrackTriageSpec struct {
	Mode                   string `json:"mode,omitempty"` // off | import (default)
	TrustUpstreamDecisions bool   `json:"trustUpstreamDecisions,omitempty"`
}

// Versions returns the version policy with its default.
func (s DTrackSourceSpec) Versions() string {
	if s.Projects.Versions == "" {
		return "latest"
	}
	return s.Projects.Versions
}

// OnlyActive returns the active-only filter with its default.
func (s DTrackSourceSpec) OnlyActive() bool {
	return s.Projects.OnlyActive == nil || *s.Projects.OnlyActive
}

// IncludeSuppressed returns the pull setting with its default.
func (s DTrackSourceSpec) IncludeSuppressed() bool {
	return s.Pull.IncludeSuppressed == nil || *s.Pull.IncludeSuppressed
}

// TriageMode returns the triage mode with its default.
func (s DTrackSourceSpec) TriageMode() string {
	if s.TriageSync.Mode == "" {
		return "import"
	}
	return s.TriageSync.Mode
}

// UseProps returns the mapping setting with its default.
func (m DTrackMappingSpec) UseProps() bool {
	return m.UseProjectProperties == nil || *m.UseProjectProperties
}

// MatchAssets returns the mapping setting with its default.
func (m DTrackMappingSpec) MatchAssets() bool {
	return m.MatchExistingAssets == nil || *m.MatchExistingAssets
}

// notBuilt names the doc 10 §8 fields this version refuses, with what to do instead.
var dtrackNotBuilt = map[string]string{
	"policyViolations": "policy violations are not pulled in this version (docs/09 Phase 5)",
	"sbom":             "SBOMs are not pulled in this version",
	"manage":           "the DT notification rule is not managed by the operator; create it in DT (docs/10 §8)",
	"allowedCIDRs":     "restrict the webhook at the ingress or NetworkPolicy; the bearer secret authenticates it",
	"authority":        "only import is built; Rampart's decisions are not written back to DT (docs/09 Phase 5)",
	"sbomForwarding":   "SBOM forwarding is Phase 5 (docs/09)",
	"initialSync":      "the first sync is paced by the dtrack-sync queue",
	"closeOnInactive":  "an inactive project's findings are closed by onlyActive and the close step",
}

// ParseDTrackSourceSpec decodes and validates the block. Unknown fields are refused, and fields of doc 10 §8 that
// are not built are refused with the reason.
func ParseDTrackSourceSpec(raw []byte) (DTrackSourceSpec, error) {
	var s DTrackSourceSpec
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return s, nil
	}
	if err := refuseNotBuilt(raw); err != nil {
		return s, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, fmt.Errorf("dependencyTrack: %w", err)
	}
	return s, s.Validate()
}

func refuseNotBuilt(raw []byte) error {
	var walk func(v any, path string) error
	walk = func(v any, path string) error {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		for k, child := range m {
			if why, bad := dtrackNotBuilt[k]; bad {
				return fmt.Errorf("dependencyTrack.%s%s: not supported: %s", path, k, why)
			}
			if path == "triageSync." && k == "mode" {
				if s, _ := child.(string); s == "export" || s == "bidirectional" {
					return fmt.Errorf("dependencyTrack.triageSync.mode %q: not supported: only off and import are built (decisions are not written back to DT)", s)
				}
			}
			if err := walk(child, path+k+"."); err != nil {
				return err
			}
		}
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("dependencyTrack: %w", err)
	}
	return walk(v, "")
}

var dtrackClassifiers = map[string]bool{
	"APPLICATION": true, "FRAMEWORK": true, "LIBRARY": true, "CONTAINER": true, "OPERATING_SYSTEM": true,
	"DEVICE": true, "FIRMWARE": true, "FILE": true, "PLATFORM": true, "DEVICE_DRIVER": true,
	"MACHINE_LEARNING_MODEL": true, "DATA": true,
}

// Validate checks the values.
func (s DTrackSourceSpec) Validate() error {
	switch s.Projects.Versions {
	case "", "latest", "all":
	default:
		return fmt.Errorf("dependencyTrack.projects.versions %q: use latest or all", s.Projects.Versions)
	}
	if s.Projects.NameRegex != "" {
		if _, err := regexp.Compile(s.Projects.NameRegex); err != nil {
			return fmt.Errorf("dependencyTrack.projects.nameRegex: %w", err)
		}
	}
	for _, c := range s.Projects.Classifiers {
		if !dtrackClassifiers[strings.ToUpper(c)] {
			return fmt.Errorf("dependencyTrack.projects.classifiers: unknown classifier %q", c)
		}
	}
	for i, r := range s.Mapping.Rules {
		if strings.TrimSpace(r.When) == "" || strings.TrimSpace(r.Application) == "" {
			return fmt.Errorf("dependencyTrack.mapping.rules[%d]: when and application are required", i)
		}
	}
	if s.Pull.Findings != nil && !*s.Pull.Findings {
		return fmt.Errorf("dependencyTrack.pull.findings: false would pull nothing; remove the ScanSource instead")
	}
	switch s.TriageSync.Mode {
	case "", "off", "import":
	default:
		return fmt.Errorf("dependencyTrack.triageSync.mode %q: use off or import", s.TriageSync.Mode)
	}
	if s.TriageSync.TrustUpstreamDecisions && s.TriageSync.Mode == "off" {
		return fmt.Errorf("dependencyTrack.triageSync: trustUpstreamDecisions needs mode import")
	}
	return nil
}

// DefaultDTrackSchedule is the incremental sync interval when the ScanSource names none (docs/10 Flow C).
const DefaultDTrackSchedule = 30 * time.Minute

// MinDTrackSchedule keeps a schedule from hammering Dependency-Track.
const MinDTrackSchedule = 5 * time.Minute

var cronEveryMinutes = regexp.MustCompile(`^\*/([0-9]{1,4}) \* \* \* \*$`)

// ParseDTrackSchedule reads a ScanSource schedule: a Go duration ("30m"), or the cron form "*/N * * * *" that
// doc 10 §8 shows. Other cron expressions are refused rather than misread.
func ParseDTrackSchedule(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return DefaultDTrackSchedule, nil
	}
	var d time.Duration
	if m := cronEveryMinutes.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		d = time.Duration(n) * time.Minute
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("schedule %q: use a duration such as 30m, or \"*/N * * * *\"", s)
		}
	}
	if d < MinDTrackSchedule {
		return 0, fmt.Errorf("schedule %q: at least %s", s, MinDTrackSchedule)
	}
	return d, nil
}

// DTrackSourceInput is the part of a ScanSource spec that makes it a Dependency-Track source.
type DTrackSourceInput struct {
	Type            string          `json:"type,omitempty"`
	Connector       string          `json:"connector,omitempty"`
	Schedule        string          `json:"schedule,omitempty"`
	DependencyTrack json.RawMessage `json:"dependencyTrack,omitempty"`
}

// Check validates the input the operator and `rampart apply` share. It returns the schedule; ok is false when the
// ScanSource is not a Dependency-Track one.
func (in DTrackSourceInput) Check() (spec json.RawMessage, schedule time.Duration, ok bool, err error) {
	if in.Connector == "" {
		if len(in.DependencyTrack) > 0 || in.Schedule != "" {
			return nil, 0, false, fmt.Errorf("dependencyTrack and schedule need connector: the name of a Connector of type dependencyTrack")
		}
		return nil, 0, false, nil
	}
	if in.Type != "" && in.Type != "apiPull" {
		return nil, 0, true, fmt.Errorf("a ScanSource with a connector is of type apiPull, not %q", in.Type)
	}
	if _, err := ParseDTrackSourceSpec(in.DependencyTrack); err != nil {
		return nil, 0, true, err
	}
	d, err := ParseDTrackSchedule(in.Schedule)
	if err != nil {
		return nil, 0, true, err
	}
	raw := in.DependencyTrack
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	return raw, d, true, nil
}
