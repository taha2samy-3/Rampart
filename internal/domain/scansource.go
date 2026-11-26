package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// IngestionPolicy configures the ingestion and reimport behaviors for a ScanSource (docs/04, D22).
type IngestionPolicy struct {
	MinimumSeverity  string   `json:"minimumSeverity,omitempty"`
	CloseOldFindings *bool    `json:"closeOldFindings,omitempty"`
	CloseScope       string   `json:"closeScope,omitempty"`
	DoNotReactivate  *bool    `json:"doNotReactivate,omitempty"`
	FieldMerge       string   `json:"fieldMerge,omitempty"`
	MaxClosePercent  *float64 `json:"maxClosePercent,omitempty"`
	MinHeldClose     *int     `json:"minHeldClose,omitempty"`
	MaxReportBytes   *int64   `json:"maxReportBytes,omitempty"`
	AcceptedFormats  []string `json:"acceptedFormats,omitempty"`
	// TrackedRefs are the branches (or tags, or environments by name) whose runs change the inventory (docs/04, D10): an
	// exact name, a prefix ending in * ("release/*", "hotfix-*"), or * for every ref. Any other ref is ephemeral and
	// feeds only the CI gate. Empty: the defaults (main, master, default, release/*, prod, production). A pull request
	// is always ephemeral, whatever is listed.
	TrackedRefs []string `json:"trackedRefs,omitempty"`
}

// MaxTrackedRefs bounds the list, so a source cannot make every upload walk a long one.
const MaxTrackedRefs = 50

// Validate checks that policy values fall within allowed ranges.
func (p *IngestionPolicy) Validate() error {
	if p == nil {
		return nil
	}
	if p.MaxClosePercent != nil {
		if *p.MaxClosePercent < 0 || *p.MaxClosePercent > 100 {
			return fmt.Errorf("maxClosePercent must be between 0 and 100, got %f", *p.MaxClosePercent)
		}
	}
	if p.MinHeldClose != nil {
		if *p.MinHeldClose < 0 {
			return fmt.Errorf("minHeldClose must be non-negative, got %d", *p.MinHeldClose)
		}
	}
	return ValidateTrackedRefs(p.TrackedRefs)
}

// ValidateTrackedRefs refuses a list that could not mean what the author meant: an empty or oversized name, a space or
// control character in it (a branch name has none), a * anywhere but the end (it would be read as a literal), more
// than MaxTrackedRefs names.
func ValidateTrackedRefs(refs []string) error {
	if len(refs) > MaxTrackedRefs {
		return fmt.Errorf("trackedRefs has at most %d entries, got %d", MaxTrackedRefs, len(refs))
	}
	for _, r := range refs {
		if r == "" || len(r) > 255 {
			return fmt.Errorf("trackedRefs: %q is empty or longer than 255 characters", r)
		}
		for i, c := range r {
			if c <= ' ' || c == 0x7f {
				return fmt.Errorf("trackedRefs: %q has a space or a control character", r)
			}
			if c == '*' && i != len(r)-1 {
				return fmt.Errorf("trackedRefs: %q has a * that is not the last character; only a trailing * is a wildcard", r)
			}
		}
	}
	return nil
}

// WithTrackedRefs returns the policy with the refs of spec.trackedRefs set (they sit beside ingestionPolicy in a
// ScanSource, as in docs/04, and are stored with it). It does not change the policy it is given.
func WithTrackedRefs(p *IngestionPolicy, refs []string) *IngestionPolicy {
	if len(refs) == 0 {
		return p
	}
	out := IngestionPolicy{}
	if p != nil {
		out = *p
	}
	out.TrackedRefs = append([]string(nil), refs...)
	return &out
}

// HeldClose records a mass-close held by the safety guard for human review (D22, Milestone 3.3).
type HeldClose struct {
	ID          uuid.UUID   `json:"id"`
	TenantID    uuid.UUID   `json:"tenant_id"`
	IngestRunID uuid.UUID   `json:"ingest_run_id"`
	Scope       CloseScope  `json:"scope"`
	FindingIDs  []uuid.UUID `json:"finding_ids"`
	CreatedAt   time.Time   `json:"created_at"`
	DecidedBy   string      `json:"decided_by,omitempty"`
	Decision    string      `json:"decision,omitempty"` // "confirmed" | "discarded" | ""
	DecidedAt   *time.Time  `json:"decided_at,omitempty"`
}

const (
	HeldCloseDecisionConfirmed = "confirmed"
	HeldCloseDecisionDiscarded = "discarded"
	// HeldCloseDecisionSuperseded: a newer run of the same scope completed, so the hold no longer describes the
	// scope and is closed without action (D83).
	HeldCloseDecisionSuperseded = "superseded"
)

// TrustRule defines CI OIDC federation rules for a ScanSource (D22).
type TrustRule struct {
	Issuer            string            `json:"issuer"`
	Provider          string            `json:"provider,omitempty"`
	RepositoryID      string            `json:"repositoryId,omitempty"`
	RepositoryOwnerID string            `json:"repositoryOwnerId,omitempty"`
	ProjectID         string            `json:"projectId,omitempty"`
	NamespaceID       string            `json:"namespaceId,omitempty"`
	Repository        string            `json:"repository,omitempty"`
	BoundClaims       map[string]string `json:"boundClaims,omitempty"`
	// RepositoryClaim and RefClaim name the claims of a generic issuer's token that carry the repository and the ref the CI
	// job runs on. The token exchanged under the rule is bound to them (D80), so a job cannot upload as another branch.
	// A rule with a provider (github, gitlab) reads the provider's own claims instead (docs/51 step 1.3).
	RepositoryClaim string `json:"repositoryClaim,omitempty"`
	RefClaim        string `json:"refClaim,omitempty"`
}

// Validate checks that the trust rule contains valid and complete identifiers.
func (r *TrustRule) Validate() error {
	if strings.TrimSpace(r.Issuer) == "" {
		return fmt.Errorf("issuer cannot be empty")
	}
	if len(r.BoundClaims) > 0 {
		for k, v := range r.BoundClaims {
			if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
				return fmt.Errorf("boundClaims cannot contain empty keys or values")
			}
		}
		return r.validateBoundClaims()
	}
	if r.Provider != "github" && r.Provider != "gitlab" {
		return fmt.Errorf("provider must be 'github' or 'gitlab', got %q", r.Provider)
	}
	if r.Provider == "github" && (r.RepositoryID == "" || r.RepositoryOwnerID == "") {
		return fmt.Errorf("github trust rule must specify both repositoryId and repositoryOwnerId (D22)")
	}
	if r.Provider == "gitlab" && (r.ProjectID == "" || r.NamespaceID == "") {
		return fmt.Errorf("gitlab trust rule must specify both projectId and namespaceId (D22)")
	}
	return nil
}

// validateBoundClaims checks that a boundClaims rule binds the job to one repository and one ref (D80), and that it names the
// repository by an id that cannot be re-registered by someone else (D22). docs/51 step 1.3: before this, a rule with boundClaims
// skipped both, so a feature branch could upload as main, and a rule naming `repository: acme/payments` trusted whoever owns
// that name next.
func (r *TrustRule) validateBoundClaims() error {
	switch r.Provider {
	case "github":
		if r.BoundClaims["repository_id"] == "" || r.BoundClaims["repository_owner_id"] == "" {
			return fmt.Errorf("a github federation must bind repository_id and repository_owner_id in boundClaims (D22): a repository name can be taken over by someone else")
		}
	case "gitlab":
		if r.BoundClaims["project_id"] == "" || r.BoundClaims["namespace_id"] == "" {
			return fmt.Errorf("a gitlab federation must bind project_id and namespace_id in boundClaims (D22): a project path can be taken over by someone else")
		}
	case "":
		if strings.TrimSpace(r.RepositoryClaim) == "" || strings.TrimSpace(r.RefClaim) == "" {
			return fmt.Errorf("a federation must say which claims name the repository and the ref: set provider (github or gitlab), or repositoryClaim and refClaim, so the token is bound to one repository and branch (D80)")
		}
	default:
		return fmt.Errorf("provider must be 'github', 'gitlab' or empty (with repositoryClaim and refClaim), got %q", r.Provider)
	}
	return nil
}

// TrustRuleRecord represents a stored trust rule linked to a ScanSource.
type TrustRuleRecord struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	ScanSourceID uuid.UUID `json:"scan_source_id"`
	Rule         TrustRule `json:"rule"`
	CreatedAt    time.Time `json:"created_at"`
}

// ErrAmbiguousApplicationRef is returned when an applicationRef matches more than one application (docs/51 step 2.5).
var ErrAmbiguousApplicationRef = errors.New("applicationRef matches more than one application")

// ApplicationSelector matches applications by labels.
type ApplicationSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// ApplicationRef names the target Application a ScanSource is exclusively bound to (D140).
// Supports multi-mode resolution: by name/slug, label selector, or repository URL.
type ApplicationRef struct {
	Name       string               `json:"name,omitempty"`
	Selector   *ApplicationSelector `json:"selector,omitempty"`
	Repository string               `json:"repository,omitempty"`
}

// Validate ensures at least one resolution mode is provided and valid.
func (r ApplicationRef) Validate() error {
	hasName := strings.TrimSpace(r.Name) != ""
	hasSelector := r.Selector != nil && len(r.Selector.MatchLabels) > 0
	hasRepo := strings.TrimSpace(r.Repository) != ""

	if !hasName && !hasSelector && !hasRepo {
		return fmt.Errorf("applicationRef must specify at least one of name, selector, or repository")
	}
	if hasName && len(r.Name) > 255 {
		return fmt.Errorf("applicationRef.name cannot exceed 255 characters")
	}
	if hasRepo && len(r.Repository) > 500 {
		return fmt.Errorf("applicationRef.repository cannot exceed 500 characters")
	}
	return nil
}

// SecretRef points to a Kubernetes Secret by name and key.
type SecretRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// Validate ensures the secret reference is populated.
func (s SecretRef) Validate() error {
	if strings.TrimSpace(s.Name) == "" || strings.TrimSpace(s.Key) == "" {
		return fmt.Errorf("secretRef name and key must not be empty")
	}
	return nil
}

// FederationSpec defines universal workload identity federation parameters (RFC 8693).
type FederationSpec struct {
	Issuer      string            `json:"issuer"`
	BoundClaims map[string]string `json:"boundClaims"`
	// Provider is github or gitlab when the issuer is one of them; its claims then bind the repository and the ref (D80).
	Provider string `json:"provider,omitempty"`
	// RepositoryClaim and RefClaim name the claims that bind the repository and the ref for any other issuer.
	RepositoryClaim string `json:"repositoryClaim,omitempty"`
	RefClaim        string `json:"refClaim,omitempty"`
}

// TrustRule is the stored rule this federation becomes.
func (f FederationSpec) TrustRule() TrustRule {
	return TrustRule{Issuer: f.Issuer, Provider: f.Provider, BoundClaims: f.BoundClaims, RepositoryClaim: f.RepositoryClaim, RefClaim: f.RefClaim}
}

// Validate ensures the federation specification is non-empty and well-formed.
func (f FederationSpec) Validate() error {
	if strings.TrimSpace(f.Issuer) == "" {
		return fmt.Errorf("federation.issuer cannot be empty")
	}
	if len(f.BoundClaims) == 0 {
		return fmt.Errorf("federation.boundClaims cannot be empty")
	}
	for k, v := range f.BoundClaims {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return fmt.Errorf("federation.boundClaims cannot contain empty keys or values")
		}
	}
	rule := f.TrustRule()
	if err := rule.validateBoundClaims(); err != nil {
		return fmt.Errorf("federation: %w", err)
	}
	return nil
}

// AuthSpec defines the authentication contract for a ScanSource.
// Supports multi-auth: tokenSecretRef and federation/federations can be configured simultaneously.
type AuthSpec struct {
	TokenSecretRef *SecretRef       `json:"tokenSecretRef,omitempty"`
	Federation     *FederationSpec  `json:"federation,omitempty"`
	Federations    []FederationSpec `json:"federations,omitempty"`
}

// AllFederations returns the combined slice of all configured federation specs.
func (a AuthSpec) AllFederations() []FederationSpec {
	var list []FederationSpec
	if a.Federation != nil {
		list = append(list, *a.Federation)
	}
	list = append(list, a.Federations...)
	return list
}

// Validate ensures at least one valid authentication mode is specified.
func (a AuthSpec) Validate() error {
	hasToken := a.TokenSecretRef != nil
	feds := a.AllFederations()
	if !hasToken && len(feds) == 0 {
		return fmt.Errorf("at least one of tokenSecretRef or federation/federations must be specified")
	}
	if a.TokenSecretRef != nil {
		if err := a.TokenSecretRef.Validate(); err != nil {
			return err
		}
	}
	for i, f := range feds {
		if err := f.Validate(); err != nil {
			return fmt.Errorf("federation[%d]: %w", i, err)
		}
	}
	return nil
}

// ApplicationScanSource describes a ScanSource bound to an Application, including its run statistics.
type ApplicationScanSource struct {
	ID            uuid.UUID  `json:"id"`
	Name          string     `json:"name"`
	Type          string     `json:"type"`
	ScannerFamily string     `json:"scanner_family,omitempty"`
	Categories    []string   `json:"categories"`
	AuthType      string     `json:"auth_type"`
	Active        bool       `json:"active"`
	TrackedRefs   []string   `json:"tracked_refs,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	DisabledAt    *time.Time `json:"disabled_at,omitempty"`
	TotalRuns     int        `json:"total_runs"`
	LastScanAt    *time.Time `json:"last_scan_at,omitempty"`
}

// ScanSource defines an ingestion source bound to a specific Application (D140).
type ScanSource struct {
	ID              uuid.UUID        `json:"id"`
	TenantID        uuid.UUID        `json:"tenant_id"`
	Name            string           `json:"name"`
	ApplicationRef  ApplicationRef   `json:"applicationRef"`
	ApplicationID   uuid.UUID        `json:"application_id"`
	Categories      []string         `json:"categories"`
	Type            string           `json:"type"`
	Auth            AuthSpec         `json:"auth"`
	ScannerFamily   string           `json:"scannerFamily,omitempty"`
	IngestionPolicy *IngestionPolicy `json:"ingestionPolicy,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	DisabledAt      *time.Time       `json:"disabled_at,omitempty"`
}

// PermitsCategory checks if the given FindingCategory is allowed by this ScanSource.
func (s *ScanSource) PermitsCategory(cat FindingCategory) bool {
	if s == nil || len(s.Categories) == 0 {
		return true // Default allows all
	}
	for _, c := range s.Categories {
		if c == "all" || c == string(cat) {
			return true
		}
	}
	return false
}

// Validate checks the ScanSource configuration.
func (s *ScanSource) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("scansource name cannot be empty")
	}
	if err := s.ApplicationRef.Validate(); err != nil {
		return err
	}
	if len(s.Categories) == 0 {
		return fmt.Errorf("categories must specify at least one category or 'all'")
	}
	for _, cat := range s.Categories {
		if cat != "all" && !FindingCategory(cat).IsValid() {
			return fmt.Errorf("invalid category %q", cat)
		}
	}
	if s.Auth.TokenSecretRef != nil || s.Auth.Federation != nil || len(s.Auth.Federations) > 0 {
		if err := s.Auth.Validate(); err != nil {
			return err
		}
	}
	if s.IngestionPolicy != nil {
		if err := s.IngestionPolicy.Validate(); err != nil {
			return err
		}
	}
	return nil
}
