package domain

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Tenant represents an isolated customer boundary (normative D4, D8, ADR 0005).
type Tenant struct {
	ID           uuid.UUID       `json:"id"`
	Slug         string          `json:"slug"`
	DisplayName  string          `json:"display_name"`
	K8sNamespace string          `json:"k8s_namespace"`
	Settings     json.RawMessage `json:"settings,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

// Validate checks Tenant domain invariants.
func (t Tenant) Validate() error {
	if t.ID == NilID {
		return ErrInvalidTenantID
	}
	if t.Slug == "" {
		return fmt.Errorf("%w: tenant slug is required", ErrMissingRequiredField)
	}
	return nil
}

// Application represents a high-level product or system (DefectDojo Product).
type Application struct {
	ID                  uuid.UUID  `json:"id"`
	TenantID            uuid.UUID  `json:"tenant_id"`
	HierarchyNodeID     *uuid.UUID `json:"hierarchy_node_id,omitempty"`
	Slug                string     `json:"slug"`
	Name                string     `json:"name"`
	Description         string     `json:"description,omitempty"`
	BusinessCriticality string     `json:"business_criticality"` // critical | high | medium | low
	InternetFacing      bool       `json:"internet_facing"`
	DataClassification  []string   `json:"data_classification,omitempty"` // pii, pci, phi, secret, public
	Lifecycle           string     `json:"lifecycle"`                     // planning | development | production | deprecated
	Owners              []string   `json:"owners,omitempty"`
	Tags                []string   `json:"tags,omitempty"`
	Version             int        `json:"version"`
	CreatedAt           time.Time  `json:"created_at"`
}

// Validate checks Application domain invariants.
func (a Application) Validate() error {
	if a.ID == NilID {
		return fmt.Errorf("%w: application id cannot be nil", ErrMissingRequiredField)
	}
	if a.TenantID == NilID {
		return ErrInvalidTenantID
	}
	if a.Slug == "" || a.Name == "" {
		return fmt.Errorf("%w: application slug and name are required", ErrMissingRequiredField)
	}
	return nil
}

// Asset represents a long-lived physical entity that receives scans (D10).
// An asset is the long-lived entity; a version is one build/digest of it.
type Asset struct {
	ID            uuid.UUID       `json:"id"`
	TenantID      uuid.UUID       `json:"tenant_id"`
	ApplicationID *uuid.UUID      `json:"application_id,omitempty"` // Nullable for shared assets (D10)
	ServiceID     *uuid.UUID      `json:"service_id,omitempty"`
	EnvironmentID *uuid.UUID      `json:"environment_id,omitempty"`
	Type          AssetType       `json:"type"`
	Key           string          `json:"key"` // Stable natural key, unique per (tenant, type)
	DisplayName   string          `json:"display_name"`
	Attributes    json.RawMessage `json:"attributes,omitempty"`
	Active        bool            `json:"active"`
	FirstSeen     time.Time       `json:"first_seen"`
	LastSeen      time.Time       `json:"last_seen"`
}

// Validate checks Asset domain invariants.
func (a Asset) Validate() error {
	if a.ID == NilID {
		return fmt.Errorf("%w: asset id cannot be nil", ErrMissingRequiredField)
	}
	if a.TenantID == NilID {
		return ErrInvalidTenantID
	}
	if a.Key == "" {
		return ErrInvalidAssetKey
	}
	if a.Type == "" {
		return fmt.Errorf("%w: asset type is required", ErrMissingRequiredField)
	}
	return nil
}

// AssetVersion records an immutable build or commit of an asset (D10).
type AssetVersion struct {
	TenantID   uuid.UUID       `json:"tenant_id"`
	AssetID    uuid.UUID       `json:"asset_id"`
	Version    string          `json:"version"` // commit SHA or image digest
	Attributes json.RawMessage `json:"attributes,omitempty"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
}

// DependencyEdge models a directed relationship in an SBOM dependency graph.
type DependencyEdge struct {
	FromRef string `json:"from_ref"` // Parent component identifier (PURL, BOM-Ref, or SPDXID)
	ToRef   string `json:"to_ref"`   // Child dependency identifier
	Scope   string `json:"scope,omitempty"`
}

// SBOM models an ingested Software Bill of Materials (docs/12 §Inventory).
type SBOM struct {
	ID             uuid.UUID        `json:"id"`
	TenantID       uuid.UUID        `json:"tenant_id"`
	AssetID        uuid.UUID        `json:"asset_id"`
	IngestRunID    uuid.UUID        `json:"ingest_run_id"`
	Format         string           `json:"format"`       // cyclonedx | spdx | syft
	SpecVersion    string           `json:"spec_version"` // 1.4, 1.5, 1.6, 2.2, 2.3, 3.0
	Serial         string           `json:"serial,omitempty"`
	ObjectRef      string           `json:"object_ref,omitempty"`
	RootComponent  string           `json:"root_component,omitempty"`
	ComponentCount int              `json:"component_count"`
	Dependencies   []DependencyEdge `json:"dependencies,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
}

// SBOMComponent models an individual library or package in an SBOM (docs/12).
type SBOMComponent struct {
	TenantID uuid.UUID         `json:"tenant_id"`
	SBOMID   uuid.UUID         `json:"sbom_id"`
	Ref      string            `json:"ref,omitempty"` // Unique document-scoped ID (BOM-Ref, SPDXID)
	Purl     string            `json:"purl"`
	PurlBase string            `json:"purl_base"`
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	Licenses []string          `json:"licenses,omitempty"`
	Scope    string            `json:"scope,omitempty"` // required | optional | excluded
	Direct   bool              `json:"direct"`
	Hashes   map[string]string `json:"hashes,omitempty"`
}

// UploadContext represents the canonical context payload supplied at upload time (D10).
type UploadContext struct {
	Repository   string    `json:"repository,omitempty"`
	Branch       string    `json:"branch,omitempty"`
	Commit       string    `json:"commit,omitempty"`
	ImageRef     string    `json:"image_ref,omitempty"`
	ImageDigest  string    `json:"image_digest,omitempty"`
	Environment  string    `json:"environment,omitempty"`
	Service      string    `json:"service,omitempty"`
	Version      string    `json:"version,omitempty"`
	BuildID      string    `json:"build_id,omitempty"`
	PipelineURL  string    `json:"pipeline_url,omitempty"`
	ScanStarted  time.Time `json:"scan_started,omitempty"`
	ScanFinished time.Time `json:"scan_finished,omitempty"`
	Tags         []string  `json:"tags,omitempty"`
}

// IngestStats stores exact metrics for an ingest run (normative D2).
type IngestStats struct {
	Parsed             int `json:"parsed"`
	Created            int `json:"created"`
	Updated            int `json:"updated"`
	Untouched          int `json:"untouched"`
	Reactivated        int `json:"reactivated"`
	Closed             int `json:"closed"`
	SkippedMinSeverity int `json:"skipped_min_severity"`
	RecordErrors       int `json:"record_errors"`
	WeakFingerprints   int `json:"weak_fingerprints"`
}

// IngestRun models a single execution of report ingestion (D2).
type IngestRun struct {
	ID             uuid.UUID       `json:"id"`
	TenantID       uuid.UUID       `json:"tenant_id"`
	UploadID       *uuid.UUID      `json:"upload_id,omitempty"`
	ScanSourceID   uuid.UUID       `json:"scan_source_id"`
	ApplicationID  uuid.UUID       `json:"application_id"`
	AssetID        uuid.UUID       `json:"asset_id"`
	Track          string          `json:"track"`
	ScannerFamily  string          `json:"scanner_family"`
	ScannerVersion string          `json:"scanner_version,omitempty"`
	Format         string          `json:"format"`
	Context        UploadContext   `json:"context"`
	Status         IngestRunStatus `json:"status"`
	Stats          IngestStats     `json:"stats"`
	Error          string          `json:"error,omitempty"`
	ScanStarted    time.Time       `json:"scan_started"`
	ScanFinished   time.Time       `json:"scan_finished"`
	CreatedAt      time.Time       `json:"created_at"`
	FinishedAt     *time.Time      `json:"finished_at,omitempty"`
	// HoldsSecrets is true when the report named at least one secret: its raw report is kept for a shorter time.
	HoldsSecrets bool `json:"holds_secrets"`
	// ReportPurgedAt is when retention removed the raw report (D53).
	ReportPurgedAt *time.Time `json:"report_purged_at,omitempty"`
}

// IngestRunScope tracks an asset/track scope touched by a run (D10, D13).
type IngestRunScope struct {
	IngestRunID   uuid.UUID `json:"ingest_run_id"`
	TenantID      uuid.UUID `json:"tenant_id"`
	ScanSourceID  uuid.UUID `json:"scan_source_id"`
	ScannerFamily string    `json:"scanner_family"`
	AssetID       uuid.UUID `json:"asset_id"`
	Track         string    `json:"track"`
}

// CloseScope uniquely identifies the rescan closure boundary (normative D13).
type CloseScope struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	ScanSourceID  uuid.UUID `json:"scan_source_id"`
	ScannerFamily string    `json:"scanner_family"`
	AssetID       uuid.UUID `json:"asset_id"`
	Track         string    `json:"track"`
}

func (s CloseScope) Key() string {
	return fmt.Sprintf("%s:%s:%s:%s:%s", s.TenantID, s.ScanSourceID, s.ScannerFamily, s.AssetID, s.Track)
}

// IngestRunResult stores ephemeral scan run findings for gate evaluation without polluting inventory (D10).
type IngestRunResult struct {
	TenantID    uuid.UUID       `json:"tenant_id"`
	IngestRunID uuid.UUID       `json:"ingest_run_id"`
	FindingKey  string          `json:"finding_key"`
	IsNew       bool            `json:"is_new"`   // absent from the baseline track (D26)
	IsFixed     bool            `json:"is_fixed"` // present in baseline, absent here
	Severity    Severity        `json:"severity"`
	Category    FindingCategory `json:"category"`
	Location    Location        `json:"location"`
	RawPayload  json.RawMessage `json:"raw_payload,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
}

// Finding represents the deduplicated, triaged vulnerability entity (D11, D18, D28).
type Finding struct {
	ID                     uuid.UUID       `json:"id"`
	TenantID               uuid.UUID       `json:"tenant_id"`
	FindingKey             string          `json:"finding_key"`               // SHA-256 deterministic fingerprint (D11)
	CorrelationKey         string          `json:"correlation_key,omitempty"` // groups findings of different tools for display (D24)
	DedupScope             string          `json:"dedup_scope"`               // asset | application | tenant
	AssetID                uuid.UUID       `json:"asset_id"`
	ApplicationID          uuid.UUID       `json:"application_id"`
	Track                  string          `json:"track"` // Named branch or environment line (D10)
	Category               FindingCategory `json:"category"`
	RuleScannerFamily      string          `json:"rule_scanner_family"`
	RuleID                 string          `json:"rule_id"`
	Title                  string          `json:"title"`
	Description            string          `json:"description,omitempty"`
	CWEs                   []int           `json:"cwes,omitempty"`
	VulnerabilityID        *string         `json:"vulnerability_id,omitempty"`
	Location               Location        `json:"location"`
	Severity               Severity        `json:"severity"` // Normalized severity
	ToolSeverity           string          `json:"tool_severity"`
	SeverityOverrideReason *string         `json:"severity_override_reason,omitempty"`
	CVSSVector             string          `json:"cvss_vector,omitempty"`
	RiskScore              int             `json:"risk_score"` // 0–1000 explainable score
	// RiskBand, KEV and EPSSBucket are stored with the score so the explorer can filter and sort in SQL (D28);
	// the factors that depend on time (age) are not in the stored score, they are evaluated when read.
	RiskBand Severity `json:"risk_band"`
	// SecretVerified is set while the scanner that found a secret says it is live.
	SecretVerified bool   `json:"secret_verified,omitempty"`
	KEV            bool   `json:"kev"`
	EPSSBucket     string `json:"epss_bucket,omitempty"`
	// The SLA clock (docs/06 section 4): it starts at SLAStart (first seen), ends at SLADue, stops while
	// SLAPausedAt is set (a risk acceptance), and SLABreachedAt records the first time the due date passed.
	SLAStart      *time.Time   `json:"sla_start,omitempty"`
	SLADue        *time.Time   `json:"sla_due_date,omitempty"`
	SLABreachedAt *time.Time   `json:"sla_breached_at,omitempty"`
	SLAPausedAt   *time.Time   `json:"sla_paused_at,omitempty"`
	State         FindingState `json:"state"` // OpenVEX disposition (D18)
	PreviousState FindingState `json:"previous_state,omitempty"`
	StateReason   string       `json:"state_reason,omitempty"`
	// Justification and ImpactStatement belong to a not_affected decision (OpenVEX); DuplicateOfID to a duplicate.
	Justification   string     `json:"justification,omitempty"`
	ImpactStatement string     `json:"impact_statement,omitempty"`
	DuplicateOfID   *uuid.UUID `json:"duplicate_of_id,omitempty"`
	Tags            []string   `json:"tags,omitempty"`
	// RiskAcceptanceID is set while the finding is risk_accepted through a risk acceptance (D39).
	RiskAcceptanceID *uuid.UUID      `json:"risk_acceptance_id,omitempty"`
	Detection        DetectionStatus `json:"detection"` // present | absent (D18)
	ContentHash      string          `json:"content_hash"`
	WeakFingerprint  bool            `json:"weak_fingerprint"`
	FirstSeen        time.Time       `json:"first_seen"`
	LastSeen         time.Time       `json:"last_seen"`
	ResolvedAt       *time.Time      `json:"resolved_at,omitempty"`
	Resolution       *Resolution     `json:"resolution,omitempty"`
	ReopenedCount    int             `json:"reopened_count"`
	OccurrenceCount  int             `json:"occurrence_count"`
	Version          int             `json:"version"` // Optimistic locking
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// Validate checks Finding domain invariants.
func (f Finding) Validate() error {
	if f.ID == NilID {
		return fmt.Errorf("%w: finding id cannot be nil", ErrMissingRequiredField)
	}
	if f.TenantID == NilID {
		return ErrInvalidTenantID
	}
	if f.FindingKey == "" {
		return ErrInvalidFindingKey
	}
	if f.AssetID == NilID || f.ApplicationID == NilID {
		return fmt.Errorf("%w: finding asset and application ids are required", ErrMissingRequiredField)
	}
	if !f.Severity.Valid() {
		return fmt.Errorf("%w: %s", ErrInvalidSeverity, f.Severity)
	}
	return nil
}

// Occurrence represents the current concrete evidence of one finding from one source (D12).
type Occurrence struct {
	ID             uuid.UUID       `json:"id"`
	TenantID       uuid.UUID       `json:"tenant_id"`
	FindingID      uuid.UUID       `json:"finding_id"`
	IngestRunID    uuid.UUID       `json:"ingest_run_id"`
	ScanSourceID   uuid.UUID       `json:"scan_source_id"`
	AssetID        uuid.UUID       `json:"asset_id"`
	Track          string          `json:"track"`
	OccurrenceKey  string          `json:"occurrence_key"` // SHA-256(tool_record_id) or location hash
	ScannerFamily  string          `json:"scanner_family"`
	ScannerName    string          `json:"scanner_name"`
	ScannerVersion string          `json:"scanner_version,omitempty"`
	ToolRecordID   string          `json:"tool_record_id,omitempty"`
	Location       Location        `json:"location"`
	ToolSeverity   string          `json:"tool_severity"`
	Normalized     json.RawMessage `json:"normalized,omitempty"`
	Raw            json.RawMessage `json:"raw,omitempty"`
	Present        bool            `json:"present"` // true = seen in latest run of this scope (D12)
	SeenCount      int             `json:"seen_count"`
	FirstSeen      time.Time       `json:"first_seen"`
	LastSeen       time.Time       `json:"last_seen"`
}

// FindingEvent records an immutable audit milestone in the finding lifecycle (timeline).
type FindingEvent struct {
	ID        uuid.UUID       `json:"id"`
	FindingID uuid.UUID       `json:"finding_id"`
	At        time.Time       `json:"at"`
	Actor     string          `json:"actor"` // user | system:parser | system:policy | connector:jira
	Type      string          `json:"type"`  // created | reactivated | closed_by_rescan | state_changed
	From      json.RawMessage `json:"from,omitempty"`
	To        json.RawMessage `json:"to,omitempty"`
	Note      string          `json:"note,omitempty"`
}

// RawFinding is emitted in streaming fashion by parsers (D11, D15, docs/05 §2).
type RawFinding struct {
	RuleID          string          `json:"rule_id"`
	RuleName        string          `json:"rule_name,omitempty"`
	RuleDescription string          `json:"rule_description,omitempty"`
	ScannerFamily   string          `json:"scanner_family"`
	ScannerName     string          `json:"scanner_name,omitempty"`
	ScannerVersion  string          `json:"scanner_version,omitempty"`
	Category        FindingCategory `json:"category"`
	ToolRecordID    string          `json:"tool_record_id,omitempty"`
	ToolSeverity    string          `json:"tool_severity"`
	Severity        Severity        `json:"severity"`
	Title           string          `json:"title"`
	Description     string          `json:"description,omitempty"`
	Location        Location        `json:"location"`
	CWEs            []int           `json:"cwes,omitempty"`
	VulnIDs         []string        `json:"vuln_ids,omitempty"` // CVE, GHSA, OSV
	CVSSVector      string          `json:"cvss_vector,omitempty"`
	SecretValue     string          `json:"secret_value,omitempty"` // For generating secret_hash
	// SecretVerified: the scanner tried the credential against its provider and it is live (docs/06 SECRET_VERIFIED).
	SecretVerified bool            `json:"secret_verified,omitempty"`
	VEX            *VEXStatement   `json:"vex,omitempty"`
	RawPayload     json.RawMessage `json:"raw_payload,omitempty"`
}

// VEXStatement captures vulnerability exploitability exchange statements (OpenVEX / CSAF / CycloneDX VEX).
type VEXStatement struct {
	StatementID   uuid.UUID    `json:"statement_id"`
	VulnID        string       `json:"vuln_id"`
	State         FindingState `json:"state"` // affected | not_affected | under_investigation | fixed
	Justification string       `json:"justification,omitempty"`
	Impact        string       `json:"impact,omitempty"`
	Remediation   string       `json:"remediation,omitempty"`
	Action        string       `json:"action,omitempty"`
}

// ParseContext supplies the runtime parameters and boundaries to parsers (D11).
type ParseContext struct {
	TenantID      uuid.UUID     `json:"tenant_id"`
	ScanSourceID  uuid.UUID     `json:"scan_source_id"`
	ScannerFamily string        `json:"scanner_family"`
	Track         string        `json:"track"`
	UploadContext UploadContext `json:"upload_context"`
	// RecordError, when set, receives each record a parser could not read, so the rest of the report is still
	// processed (docs/16 D13: a run with record errors ends completed_with_errors). A parser that finds it nil
	// stops at the first bad record, as before.
	RecordError func(RecordError) `json:"-"`
}

// RecordError is one record of a report that could not be read: where it is in the report, and why, without the
// record's content (a report can hold secrets).
type RecordError struct {
	Where   string `json:"where"`
	Message string `json:"message"`
}

func (e *RecordError) Error() string {
	if e.Where == "" {
		return e.Message
	}
	return e.Where + ": " + e.Message
}

// Upload is a presigned upload awaiting, or past, its `complete` call (D2, D9).
type Upload struct {
	ID             uuid.UUID     `json:"id"`
	TenantID       uuid.UUID     `json:"tenant_id"`
	ScanSourceID   uuid.UUID     `json:"scan_source_id"`
	IdempotencyKey string        `json:"idempotency_key,omitempty"`
	RequestHash    string        `json:"request_hash,omitempty"` // SHA-256 of the create request body
	ObjectRef      string        `json:"object_ref"`
	SHA256         string        `json:"sha256,omitempty"` // declared at complete
	SizeBytes      int64         `json:"size_bytes"`       // declared at create, signed into the PUT
	FormatHint     string        `json:"format_hint,omitempty"`
	Context        UploadContext `json:"context"`
	Status         string        `json:"status"` // created | completed
	CreatedAt      time.Time     `json:"created_at"`
}
