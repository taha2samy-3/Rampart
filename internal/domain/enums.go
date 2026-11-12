package domain

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors representing domain rule violations.
var (
	ErrInvalidTenantID        = errors.New("domain: tenant id must be a valid non-nil UUIDv7")
	ErrInvalidAssetKey        = errors.New("domain: asset natural key cannot be empty")
	ErrInvalidFindingKey      = errors.New("domain: finding fingerprint key cannot be empty")
	ErrInvalidStateTransition = errors.New("domain: invalid finding state transition")
	ErrMissingRequiredField   = errors.New("domain: required field is missing")
	ErrInvalidSeverity        = errors.New("domain: unknown or invalid severity level")
)

// Severity represents normalized finding impact across all scanner families.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityUnknown  Severity = "unknown"
)

// ParseSeverity normalizes arbitrary scanner strings into standard Severity.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "blocker", "fatal":
		return SeverityCritical
	case "high", "major", "error":
		return SeverityHigh
	case "medium", "moderate", "warning", "warn":
		return SeverityMedium
	case "low", "minor":
		return SeverityLow
	case "info", "informational", "note":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// Rank returns the numeric priority order (higher is more critical).
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Valid checks if the severity is a known valid level.
func (s Severity) Valid() bool {
	return s.Rank() > 0
}

// FindingState represents OpenVEX lifecycle state (normative D18).
type FindingState string

const (
	StateOpen               FindingState = "open"
	StateUnderInvestigation FindingState = "under_investigation"
	StateAffected           FindingState = "affected"
	StateNotAffected        FindingState = "not_affected"
	StateFixed              FindingState = "fixed"
	StateRiskAccepted       FindingState = "risk_accepted"
	StateOutOfScope         FindingState = "out_of_scope"
	StateDuplicate          FindingState = "duplicate"
)

// IsValid returns true if the disposition is a valid domain state.
func (s FindingState) IsValid() bool {
	switch s {
	case StateOpen, StateUnderInvestigation, StateAffected, StateNotAffected,
		StateFixed, StateRiskAccepted, StateOutOfScope, StateDuplicate:
		return true
	default:
		return false
	}
}

// IsActive returns true if the finding disposition requires remediation/attention.
func (s FindingState) IsActive() bool {
	switch s {
	case StateOpen, StateUnderInvestigation, StateAffected:
		return true
	default:
		return false
	}
}

// CanTransitionTo validates the state machine transition per OpenVEX lifecycle specification.
func (s FindingState) CanTransitionTo(next FindingState) error {
	if s == next {
		return nil
	}

	valid := false
	switch s {
	case StateOpen:
		// From open, can transition to any triage state or fixed
		valid = true
	case StateUnderInvestigation:
		// Under investigation can transition to affected, not_affected, risk_accepted, out_of_scope, duplicate, fixed
		valid = true
	case StateAffected:
		// Affected can be fixed, risk_accepted, or reopened for investigation
		valid = (next == StateFixed || next == StateRiskAccepted || next == StateUnderInvestigation || next == StateNotAffected)
	case StateNotAffected:
		// Not affected (false positive) stays unless explicitly moved back to under_investigation or affected
		valid = (next == StateUnderInvestigation || next == StateAffected)
	case StateFixed:
		// Fixed findings can only be reactivated to open (by rescan or manual)
		valid = (next == StateOpen || next == StateUnderInvestigation)
	case StateRiskAccepted:
		// Risk accepted can expire back to open/previous_state, or be marked fixed if code changes
		valid = (next == StateOpen || next == StateFixed || next == StateUnderInvestigation || next == StateAffected)
	case StateOutOfScope:
		valid = (next == StateUnderInvestigation || next == StateOpen)
	case StateDuplicate:
		valid = (next == StateUnderInvestigation || next == StateOpen)
	default:
		valid = false
	}

	if !valid {
		return fmt.Errorf("%w: cannot transition from %s to %s", ErrInvalidStateTransition, s, next)
	}
	return nil
}

// DetectionStatus separates physical scanner presence from human disposition (normative D18).
type DetectionStatus string

const (
	DetectionPresent DetectionStatus = "present"
	DetectionAbsent  DetectionStatus = "absent"
)

// Resolution describes how a closed/resolved finding was settled.
type Resolution string

const (
	ResolutionFixed        Resolution = "fixed"
	ResolutionNotAffected  Resolution = "not_affected"
	ResolutionRiskAccepted Resolution = "risk_accepted"
	ResolutionOutOfScope   Resolution = "out_of_scope"
	ResolutionDuplicate    Resolution = "duplicate"
	ResolutionSuperseded   Resolution = "superseded"
	ResolutionDeletedAsset Resolution = "deleted_asset"
)

// IngestRunStatus tracks the execution phase of an ingestion run (normative D2).
type IngestRunStatus string

const (
	RunQueued              IngestRunStatus = "queued"
	RunParsing             IngestRunStatus = "parsing"
	RunMerging             IngestRunStatus = "merging"
	RunEnriching           IngestRunStatus = "enriching"
	RunScoring             IngestRunStatus = "scoring"
	RunCompleted           IngestRunStatus = "completed"
	RunCompletedWithErrors IngestRunStatus = "completed_with_errors"
	RunFailed              IngestRunStatus = "failed"
	RunStale               IngestRunStatus = "stale"
)

// IsTerminal returns true if the ingest run has reached a final state.
func (s IngestRunStatus) IsTerminal() bool {
	switch s {
	case RunCompleted, RunCompletedWithErrors, RunFailed, RunStale:
		return true
	default:
		return false
	}
}

// AssetType categorizes inventory entities.
type AssetType string

const (
	AssetRepository    AssetType = "repository"
	AssetBranch        AssetType = "branch"
	AssetImage         AssetType = "image"
	AssetWorkload      AssetType = "workload"
	AssetHost          AssetType = "host"
	AssetURL           AssetType = "url"
	AssetPackage       AssetType = "package"
	AssetCloudResource AssetType = "cloud_resource"
	AssetPipeline      AssetType = "pipeline"
)

// FindingCategory identifies the security testing discipline (D17).
type FindingCategory string

const (
	CategorySAST        FindingCategory = "sast"
	CategorySCA         FindingCategory = "sca"
	CategorySecret      FindingCategory = "secret"
	CategoryIaC         FindingCategory = "iac"
	CategoryContainer   FindingCategory = "container"
	CategoryDAST        FindingCategory = "dast"
	CategoryCSPM        FindingCategory = "cspm"
	CategoryCompliance  FindingCategory = "compliance"
	CategoryLicense     FindingCategory = "license"
	CategorySupplyChain FindingCategory = "supply_chain"
)
