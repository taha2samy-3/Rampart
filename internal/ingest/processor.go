package ingest

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"rampart/internal/domain"
	"rampart/internal/integrations"
	"rampart/internal/jobs"
	"rampart/internal/normalize"
	"rampart/internal/objectstore"
	"rampart/internal/parsers/cyclonedx"
	"rampart/internal/parsers/spdx"
	"rampart/internal/parsers/syft"
	"rampart/internal/telemetry"
)

// Typed failure codes of an ingest run (ingest_run.error, D17).
const (
	ErrCodeSizeMismatch      = "size_mismatch"
	ErrCodeSHA256Mismatch    = "sha256_mismatch"
	ErrCodeParse             = "parse_error"
	ErrCodeUnsupportedFormat = "unsupported_format"
	ErrCodeReportTooLarge    = "report_too_large"
	ErrCodeSBOMTooLarge      = "sbom_too_large"
	ErrCodeRetriesExhausted  = "retries_exhausted"
	ErrCodeMergeFailed       = "merge_failed"
	ErrCodeCloseFailed       = "close_failed"
	ErrCodeObjectMissing     = "object_missing"
)

// Processor turns one uploaded report into findings: verify, stream-parse, merge in batches, close
// (D2, D9, D13, D15). The ingest worker and the direct-upload endpoint share it, so both follow
// exactly the same rules.
type Processor struct {
	store        Store
	engine       *Engine
	registry     *integrations.Registry
	objects      objectstore.Store
	logger       *slog.Logger
	batchRows    int
	maxReport    int64
	maxSBOMBytes int64
}

// NewProcessor creates a Processor with the documented defaults: 5 000 rows per batch (D2), a 512 MiB
// report cap (D6) and a 256 MiB SBOM cap (D15).
func NewProcessor(store Store, registry *integrations.Registry, objects objectstore.Store, logger *slog.Logger) *Processor {
	if logger == nil {
		logger = slog.Default()
	}
	if registry == nil {
		registry = integrations.DefaultRegistry()
	}
	return &Processor{store: store, engine: NewEngine(store), registry: registry, objects: objects, logger: logger,
		batchRows: 5000, maxReport: 512 << 20, maxSBOMBytes: 256 << 20}
}

// SetLimits overrides the batch size and the size caps (ingest.batchRows, ingest.maxReportBytes).
func (p *Processor) SetLimits(batchRows int, maxReport int64) {
	if batchRows > 0 {
		p.batchRows = batchRows
	}
	if maxReport > 0 {
		p.maxReport = maxReport
	}
}

// StreamSource gives a fresh reader of the report each time it is called (the report is read once
// to verify it and once to parse it, so neither pass holds it in memory).
type StreamSource func(ctx context.Context) (io.ReadCloser, error)

// ProcessParams describes one run to process.
type ProcessParams struct {
	Run             *domain.IngestRun
	Parser          integrations.ParserContract
	ScannerOverride string // names the scanner when the report has no findings to read it from
	ScanFinished    time.Time
	IsEphemeral     bool
	IsSBOM          bool
	Open            StreamSource
}

// Result is the outcome of a processed run.
type Result struct {
	Status domain.IngestRunStatus
	Reason string
	Stats  domain.IngestStats
	// Components is the number of SBOM components stored, for SBOM reports.
	Components int
}

type famState struct {
	scope CloseScope
	buf   []StagedRecord
	stale bool
}

// Process streams the report and applies it. Findings committed by earlier batches are kept when a
// later step fails, and nothing is closed (D2). Errors that retrying cannot fix are *jobs.PermanentError.
func (p *Processor) Process(ctx context.Context, pp ProcessParams) (Result, error) {
	run := pp.Run
	parserID := pp.Parser.Descriptor().ID
	parseCtx := domain.ParseContext{
		TenantID: run.TenantID, ScanSourceID: run.ScanSourceID, ScannerFamily: parserID, Track: run.Track, UploadContext: run.Context,
	}
	fams := map[string]*famState{}
	var order []string
	var stats domain.IngestStats
	var total MergeOutcome
	opts := MergeOptions{FieldMerge: "scanner", ScanFinished: pp.ScanFinished, IsEphemeral: pp.IsEphemeral}

	getFam := func(family string) (*famState, error) {
		if f, ok := fams[family]; ok {
			return f, nil
		}
		f := &famState{scope: CloseScope{TenantID: run.TenantID, ScanSourceID: run.ScanSourceID, ScannerFamily: family, AssetID: run.AssetID, Track: run.Track}}
		if err := p.store.RecordRunScope(ctx, &domain.IngestRunScope{
			IngestRunID: run.ID, TenantID: run.TenantID, ScanSourceID: run.ScanSourceID, ScannerFamily: family, AssetID: run.AssetID, Track: run.Track,
		}); err != nil {
			return nil, err
		}
		fams[family] = f
		order = append(order, family)
		return f, nil
	}
	flush := func(f *famState) error {
		if len(f.buf) == 0 || f.stale {
			f.buf = f.buf[:0]
			return nil
		}
		out, err := p.engine.MergeBatchWithOptions(ctx, f.scope, run.ID, run.ApplicationID, f.buf, opts)
		f.buf = f.buf[:0]
		if errors.Is(err, ErrRunStale) {
			f.stale = true // stored, visible, not merged, nothing closed for this scope (D13)
			return nil
		}
		if err != nil {
			return err
		}
		total.Created += out.Created
		total.Updated += out.Updated
		total.Untouched += out.Untouched
		total.Reactivated += out.Reactivated
		return nil
	}

	rc, err := pp.Open(ctx)
	if err != nil {
		return Result{}, p.openError(err)
	}
	reader := bufio.NewReaderSize(io.LimitReader(rc, p.maxReport+1), 256<<10)
	var parseErr error
	for raw, perr := range pp.Parser.Parse(ctx, reader, parseCtx) {
		if perr != nil {
			parseErr = perr
			break
		}
		stats.Parsed++
		family := firstNonEmpty(pp.ScannerOverride, raw.ScannerFamily, parserID) // D11: the tool, not the parser
		fp := normalize.ComputeFingerprint(normalize.FingerprintParams{
			TenantID: run.TenantID, AssetID: run.AssetID, ApplicationID: run.ApplicationID, Track: run.Track,
			Scope: normalize.ScopeAsset, Family: family, Category: raw.Category, RuleID: raw.RuleID, RawFinding: raw,
		})
		f, err := getFam(family)
		if err != nil {
			_ = rc.Close()
			return Result{}, err
		}
		f.buf = append(f.buf, StagedRecord{
			ScannerFamily: family, FindingKey: fp.FindingKey, Category: raw.Category, RuleID: raw.RuleID, Title: raw.Title,
			Description: raw.Description, ToolSeverity: raw.ToolSeverity, Severity: raw.Severity, Location: raw.Location, CWEs: raw.CWEs,
			VulnID: canonicalVulnID(raw), CVSSVector: raw.CVSSVector,
			ContentHash: normalize.ComputeContentHash(raw.Title, raw.Description, raw.ToolSeverity, raw.CVSSVector, "", raw.Location.PrimaryPath()),
			SeenAt:      pp.ScanFinished, RawPayload: raw.RawPayload,
		})
		if len(f.buf) >= p.batchRows {
			if err := flush(f); err != nil {
				_ = rc.Close()
				return Result{Stats: stats}, fmt.Errorf("%s: %w", ErrCodeMergeFailed, err)
			}
		}
	}
	_ = rc.Close()
	if parseErr != nil {
		return Result{Stats: stats}, &jobs.PermanentError{Code: ErrCodeParse, Err: parseErr}
	}
	// A report with no findings has no tool to read: the scope is the named scanner or the parser id,
	// so a clean rescan can still close what that scope reported before.
	if len(order) == 0 {
		if _, err := getFam(firstNonEmpty(pp.ScannerOverride, parserID)); err != nil {
			return Result{}, err
		}
	}
	for _, name := range order {
		if err := flush(fams[name]); err != nil {
			return Result{Stats: stats}, fmt.Errorf("%s: %w", ErrCodeMergeFailed, err)
		}
	}

	status, reason := domain.RunCompleted, ""
	stale := 0
	closed := 0
	for _, name := range order {
		f := fams[name]
		if f.stale {
			stale++
			continue
		}
		if pp.IsEphemeral { // D10: no close for ephemeral runs
			continue
		}
		res, err := p.engine.CloseScopeStepWithGuard(ctx, f.scope, run.ID, true)
		if err != nil {
			return Result{Stats: stats}, fmt.Errorf("%s: %w", ErrCodeCloseFailed, err)
		}
		closed += res.Closed
		if res.HeldForConfirmation { // D22: a held close is reported, not applied
			status, reason = domain.RunCompletedWithErrors, "close_held"
		}
	}
	if stale == len(order) {
		return Result{Status: domain.RunStale, Stats: stats}, nil
	}
	stats.Created, stats.Updated, stats.Untouched, stats.Reactivated, stats.Closed =
		total.Created, total.Updated, total.Untouched, total.Reactivated, closed

	res := Result{Status: status, Reason: reason, Stats: stats}
	if pp.IsSBOM {
		n, err := p.saveSBOM(ctx, run, parserID, pp.Open)
		if err != nil {
			return res, err
		}
		res.Components = n
	}
	return res, nil
}

func (p *Processor) openError(err error) error {
	if errors.Is(err, objectstore.ErrNotFound) {
		return fmt.Errorf("%s: %w", ErrCodeObjectMissing, err) // may be eventual consistency: retried
	}
	return err
}

// saveSBOM stores the component inventory and dependency graph of an SBOM report. SBOM documents are
// decoded whole (D15), under a size cap.
func (p *Processor) saveSBOM(ctx context.Context, run *domain.IngestRun, parserID string, open StreamSource) (int, error) {
	rc, err := open(ctx)
	if err != nil {
		return 0, p.openError(err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, p.maxSBOMBytes+1))
	if err != nil {
		return 0, err
	}
	if int64(len(data)) > p.maxSBOMBytes {
		return 0, &jobs.PermanentError{Code: ErrCodeSBOMTooLarge, Err: fmt.Errorf("the SBOM is larger than %d bytes", p.maxSBOMBytes)}
	}
	var (
		sbom       *domain.SBOM
		components []domain.SBOMComponent
	)
	switch {
	case strings.Contains(parserID, "cyclonedx"):
		sbom, components, _, _ = cyclonedx.NewParser().ParseSBOM(strings.NewReader(string(data)))
	case strings.Contains(parserID, "spdx"):
		sbom, components, _, _ = spdx.NewParser().ParseSBOM(strings.NewReader(string(data)))
	case strings.Contains(parserID, "syft"):
		sbom, components, _, _ = syft.NewParser().ParseSBOM(strings.NewReader(string(data)))
	}
	if len(components) == 0 {
		return 0, nil
	}
	if sbom == nil {
		sbom = &domain.SBOM{ID: domain.NewID(), Format: parserID, CreatedAt: time.Now().UTC()}
	}
	sbom.TenantID, sbom.AssetID, sbom.IngestRunID, sbom.ComponentCount = run.TenantID, run.AssetID, run.ID, len(components)
	if err := p.store.SaveSBOM(ctx, sbom, components); err != nil {
		return 0, err
	}
	return len(components), nil
}

// Finish records the final status of a run and its metrics.
func (p *Processor) Finish(ctx context.Context, run *domain.IngestRun, status domain.IngestRunStatus, reason string) {
	now := time.Now().UTC()
	run.Status, run.Error, run.FinishedAt = status, reason, &now
	if err := p.store.UpdateIngestRun(ctx, run); err != nil {
		p.logger.Error("recording the final status of an ingest run", "run", run.ID, "status", status, "err", err)
	}
	telemetry.RecordIngestRun(ctx, string(status))
	telemetry.RecordIngestOutcome(ctx, "created", run.Stats.Created)
	telemetry.RecordIngestOutcome(ctx, "updated", run.Stats.Updated)
	telemetry.RecordIngestOutcome(ctx, "untouched", run.Stats.Untouched)
	telemetry.RecordIngestOutcome(ctx, "reactivated", run.Stats.Reactivated)
	telemetry.RecordIngestOutcome(ctx, "closed", run.Stats.Closed)
}

// verifyUpload reads the object once and checks its size and SHA-256 against what the client declared,
// before anything is parsed or merged (D9).
func (p *Processor) verifyUpload(ctx context.Context, u *domain.Upload) error {
	rc, err := p.objects.Open(ctx, u.ObjectRef)
	if err != nil {
		return p.openError(err)
	}
	defer func() { _ = rc.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(rc, p.maxReport+1))
	if err != nil {
		return err
	}
	if n > p.maxReport {
		return &jobs.PermanentError{Code: ErrCodeReportTooLarge, Err: fmt.Errorf("the report is larger than %d bytes", p.maxReport)}
	}
	if n != u.SizeBytes {
		return &jobs.PermanentError{Code: ErrCodeSizeMismatch, Err: fmt.Errorf("declared %d bytes, stored %d", u.SizeBytes, n)}
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, u.SHA256) {
		return &jobs.PermanentError{Code: ErrCodeSHA256Mismatch, Err: errors.New("the stored report does not match the declared SHA-256")}
	}
	return nil
}

// HandleParse is the River worker body for a queued ingest run created by `complete` (D2).
// It is idempotent: a run that already reached a final status is left alone, so a retry after a crash
// in the last step does not repeat work.
func (p *Processor) HandleParse(ctx context.Context, args jobs.ParseJobArgs, attempt int) error {
	run, err := p.store.GetIngestRun(ctx, args.TenantID, args.IngestRunID)
	if err != nil {
		return err
	}
	switch run.Status {
	case domain.RunCompleted, domain.RunCompletedWithErrors, domain.RunFailed, domain.RunStale:
		return nil
	}
	err = p.processUploadedRun(ctx, run)
	if err == nil {
		return nil
	}
	var perm *jobs.PermanentError
	switch {
	case errors.As(err, &perm):
		p.Finish(ctx, run, domain.RunFailed, perm.Code)
	case attempt >= jobs.ParseMaxAttempts:
		p.Finish(ctx, run, domain.RunFailed, ErrCodeRetriesExhausted)
		return &jobs.PermanentError{Code: ErrCodeRetriesExhausted, Err: err}
	default:
		p.logger.Warn("ingest run will be retried", "run", run.ID, "attempt", attempt, "err", err)
	}
	return err
}

func (p *Processor) processUploadedRun(ctx context.Context, run *domain.IngestRun) error {
	if run.UploadID == nil {
		return &jobs.PermanentError{Code: ErrCodeParse, Err: errors.New("the run has no upload")}
	}
	u, err := p.store.GetUpload(ctx, run.TenantID, *run.UploadID)
	if err != nil {
		return err
	}
	run.Status = domain.RunParsing
	if err := p.store.UpdateIngestRun(ctx, run); err != nil {
		return err
	}
	if err := p.verifyUpload(ctx, u); err != nil { // D9: before any merge
		return err
	}

	open := func(ctx context.Context) (io.ReadCloser, error) { return p.objects.Open(ctx, u.ObjectRef) }
	parser, isSBOM, err := p.selectParser(ctx, u.FormatHint, open)
	if err != nil {
		return err
	}
	run.Status = domain.RunMerging
	_ = p.store.UpdateIngestRun(ctx, run)

	res, err := p.Process(ctx, ProcessParams{
		Run: run, Parser: parser, IsSBOM: isSBOM, ScanFinished: scanFinishedOf(u.Context),
		IsEphemeral: IsEphemeral(u.Context.Branch, nil), Open: open,
	})
	if err != nil {
		return err
	}
	run.Stats = res.Stats
	p.Finish(ctx, run, res.Status, res.Reason)
	return nil
}

// selectParser picks the parser from the declared format, or detects it from the first 64 KiB.
func (p *Processor) selectParser(ctx context.Context, hint string, open StreamSource) (integrations.ParserContract, bool, error) {
	var parser integrations.ParserContract
	if hint != "" {
		var err error
		if parser, err = p.registry.GetParser("builtin:" + strings.ToLower(hint)); err != nil {
			parser, _ = p.registry.GetParser(strings.ToLower(hint))
		}
	}
	if parser == nil {
		rc, err := open(ctx)
		if err != nil {
			return nil, false, p.openError(err)
		}
		head := make([]byte, 64<<10)
		n, _ := io.ReadFull(rc, head)
		_ = rc.Close()
		var score int
		parser, score = p.registry.DetectParser(head[:n], "", "")
		if parser == nil || score < 40 {
			return nil, false, &jobs.PermanentError{Code: ErrCodeUnsupportedFormat, Err: errors.New("the report format is not recognised")}
		}
	}
	id := parser.Descriptor().ID
	return parser, strings.Contains(id, "cyclonedx") || strings.Contains(id, "spdx") || strings.Contains(id, "syft"), nil
}

func scanFinishedOf(c domain.UploadContext) time.Time {
	if !c.ScanFinished.IsZero() && !c.ScanFinished.After(time.Now()) {
		return c.ScanFinished.UTC()
	}
	return time.Now().UTC()
}
