package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"rampart/internal/domain"
	trackerclient "rampart/internal/tracker/client"
	trackerv1 "rampart/pkg/api/tracker/v1"
)

// GrpcTracker adapts a remote gRPC TrackerService container to Rampart's domain.Tracker interface.
// Rampart core remains responsible for outbox persistence, retries, backoff, rate limits, and approvals.
type GrpcTracker struct {
	connectorName  string
	policy         domain.ConnectorTicketingPolicy
	cfg            domain.ExternalTrackerConnectorConfig
	client         *trackerclient.Client
	secrets        map[string]string
	publicURL      string
	tenantSlug     string
	acceptedFields []string
}

// NewGrpcTracker constructs a GrpcTracker wrapping an already dialed gRPC client.
func NewGrpcTracker(cfg domain.ExternalTrackerConnectorConfig, client *trackerclient.Client, secrets map[string]string, publicURL string) (*GrpcTracker, error) {
	if client == nil {
		return nil, errors.New("grpc tracker: client is nil")
	}
	if strings.TrimSpace(cfg.TrackerRef.Name) == "" {
		return nil, errors.New("grpc tracker: trackerRef.name is required")
	}
	secCopy := make(map[string]string, len(secrets))
	for k, v := range secrets {
		secCopy[k] = v
	}
	return &GrpcTracker{
		cfg:       cfg,
		client:    client,
		secrets:   secCopy,
		publicURL: strings.TrimRight(strings.TrimSpace(publicURL), "/"),
	}, nil
}

// Name returns the connector name or the referenced tracker resource name.
func (g *GrpcTracker) Name() string {
	if g.connectorName != "" {
		return g.connectorName
	}
	if g.cfg.TrackerRef.Name != "" {
		return g.cfg.TrackerRef.Name
	}
	return "external-tracker"
}

// SetConnectorName sets the connector instance name used for outbox attribution.
func (g *GrpcTracker) SetConnectorName(name string) { g.connectorName = name }

// SetTicketingPolicy sets automated ticketing routing and hourly rate-cap settings.
func (g *GrpcTracker) SetTicketingPolicy(p domain.ConnectorTicketingPolicy) { g.policy = p }

// MaxPerHour returns the configured hourly ticket cap or 0 if unset.
func (g *GrpcTracker) MaxPerHour() int { return g.policy.MaxPerHour }

// SetTenantSlug records the tenant URL slug used in deep links.
func (g *GrpcTracker) SetTenantSlug(s string) { g.tenantSlug = s }

// SetAcceptedFields caches create screen field IDs learned during CheckDetailed (D87).
func (g *GrpcTracker) SetAcceptedFields(fields []string) { g.acceptedFields = fields }

// CloseClient closes the underlying gRPC connection.
func (g *GrpcTracker) CloseClient() error {
	if g.client != nil {
		return g.client.Close()
	}
	return nil
}

func (g *GrpcTracker) targetContext() *trackerv1.TargetContext {
	cfgJSON := g.cfg.Config
	if len(cfgJSON) == 0 && (len(g.cfg.StatusMapping.ClosedStatuses) > 0 || len(g.cfg.StatusMapping.ResolutionToState) > 0 || g.cfg.DefaultProject != "") {
		// Merge status mapping / defaults if config JSON wasn't already supplied
		payload := map[string]any{
			"defaultProject": g.cfg.DefaultProject,
			"statusMapping":  g.cfg.StatusMapping,
		}
		if b, err := json.Marshal(payload); err == nil {
			cfgJSON = b
		}
	}
	return &trackerv1.TargetContext{
		BindingName:    g.Name(),
		ConfigJson:     cfgJSON,
		Secrets:        g.secrets,
		TenantSlug:     g.tenantSlug,
		PublicUrl:      g.publicURL,
		AccountId:      g.cfg.AccountID,
		AcceptedFields: g.acceptedFields,
	}
}

func (g *GrpcTracker) findingLink(f *domain.Finding) string {
	if g.publicURL == "" || g.tenantSlug == "" || f == nil {
		return ""
	}
	if f.Notice != "" {
		return fmt.Sprintf("%s/t/%s/compliance", g.publicURL, g.tenantSlug)
	}
	return fmt.Sprintf("%s/t/%s/findings/%s", g.publicURL, g.tenantSlug, f.ID.String())
}

func (g *GrpcTracker) resolveProject(appName string) string {
	if appName != "" && len(g.policy.Projects) > 0 {
		if p := strings.TrimSpace(g.policy.Projects[appName]); p != "" {
			return p
		}
	}
	if p := strings.TrimSpace(g.policy.Project); p != "" {
		return p
	}
	return strings.TrimSpace(g.cfg.DefaultProject)
}

func (g *GrpcTracker) issuePayload(f *domain.Finding, appName string) *trackerv1.IssuePayload {
	if f == nil {
		return &trackerv1.IssuePayload{AppName: appName, Project: g.resolveProject(appName)}
	}
	kind := "finding"
	if f.Notice == "attestation-renewal" {
		kind = "attestation"
	} else if f.RuleID == "" && strings.Contains(f.Title, " findings)") {
		kind = "group"
	}
	vulnID := ""
	if f.VulnerabilityID != nil {
		vulnID = *f.VulnerabilityID
	}
	purl := ""
	if f.Location.Package != nil {
		purl = f.Location.Package.Purl
	}

	var customFields []*trackerv1.CustomFieldValue
	for k, tmpl := range g.cfg.CustomFields {
		if coreJiraFields[k] {
			continue
		}
		rendered := renderCustomField(tmpl, f, appName)
		cf := &trackerv1.CustomFieldValue{Name: k}
		switch v := rendered.(type) {
		case int:
			cf.Kind = "number"
			cf.NumberValue = float64(v)
		case int64:
			cf.Kind = "number"
			cf.NumberValue = float64(v)
		case float64:
			cf.Kind = "number"
			cf.NumberValue = v
		case bool:
			cf.Kind = "bool"
			cf.BoolValue = v
		default:
			cf.Kind = "string"
			cf.StringValue = fmt.Sprint(v)
		}
		customFields = append(customFields, cf)
	}

	return &trackerv1.IssuePayload{
		Id:               f.ID.String(),
		Kind:             kind,
		Title:            f.Title,
		Description:      f.Description,
		Severity:         string(f.Severity),
		RiskScore:        float64(f.RiskScore),
		RiskBand:         string(f.RiskBand),
		RuleId:           f.RuleID,
		ScannerFamily:    f.RuleScannerFamily,
		VulnerabilityId:  vulnID,
		Notice:           f.Notice,
		LocationPath:     f.Location.PrimaryPath(),
		Purl:             purl,
		AppName:          appName,
		Project:          g.resolveProject(appName),
		FindingUrl:       g.findingLink(f),
		IdempotencyLabel: FindingLabel(f.ID),
		CustomFields:     customFields,
		OccurrenceCount:  int32(f.OccurrenceCount),
	}
}

// Check verifies upstream connectivity and credentials via the tracker container.
func (g *GrpcTracker) Check(ctx context.Context) error {
	_, err := g.CheckDetailed(ctx)
	return err
}

// CheckDetailed verifies credentials and returns AccountID and AcceptedFields learned by the container (D87).
func (g *GrpcTracker) CheckDetailed(ctx context.Context) (domain.ConnectorCheckInfo, error) {
	resp, err := g.client.Check(ctx, g.targetContext())
	if err != nil {
		return domain.ConnectorCheckInfo{}, SanitizeError(err)
	}
	if ce := trackerclient.MapError(resp.GetError()); ce != nil {
		return domain.ConnectorCheckInfo{
			AccountID:      resp.GetAccountId(),
			AcceptedFields: resp.GetAcceptedFields(),
		}, ce
	}
	if !resp.GetOk() {
		return domain.ConnectorCheckInfo{
			AccountID:      resp.GetAccountId(),
			AcceptedFields: resp.GetAcceptedFields(),
		}, errors.New("tracker container rejected connection check")
	}
	return domain.ConnectorCheckInfo{
		AccountID:      resp.GetAccountId(),
		AcceptedFields: resp.GetAcceptedFields(),
	}, nil
}

// CreateIssue creates an upstream ticket for finding f and returns its external reference and URL.
func (g *GrpcTracker) CreateIssue(ctx context.Context, f *domain.Finding, appName string) (string, string, error) {
	resp, err := g.client.CreateIssue(ctx, g.targetContext(), g.issuePayload(f, appName))
	if err != nil {
		return "", "", SanitizeError(err)
	}
	if ce := trackerclient.MapError(resp.GetError()); ce != nil {
		return "", "", ce
	}
	if strings.TrimSpace(resp.GetTicketId()) == "" {
		return "", "", errors.New("tracker container returned empty ticket_id")
	}
	return resp.GetTicketId(), resp.GetTicketUrl(), nil
}

// FindIssueByLabel queries the upstream tracker for an existing issue carrying Rampart's idempotency label.
func (g *GrpcTracker) FindIssueByLabel(ctx context.Context, label string) (string, string, error) {
	resp, err := g.client.FindIssueByLabel(ctx, g.targetContext(), label)
	if err != nil {
		return "", "", SanitizeError(err)
	}
	if ce := trackerclient.MapError(resp.GetError()); ce != nil {
		return "", "", ce
	}
	if !resp.GetFound() {
		return "", "", nil
	}
	return resp.GetTicketId(), resp.GetTicketUrl(), nil
}

// Comment posts a comment on an upstream ticket.
func (g *GrpcTracker) Comment(ctx context.Context, ticketRef, comment string) error {
	resp, err := g.client.Comment(ctx, g.targetContext(), ticketRef, comment)
	if err != nil {
		return SanitizeError(err)
	}
	return trackerclient.MapError(resp.GetError())
}

// Close closes an upstream ticket.
func (g *GrpcTracker) Close(ctx context.Context, ticketRef string) error {
	resp, err := g.client.CloseIssue(ctx, g.targetContext(), ticketRef, "resolved in Rampart")
	if err != nil {
		return SanitizeError(err)
	}
	return trackerclient.MapError(resp.GetError())
}

// ParseWebhook delegates vendor HMAC verification and payload normalization to the container.
func (g *GrpcTracker) ParseWebhook(ctx context.Context, headers map[string]string, body []byte, secret string) (*trackerv1.ParseWebhookResponse, error) {
	resp, err := g.client.ParseWebhook(ctx, g.targetContext(), headers, body, secret)
	if err != nil {
		return nil, SanitizeError(err)
	}
	return resp, nil
}
