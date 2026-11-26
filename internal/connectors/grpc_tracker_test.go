package connectors_test

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	trackerclient "rampart/internal/tracker/client"
	trackerv1 "rampart/pkg/api/tracker/v1"
)

type fakeTrackerService struct {
	trackerv1.UnimplementedTrackerServiceServer

	lastCheckCtx    *trackerv1.TargetContext
	lastCreateReq   *trackerv1.CreateIssueRequest
	lastFindLabel   string
	lastCommentReq  *trackerv1.CommentRequest
	lastCloseReq    *trackerv1.CloseRequest
	lastWebhookReq  *trackerv1.ParseWebhookRequest
	checkErr        *trackerv1.TrackerCallError
	createErr       *trackerv1.TrackerCallError
	findFound       bool
	findTicketID    string
	findTicketURL   string
	webhookResponse *trackerv1.ParseWebhookResponse
}

func (f *fakeTrackerService) HealthCheck(context.Context, *trackerv1.HealthCheckRequest) (*trackerv1.HealthCheckResponse, error) {
	return &trackerv1.HealthCheckResponse{Status: trackerv1.HealthCheckResponse_SERVING, Message: "ready"}, nil
}

func (f *fakeTrackerService) GetMetadata(context.Context, *trackerv1.GetMetadataRequest) (*trackerv1.GetMetadataResponse, error) {
	return &trackerv1.GetMetadataResponse{
		Provider:     "jira",
		DisplayName:  "Jira Container",
		Version:      "1.0.0",
		Capabilities: []string{"create_issue", "find_by_label", "comment", "close", "two_way_webhook"},
	}, nil
}

func (f *fakeTrackerService) Check(_ context.Context, req *trackerv1.CheckRequest) (*trackerv1.CheckResponse, error) {
	f.lastCheckCtx = req.GetTarget()
	if f.checkErr != nil {
		return &trackerv1.CheckResponse{Ok: false, Error: f.checkErr}, nil
	}
	return &trackerv1.CheckResponse{
		Ok:             true,
		AccountId:      "bot-jira-1",
		AcceptedFields: []string{"summary", "description", "customfield_10042"},
	}, nil
}

func (f *fakeTrackerService) CreateIssue(_ context.Context, req *trackerv1.CreateIssueRequest) (*trackerv1.CreateIssueResponse, error) {
	f.lastCreateReq = req
	if f.createErr != nil {
		return &trackerv1.CreateIssueResponse{Error: f.createErr}, nil
	}
	return &trackerv1.CreateIssueResponse{
		TicketId:  "SEC-101",
		TicketUrl: "https://jira.example.com/browse/SEC-101",
	}, nil
}

func (f *fakeTrackerService) FindIssueByLabel(_ context.Context, req *trackerv1.FindIssueByLabelRequest) (*trackerv1.FindIssueByLabelResponse, error) {
	f.lastFindLabel = req.GetLabel()
	return &trackerv1.FindIssueByLabelResponse{
		Found:     f.findFound,
		TicketId:  f.findTicketID,
		TicketUrl: f.findTicketURL,
	}, nil
}

func (f *fakeTrackerService) Comment(_ context.Context, req *trackerv1.CommentRequest) (*trackerv1.CommentResponse, error) {
	f.lastCommentReq = req
	return &trackerv1.CommentResponse{}, nil
}

func (f *fakeTrackerService) Close(_ context.Context, req *trackerv1.CloseRequest) (*trackerv1.CloseResponse, error) {
	f.lastCloseReq = req
	return &trackerv1.CloseResponse{}, nil
}

func (f *fakeTrackerService) ParseWebhook(_ context.Context, req *trackerv1.ParseWebhookRequest) (*trackerv1.ParseWebhookResponse, error) {
	f.lastWebhookReq = req
	if f.webhookResponse != nil {
		return f.webhookResponse, nil
	}
	return &trackerv1.ParseWebhookResponse{
		Verified:    req.GetWebhookSecret() == "whsec",
		DeliveryId:  "deliv-1",
		ExternalRef: "SEC-101",
		ActorId:     "user-9",
		EventAction: "closed",
		Resolution:  "Fixed",
	}, nil
}

func startFakeTrackerClient(t *testing.T, svc trackerv1.TrackerServiceServer) *trackerclient.Client {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	trackerv1.RegisterTrackerServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = lis.Close()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	cli := trackerclient.NewFromConn(conn)
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

type storeWithTrackers struct {
	*ingest.MemoryStore
	trackers []domain.StoredTrackerObject
}

func (s *storeWithTrackers) ListTrackers(_ context.Context, _ uuid.UUID) ([]domain.StoredTrackerObject, error) {
	return append([]domain.StoredTrackerObject(nil), s.trackers...), nil
}

func (s *storeWithTrackers) GetTracker(_ context.Context, _ uuid.UUID, scope, namespace, name string) (domain.StoredTrackerObject, bool, error) {
	for _, tr := range s.trackers {
		if tr.Origin == scope && tr.Namespace == namespace && tr.Name == name {
			return tr, true, nil
		}
	}
	return domain.StoredTrackerObject{}, false, nil
}

func TestGrpcTracker_CRUDTypedCustomFieldsAndErrors(t *testing.T) {
	ctx := context.Background()
	svc := &fakeTrackerService{findFound: true, findTicketID: "SEC-101", findTicketURL: "https://jira.example.com/browse/SEC-101"}
	cli := startFakeTrackerClient(t, svc)

	cfg := domain.ExternalTrackerConnectorConfig{
		TrackerRef:     domain.ExternalTrackerRef{Scope: "cluster", Name: "jira-container"},
		DefaultProject: "SEC",
		StatusMapping: domain.JiraStatusMapping{
			ClosedStatuses:    []string{"Done"},
			ResolutionToState: map[string]string{"False Positive": "false_positive"},
		},
		CustomFields: map[string]string{
			"project":           "EVIL",                     // core field must be stripped
			"summary":           "evil summary",             // core field must be stripped
			"customfield_10042": "{{ finding.risk_score }}", // numeric custom field preserved as number
			"customfield_10043": "{{ finding.severity }} in {{ app.name }}",
		},
	}

	tr, err := connectors.NewGrpcTracker(cfg, cli, map[string]string{"token": "tok-1"}, "https://rampart.example.com/")
	if err != nil {
		t.Fatalf("NewGrpcTracker: %v", err)
	}
	tr.SetConnectorName("jira-prod")
	tr.SetTenantSlug("acme")
	tr.SetTicketingPolicy(domain.ConnectorTicketingPolicy{
		OnCritical: true,
		Project:    "DEFAULT",
		Projects:   map[string]string{"Checkout": "CHK"},
	})
	tr.SetAcceptedFields([]string{"summary", "customfield_10042"})

	info, err := tr.CheckDetailed(ctx)
	if err != nil {
		t.Fatalf("CheckDetailed: %v", err)
	}
	if info.AccountID != "bot-jira-1" || len(info.AcceptedFields) != 3 {
		t.Fatalf("unexpected CheckDetailed info: %+v", info)
	}
	if svc.lastCheckCtx.GetSecrets()["token"] != "tok-1" {
		t.Fatalf("expected token secret in TargetContext, got %+v", svc.lastCheckCtx.GetSecrets())
	}

	f := critical()
	ref, link, err := tr.CreateIssue(ctx, f, "Checkout")
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if ref != "SEC-101" || link != "https://jira.example.com/browse/SEC-101" {
		t.Fatalf("unexpected CreateIssue ref=%q link=%q", ref, link)
	}

	issue := svc.lastCreateReq.GetIssue()
	if issue.GetProject() != "CHK" {
		t.Fatalf("expected per-app project CHK, got %q", issue.GetProject())
	}
	if issue.GetFindingUrl() != "https://rampart.example.com/t/acme/findings/"+f.ID.String() {
		t.Fatalf("unexpected finding URL: %q", issue.GetFindingUrl())
	}
	if issue.GetKind() != "finding" || issue.GetIdempotencyLabel() != connectors.FindingLabel(f.ID) {
		t.Fatalf("unexpected kind=%q label=%q", issue.GetKind(), issue.GetIdempotencyLabel())
	}

	cfMap := map[string]*trackerv1.CustomFieldValue{}
	for _, cf := range issue.GetCustomFields() {
		cfMap[cf.GetName()] = cf
	}
	if _, forbidden := cfMap["project"]; forbidden {
		t.Fatal("core field 'project' must not pass through customFields")
	}
	if _, forbidden := cfMap["summary"]; forbidden {
		t.Fatal("core field 'summary' must not pass through customFields")
	}
	if cfMap["customfield_10042"].GetKind() != "number" || cfMap["customfield_10042"].GetNumberValue() != 940 {
		t.Fatalf("expected number custom field 940, got %+v", cfMap["customfield_10042"])
	}
	if cfMap["customfield_10043"].GetKind() != "string" || cfMap["customfield_10043"].GetStringValue() != "critical in Checkout" {
		t.Fatalf("unexpected string custom field: %+v", cfMap["customfield_10043"])
	}

	// Attestation notice routes to compliance link & kind="attestation"
	att := &domain.Finding{ID: uuid.New(), Notice: "attestation-renewal", Title: "Renewal", Severity: domain.SeverityMedium}
	_, _, _ = tr.CreateIssue(ctx, att, "Checkout")
	if svc.lastCreateReq.GetIssue().GetKind() != "attestation" || !strings.HasSuffix(svc.lastCreateReq.GetIssue().GetFindingUrl(), "/t/acme/compliance") {
		t.Fatalf("attestation routing mismatch: kind=%q url=%q", svc.lastCreateReq.GetIssue().GetKind(), svc.lastCreateReq.GetIssue().GetFindingUrl())
	}

	// Group issue sets kind="group"
	grp := &domain.Finding{ID: uuid.New(), Title: "CVE-1 (3 findings)", Severity: domain.SeverityHigh}
	_, _, _ = tr.CreateIssue(ctx, grp, "OtherApp")
	if svc.lastCreateReq.GetIssue().GetKind() != "group" || svc.lastCreateReq.GetIssue().GetProject() != "DEFAULT" {
		t.Fatalf("group routing mismatch: kind=%q project=%q", svc.lastCreateReq.GetIssue().GetKind(), svc.lastCreateReq.GetIssue().GetProject())
	}

	if id, u, err := tr.FindIssueByLabel(ctx, connectors.FindingLabel(f.ID)); err != nil || id != "SEC-101" || u == "" {
		t.Fatalf("FindIssueByLabel unexpected: id=%q url=%q err=%v", id, u, err)
	}
	if err := tr.Comment(ctx, "SEC-101", "re-opened"); err != nil || svc.lastCommentReq.GetBody() != "re-opened" {
		t.Fatalf("Comment unexpected: err=%v req=%+v", err, svc.lastCommentReq)
	}
	if err := tr.Close(ctx, "SEC-101"); err != nil || svc.lastCloseReq.GetTicketRef() != "SEC-101" {
		t.Fatalf("Close unexpected: err=%v req=%+v", err, svc.lastCloseReq)
	}
	wh, err := tr.ParseWebhook(ctx, map[string]string{"X-Test": "1"}, []byte(`{}`), "whsec")
	if err != nil || !wh.GetVerified() || wh.GetEventAction() != "closed" {
		t.Fatalf("ParseWebhook unexpected: err=%v wh=%+v", err, wh)
	}

	// Fatal 401 TrackerError surfaces cleanly
	svc.createErr = &trackerv1.TrackerCallError{
		Code:       "auth_failed",
		HttpStatus: 401,
		Message:    "expired API token",
		Fatal:      true,
	}
	_, _, err = tr.CreateIssue(ctx, f, "Checkout")
	if fatal, code := domain.IsFatalTrackerError(err); !fatal || code != 401 {
		t.Fatalf("expected fatal 401 TrackerError, got fatal=%v code=%d err=%v", fatal, code, err)
	}
}

func TestDefaultTrackerResolverAndChecker_ExternalTracker(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	svc := &fakeTrackerService{}
	cli := startFakeTrackerClient(t, svc)

	specJSON := []byte(`{"service":{"name":"jira-svc","namespace":"tools","port":50051}}`)
	st := &storeWithTrackers{
		MemoryStore: ingest.NewMemoryStore(),
		trackers: []domain.StoredTrackerObject{
			{Origin: "cluster", Name: "jira-container", Spec: specJSON},
		},
	}

	conn := domain.Connector{
		Name:     "jira-ext",
		TenantID: tenantID,
		Type:     domain.ConnectorTypeExternalTracker,
		Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeExternalTracker,
			ExternalTracker: &domain.ExternalTrackerConnectorConfig{
				TrackerRef:     domain.ExternalTrackerRef{Scope: "cluster", Name: "jira-container"},
				DefaultProject: "SEC",
				Secrets:        map[string]domain.SecretKeyRef{"token": {Name: "jira-sec", Key: "token"}},
			},
			Ticketing: &domain.ConnectorTicketingPolicy{OnCritical: true},
		},
	}
	_ = st.SaveConnector(ctx, tenantID, conn)

	secrets := &mockSecretResolver{
		secrets: map[string][]byte{
			tenantID.String() + ":connector:jira-ext:token": []byte("super-secret"),
		},
	}

	// Verify DefaultChecker.CheckDetailed
	checker := connectors.NewDefaultChecker(loopbackClient(), &domain.PlatformSSRFAllowlist{AllowLoopback: true})
	checker.SetTrackerStore(st)
	checker.SetTrackerDialer(func(cfg trackerclient.DialConfig) (*trackerclient.Client, error) {
		if cfg.Target != "jira-svc.tools.svc.cluster.local:50051" {
			t.Fatalf("unexpected dial target %q", cfg.Target)
		}
		return cli, nil
	})
	info, err := checker.CheckDetailed(ctx, conn, []byte(`{"token":"super-secret"}`))
	if err != nil || info.AccountID != "bot-jira-1" {
		t.Fatalf("CheckDetailed externalTracker failed: info=%+v err=%v", info, err)
	}

	// Verify DefaultTrackerResolver.ResolveTracker
	resolver := connectors.NewDefaultTrackerResolver(st, secrets, loopbackClient(), "https://rampart.example.com")
	resolver.SetTrackerDialer(func(trackerclient.DialConfig) (*trackerclient.Client, error) {
		return startFakeTrackerClient(t, svc), nil
	})
	tr, err := resolver.ResolveTracker(ctx, tenantID)
	if err != nil {
		t.Fatalf("ResolveTracker failed: %v", err)
	}
	gt, ok := tr.(*connectors.GrpcTracker)
	if !ok {
		t.Fatalf("expected *connectors.GrpcTracker, got %T", tr)
	}
	ref, _, err := gt.CreateIssue(ctx, critical(), "Payments")
	if err != nil || ref != "SEC-101" {
		t.Fatalf("resolved GrpcTracker.CreateIssue failed: ref=%q err=%v", ref, err)
	}
	if svc.lastCreateReq.GetTarget().GetSecrets()["token"] != "super-secret" {
		t.Fatalf("expected resolved secret passed to container, got %+v", svc.lastCreateReq.GetTarget().GetSecrets())
	}
}
