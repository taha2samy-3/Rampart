package client_test

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"rampart/internal/domain"
	"rampart/internal/tracker/client"
	trackerv1 "rampart/pkg/api/tracker/v1"
)

type mockTrackerServer struct {
	trackerv1.UnimplementedTrackerServiceServer
	lastAuthHeader string
	checkErr       *trackerv1.TrackerCallError
}

func (s *mockTrackerServer) captureAuth(ctx context.Context) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		vals := md.Get("authorization")
		if len(vals) > 0 {
			s.lastAuthHeader = vals[0]
		}
	}
}

func (s *mockTrackerServer) HealthCheck(ctx context.Context, _ *trackerv1.HealthCheckRequest) (*trackerv1.HealthCheckResponse, error) {
	s.captureAuth(ctx)
	return &trackerv1.HealthCheckResponse{
		Status:  trackerv1.HealthCheckResponse_SERVING,
		Message: "tracker ready",
	}, nil
}

func (s *mockTrackerServer) GetMetadata(ctx context.Context, _ *trackerv1.GetMetadataRequest) (*trackerv1.GetMetadataResponse, error) {
	return &trackerv1.GetMetadataResponse{
		Provider:     "jira",
		DisplayName:  "Jira Cloud / DC Container",
		Version:      "1.0.0",
		Capabilities: []string{"create_issue", "find_by_label", "comment", "close", "two_way_webhook"},
	}, nil
}

func (s *mockTrackerServer) Check(ctx context.Context, req *trackerv1.CheckRequest) (*trackerv1.CheckResponse, error) {
	s.captureAuth(ctx)
	if s.checkErr != nil {
		return &trackerv1.CheckResponse{Ok: false, Error: s.checkErr}, nil
	}
	return &trackerv1.CheckResponse{
		Ok:             true,
		AccountId:      "bot-acct-1",
		AcceptedFields: []string{"summary", "description", "priority", "labels"},
	}, nil
}

func (s *mockTrackerServer) CreateIssue(_ context.Context, req *trackerv1.CreateIssueRequest) (*trackerv1.CreateIssueResponse, error) {
	return &trackerv1.CreateIssueResponse{
		TicketId:  "SEC-42",
		TicketUrl: "https://jira.example.com/browse/SEC-42",
	}, nil
}

func (s *mockTrackerServer) FindIssueByLabel(_ context.Context, req *trackerv1.FindIssueByLabelRequest) (*trackerv1.FindIssueByLabelResponse, error) {
	return &trackerv1.FindIssueByLabelResponse{
		Found:     true,
		TicketId:  "SEC-42",
		TicketUrl: "https://jira.example.com/browse/SEC-42",
	}, nil
}

func (s *mockTrackerServer) Comment(_ context.Context, _ *trackerv1.CommentRequest) (*trackerv1.CommentResponse, error) {
	return &trackerv1.CommentResponse{}, nil
}

func (s *mockTrackerServer) Close(_ context.Context, _ *trackerv1.CloseRequest) (*trackerv1.CloseResponse, error) {
	return &trackerv1.CloseResponse{}, nil
}

func (s *mockTrackerServer) ParseWebhook(_ context.Context, req *trackerv1.ParseWebhookRequest) (*trackerv1.ParseWebhookResponse, error) {
	return &trackerv1.ParseWebhookResponse{
		Verified:    req.GetWebhookSecret() == "hook-secret",
		DeliveryId:  "deliv-1",
		ExternalRef: "SEC-42",
		ActorId:     "human-1",
		EventAction: "closed",
		Resolution:  "Fixed",
	}, nil
}

func (s *mockTrackerServer) PollStates(_ context.Context, req *trackerv1.PollStatesRequest) (*trackerv1.PollStatesResponse, error) {
	return &trackerv1.PollStatesResponse{
		States: []*trackerv1.PolledTicketState{{TicketRef: req.GetTicketRefs()[0], ExternalStatus: "Done", Closed: true}},
	}, nil
}

func setupTestClient(t *testing.T, srvImpl *mockTrackerServer) (*client.Client, func()) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	trackerv1.RegisterTrackerServiceServer(srv, srvImpl)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufnet: %v", err)
	}
	c := client.NewFromConn(conn)
	return c, func() {
		_ = c.Close()
		srv.Stop()
	}
}

func TestTrackerClient_FullContractAndProbe(t *testing.T) {
	srvImpl := &mockTrackerServer{}
	c, cleanup := setupTestClient(t, srvImpl)
	defer cleanup()
	c.WithBearerToken("shared-token")

	ctx := context.Background()
	probe, err := client.ProbeClient(ctx, c)
	if err != nil {
		t.Fatalf("ProbeClient: %v", err)
	}
	if !probe.Serving || probe.Provider != "jira" || len(probe.Capabilities) != 5 {
		t.Fatalf("unexpected probe result: %+v", probe)
	}
	if srvImpl.lastAuthHeader != "Bearer shared-token" {
		t.Errorf("bearer auth = %q, want Bearer shared-token", srvImpl.lastAuthHeader)
	}

	target := &trackerv1.TargetContext{BindingName: "jira-sec", Secrets: map[string]string{"token": "abc"}}
	chk, err := c.Check(ctx, target)
	if err != nil || !chk.GetOk() || chk.GetAccountId() != "bot-acct-1" {
		t.Fatalf("Check: %+v err=%v", chk, err)
	}

	cr, err := c.CreateIssue(ctx, target, &trackerv1.IssuePayload{Id: "f-1", Title: "SQLi", Project: "SEC"})
	if err != nil || cr.GetTicketId() != "SEC-42" {
		t.Fatalf("CreateIssue: %+v err=%v", cr, err)
	}

	found, err := c.FindIssueByLabel(ctx, target, "rampart-finding-f-1")
	if err != nil || !found.GetFound() || found.GetTicketId() != "SEC-42" {
		t.Fatalf("FindIssueByLabel: %+v err=%v", found, err)
	}

	if _, err := c.Comment(ctx, target, "SEC-42", "Updated"); err != nil {
		t.Fatalf("Comment: %v", err)
	}
	if _, err := c.CloseIssue(ctx, target, "SEC-42", "fixed"); err != nil {
		t.Fatalf("CloseIssue: %v", err)
	}

	wh, err := c.ParseWebhook(ctx, target, map[string]string{"x-sig": "1"}, []byte("{}"), "hook-secret")
	if err != nil || !wh.GetVerified() || wh.GetEventAction() != "closed" {
		t.Fatalf("ParseWebhook: %+v err=%v", wh, err)
	}

	polled, err := c.PollStates(ctx, target, []string{"SEC-42"})
	if err != nil || len(polled.GetStates()) != 1 || !polled.GetStates()[0].GetClosed() {
		t.Fatalf("PollStates: %+v err=%v", polled, err)
	}
}

func TestMapError_PreservesFatalClassification(t *testing.T) {
	fatalErr := client.MapError(&trackerv1.TrackerCallError{HttpStatus: 401, Fatal: true, Message: "unauthorized"})
	isFatal, status := domain.IsFatalTrackerError(fatalErr)
	if !isFatal || status != 401 {
		t.Fatalf("got fatal=%v status=%d, want true, 401", isFatal, status)
	}

	retryableErr := client.MapError(&trackerv1.TrackerCallError{HttpStatus: 503, Fatal: false, Message: "upstream busy"})
	isFatal, status = domain.IsFatalTrackerError(retryableErr)
	if isFatal || status != 503 {
		t.Fatalf("got fatal=%v status=%d, want false, 503", isFatal, status)
	}
}
