package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	trackerv1 "rampart/pkg/api/tracker/v1"
)

// Server implements Rampart's gRPC TrackerService contract as a standalone microservice.
// Replace the in-memory store with upstream Jira / GitHub / Linear HTTP API calls.
type Server struct {
	trackerv1.UnimplementedTrackerServiceServer
	mu     sync.Mutex
	seq    int
	byLbl  map[string]*trackerv1.CreateIssueResponse
	states map[string]string
}

func NewServer() *Server {
	return &Server{
		byLbl:  make(map[string]*trackerv1.CreateIssueResponse),
		states: make(map[string]string),
	}
}

func (s *Server) HealthCheck(context.Context, *trackerv1.HealthCheckRequest) (*trackerv1.HealthCheckResponse, error) {
	return &trackerv1.HealthCheckResponse{
		Status:  trackerv1.HealthCheckResponse_SERVING,
		Message: "external tracker ready",
	}, nil
}

func (s *Server) GetMetadata(context.Context, *trackerv1.GetMetadataRequest) (*trackerv1.GetMetadataResponse, error) {
	return &trackerv1.GetMetadataResponse{
		Provider:         "reference-tracker",
		DisplayName:      "Reference Issue Tracker Container",
		Version:          "1.0.0",
		Description:      "Standalone gRPC TrackerService reference implementation.",
		Capabilities:     []string{"create_issue", "find_by_label", "comment", "close", "two_way_webhook"},
		ConfigSchemaJson: `{"type":"object","properties":{"defaultProject":{"type":"string"}}}`,
		DeclaredSecrets: []*trackerv1.SecretDeclaration{
			{Name: "token", Holds: "API token for the upstream issue tracker", Purpose: "authenticates API writes", Required: true},
		},
		ExampleYaml: "apiVersion: rampart.aspm.dev/v1alpha1\nkind: ClusterExternalTracker\nmetadata:\n  name: reference-tracker\nspec:\n  protocol: grpc\n  service: {name: external-tracker-svc, namespace: security-tools, port: 50051}\n  tls: {insecure: true}\n",
	}, nil
}

func (s *Server) Check(_ context.Context, req *trackerv1.CheckRequest) (*trackerv1.CheckResponse, error) {
	if strings.TrimSpace(req.GetTarget().GetSecrets()["token"]) == "" {
		return &trackerv1.CheckResponse{
			Ok: false,
			Error: &trackerv1.TrackerCallError{
				HttpStatus: 401,
				Fatal:      true,
				Code:       "missing_token",
				Message:    "secret 'token' is required",
			},
		}, nil
	}
	return &trackerv1.CheckResponse{
		Ok:             true,
		AccountId:      "rampart-bot",
		AcceptedFields: []string{"summary", "description", "labels", "priority"},
	}, nil
}

func (s *Server) CreateIssue(_ context.Context, req *trackerv1.CreateIssueRequest) (*trackerv1.CreateIssueResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lbl := req.GetIssue().GetIdempotencyLabel()
	if existing, ok := s.byLbl[lbl]; ok && lbl != "" {
		return existing, nil
	}
	s.seq++
	proj := req.GetIssue().GetProject()
	if proj == "" {
		proj = "SEC"
	}
	key := fmt.Sprintf("%s-%d", proj, s.seq)
	res := &trackerv1.CreateIssueResponse{
		TicketId:  key,
		TicketUrl: "https://tracker.example.local/issues/" + key,
	}
	if lbl != "" {
		s.byLbl[lbl] = res
	}
	s.states[key] = "Open"
	return res, nil
}

func (s *Server) FindIssueByLabel(_ context.Context, req *trackerv1.FindIssueByLabelRequest) (*trackerv1.FindIssueByLabelResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.byLbl[req.GetLabel()]
	if !ok {
		return &trackerv1.FindIssueByLabelResponse{Found: false}, nil
	}
	return &trackerv1.FindIssueByLabelResponse{
		Found:     true,
		TicketId:  res.GetTicketId(),
		TicketUrl: res.GetTicketUrl(),
	}, nil
}

func (s *Server) Comment(_ context.Context, _ *trackerv1.CommentRequest) (*trackerv1.CommentResponse, error) {
	return &trackerv1.CommentResponse{}, nil
}

func (s *Server) Close(_ context.Context, req *trackerv1.CloseRequest) (*trackerv1.CloseResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[req.GetTicketRef()] = "Closed"
	return &trackerv1.CloseResponse{}, nil
}

func (s *Server) ParseWebhook(_ context.Context, req *trackerv1.ParseWebhookRequest) (*trackerv1.ParseWebhookResponse, error) {
	sig := strings.TrimSpace(req.GetHeaders()["x-tracker-signature"])
	mac := hmac.New(sha256.New, []byte(req.GetWebhookSecret()))
	mac.Write(req.GetBody())
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return &trackerv1.ParseWebhookResponse{Verified: false, RejectReason: "HMAC mismatch"}, nil
	}
	var payload struct {
		DeliveryID string `json:"deliveryId"`
		TicketID   string `json:"ticketId"`
		Actor      string `json:"actor"`
		Action     string `json:"action"`
		Resolution string `json:"resolution"`
	}
	if err := json.Unmarshal(req.GetBody(), &payload); err != nil {
		return &trackerv1.ParseWebhookResponse{Verified: true, EventAction: "ignored"}, nil
	}
	return &trackerv1.ParseWebhookResponse{
		Verified:    true,
		DeliveryId:  payload.DeliveryID,
		ExternalRef: payload.TicketID,
		ActorId:     payload.Actor,
		EventAction: payload.Action,
		Resolution:  payload.Resolution,
	}, nil
}

func main() {
	addr := ":50051"
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		addr = v
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	grpcSrv := grpc.NewServer()
	trackerv1.RegisterTrackerServiceServer(grpcSrv, NewServer())
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcSrv, hs)

	log.Printf("Rampart external tracker service listening on %s", addr)
	if err := grpcSrv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
