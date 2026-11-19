package client_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"rampart/internal/analyzer/client"
	"rampart/internal/domain"
	analyzerv1 "rampart/pkg/api/analyzer/v1"
)

// mockServer implements AnalyzerServiceServer for unit testing.
type mockServer struct {
	analyzerv1.UnimplementedAnalyzerServiceServer
}

func (s *mockServer) HealthCheck(ctx context.Context, req *analyzerv1.HealthCheckRequest) (*analyzerv1.HealthCheckResponse, error) {
	return &analyzerv1.HealthCheckResponse{
		Status:  analyzerv1.HealthCheckResponse_SERVING,
		Message: "ready",
	}, nil
}

func (s *mockServer) GetMetadata(ctx context.Context, req *analyzerv1.GetMetadataRequest) (*analyzerv1.GetMetadataResponse, error) {
	return &analyzerv1.GetMetadataResponse{
		Name:                "Mock Security Analyzer",
		Version:             "2.0.0",
		SupportedEcosystems: []string{"npm", "golang", "maven"},
	}, nil
}

func (s *mockServer) Analyze(ctx context.Context, req *analyzerv1.AnalyzeRequest) (*analyzerv1.AnalyzeResponse, error) {
	var findings []*analyzerv1.Finding

	for _, comp := range req.Components {
		if comp.Name == "lodash" && comp.Version == "4.17.20" {
			findings = append(findings, &analyzerv1.Finding{
				VulnerabilityId:      "CVE-2021-23337",
				Title:                "Command Injection in lodash",
				Severity:             "HIGH",
				CvssScore:            7.2,
				CvssVector:           "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
				Cwes:                 []int32{78},
				AffectedComponentRef: comp.Ref,
				FixedVersion:         "4.17.21",
				Description:          "Vulnerable to command injection",
			})
		}
	}

	return &analyzerv1.AnalyzeResponse{
		ScanId:   req.ScanId,
		Findings: findings,
	}, nil
}

func setupTestServer(t *testing.T) (*client.Client, func()) {
	t.Helper()
	bufferSize := 1024 * 1024
	lis := bufconn.Listen(bufferSize)

	srv := grpc.NewServer()
	analyzerv1.RegisterAnalyzerServiceServer(srv, &mockServer{})

	go func() {
		if err := srv.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			t.Logf("test grpc server error: %v", err)
		}
	}()

	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial bufnet: %v", err)
	}

	c := client.NewFromConn(conn)

	cleanup := func() {
		_ = c.Close()
		srv.GracefulStop()
		_ = lis.Close()
	}

	return c, cleanup
}

func TestExternalAnalyzer_HealthCheck(t *testing.T) {
	c, cleanup := setupTestServer(t)
	defer cleanup()

	ctx := context.Background()
	healthy, err := c.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("HealthCheck failed: %v", err)
	}
	if !healthy {
		t.Errorf("expected healthy = true, got false")
	}
}

func TestExternalAnalyzer_GetMetadata(t *testing.T) {
	c, cleanup := setupTestServer(t)
	defer cleanup()

	ctx := context.Background()
	meta, err := c.GetMetadata(ctx)
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}
	if meta.Name != "Mock Security Analyzer" || meta.Version != "2.0.0" {
		t.Errorf("unexpected metadata: %+v", meta)
	}
	if len(meta.SupportedEcosystems) != 3 {
		t.Errorf("expected 3 ecosystems, got %d", len(meta.SupportedEcosystems))
	}
}

func TestExternalAnalyzer_Analyze(t *testing.T) {
	c, cleanup := setupTestServer(t)
	defer cleanup()

	ctx := context.Background()
	components := []domain.SBOMComponent{
		{
			Ref:      "pkg:npm/lodash@4.17.20",
			Name:     "lodash",
			Version:  "4.17.20",
			Purl:     "pkg:npm/lodash@4.17.20",
			PurlBase: "pkg:npm/lodash",
			Direct:   true,
		},
		{
			Ref:      "pkg:npm/express@4.18.2",
			Name:     "express",
			Version:  "4.18.2",
			Purl:     "pkg:npm/express@4.18.2",
			PurlBase: "pkg:npm/express",
			Direct:   true,
		},
	}

	findings, err := c.Analyze(ctx, "scan-123", "asset-456", components, nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "CVE-2021-23337" {
		t.Errorf("expected RuleID CVE-2021-23337, got %s", f.RuleID)
	}
	if f.Severity != domain.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", f.Severity)
	}
	if len(f.CWEs) != 1 || f.CWEs[0] != 78 {
		t.Errorf("expected CWE 78, got %v", f.CWEs)
	}
	if f.Location.Package.Purl != "pkg:npm/lodash@4.17.20" {
		t.Errorf("expected affected PURL pkg:npm/lodash@4.17.20, got %s", f.Location.Package.Purl)
	}
	if f.Location.Package.FixedVersion != "4.17.21" {
		t.Errorf("expected FixedVersion 4.17.21, got %s", f.Location.Package.FixedVersion)
	}
}
