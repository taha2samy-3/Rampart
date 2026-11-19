package client

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"

	analyzerv1 "rampart/pkg/api/analyzer/v1"
)

type probeServer struct {
	analyzerv1.UnimplementedAnalyzerServiceServer
	status  analyzerv1.HealthCheckResponse_ServingStatus
	delay   time.Duration
	metaErr bool
}

func (s *probeServer) HealthCheck(ctx context.Context, _ *analyzerv1.HealthCheckRequest) (*analyzerv1.HealthCheckResponse, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &analyzerv1.HealthCheckResponse{Status: s.status, Message: "ready; token ok"}, nil
}

func (s *probeServer) GetMetadata(context.Context, *analyzerv1.GetMetadataRequest) (*analyzerv1.GetMetadataResponse, error) {
	if s.metaErr {
		return nil, context.DeadlineExceeded
	}
	return &analyzerv1.GetMetadataResponse{Name: "Sonatype OSS Index", Version: "0.1.0", SupportedEcosystems: []string{"npm", "maven"}}, nil
}

func serve(t *testing.T, s *probeServer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	analyzerv1.RegisterAnalyzerServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func TestProbeReportsWhatTheAnalyzerSaysAndHowLongItTook(t *testing.T) {
	addr := serve(t, &probeServer{status: analyzerv1.HealthCheckResponse_SERVING, delay: 20 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := Probe(ctx, addr, false)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Serving || r.Name != "Sonatype OSS Index" || r.Version != "0.1.0" || len(r.Ecosystems) != 2 || r.Message != "ready; token ok" || r.Latency < 20*time.Millisecond {
		t.Fatalf("%+v", r)
	}
}

func TestProbeSaysNotServingWhenTheAnalyzerDoes(t *testing.T) {
	addr := serve(t, &probeServer{status: analyzerv1.HealthCheckResponse_NOT_SERVING})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := Probe(ctx, addr, false)
	if err != nil || r.Serving {
		t.Fatalf("an analyzer that answers NOT_SERVING is reachable and not serving: %+v %v", r, err)
	}
}

func TestProbeFailsWhenNothingAnswers(t *testing.T) {
	// nothing listens here
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := lis.Addr().String()
	_ = lis.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := Probe(ctx, addr, false); err == nil {
		t.Fatal("an address nobody listens on must be an error")
	}
	// an analyzer that is slower than the deadline
	slow := serve(t, &probeServer{status: analyzerv1.HealthCheckResponse_SERVING, delay: 2 * time.Second})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel2()
	if _, err := Probe(ctx2, slow, false); err == nil {
		t.Fatal("an analyzer slower than the deadline must be an error, not a hang")
	}
}

func TestProbeSaysWhenMetadataFailsAfterAGoodHealthCheck(t *testing.T) {
	addr := serve(t, &probeServer{status: analyzerv1.HealthCheckResponse_SERVING, metaErr: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := Probe(ctx, addr, false)
	if err == nil || !r.Serving {
		t.Fatalf("the health answer is kept and the failure named: %+v %v", r, err)
	}
}

func TestProbeWithTLSFailsAgainstAPlaintextAnalyzer(t *testing.T) {
	addr := serve(t, &probeServer{status: analyzerv1.HealthCheckResponse_SERVING})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := Probe(ctx, addr, true); err == nil {
		t.Fatal("asking for TLS from a plaintext analyzer must fail, not fall back")
	}
}
