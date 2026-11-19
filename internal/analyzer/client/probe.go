package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	analyzerv1 "rampart/pkg/api/analyzer/v1"
)

// ProbeResult is what one test of an analyzer learned: whether it says it is serving, what it is, and how long it took to answer.
type ProbeResult struct {
	Serving    bool
	Message    string // the analyzer's own words about its health
	Name       string
	Version    string
	Ecosystems []string
	Latency    time.Duration
}

// Probe calls an analyzer's HealthCheck and GetMetadata, the two calls that carry no component and change nothing. The caller's context bounds it: an
// analyzer that does not answer before the deadline is an error, not a hang. secure dials with TLS (the system's roots); otherwise the connection is
// plaintext, as every call to an analyzer has been (docs/34 F29).
func Probe(ctx context.Context, target string, secure bool) (ProbeResult, error) {
	var res ProbeResult
	creds := grpc.WithTransportCredentials(insecure.NewCredentials())
	if secure {
		creds = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}))
	}
	conn, err := grpc.NewClient(target, creds)
	if err != nil {
		return res, fmt.Errorf("cannot dial %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()
	c := analyzerv1.NewAnalyzerServiceClient(conn)

	started := time.Now()
	h, err := c.HealthCheck(ctx, &analyzerv1.HealthCheckRequest{})
	res.Latency = time.Since(started)
	if err != nil {
		return res, err
	}
	res.Serving = h.GetStatus() == analyzerv1.HealthCheckResponse_SERVING
	res.Message = h.GetMessage()
	m, err := c.GetMetadata(ctx, &analyzerv1.GetMetadataRequest{})
	if err != nil {
		return res, fmt.Errorf("it answered the health check and then failed GetMetadata: %w", err)
	}
	res.Name, res.Version, res.Ecosystems = m.GetName(), m.GetVersion(), m.GetSupportedEcosystems()
	return res, nil
}
