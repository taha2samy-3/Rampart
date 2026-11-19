package client

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"rampart/internal/domain"
	analyzerv1 "rampart/pkg/api/analyzer/v1"
)

// Client communicates with external analyzer microservices over gRPC.
type Client struct {
	conn   *grpc.ClientConn
	client analyzerv1.AnalyzerServiceClient
}

// New connects to a target gRPC analyzer service.
func New(target string, _ time.Duration) (*Client, error) {
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial analyzer at %s: %w", target, err)
	}

	return &Client{
		conn:   conn,
		client: analyzerv1.NewAnalyzerServiceClient(conn),
	}, nil
}

// NewFromConn wraps an existing client connection (useful for in-memory testing).
func NewFromConn(conn *grpc.ClientConn) *Client {
	return &Client{
		conn:   conn,
		client: analyzerv1.NewAnalyzerServiceClient(conn),
	}
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// HealthCheck tests connectivity and serving status of the analyzer.
func (c *Client) HealthCheck(ctx context.Context) (bool, error) {
	resp, err := c.client.HealthCheck(ctx, &analyzerv1.HealthCheckRequest{})
	if err != nil {
		return false, err
	}
	return resp.Status == analyzerv1.HealthCheckResponse_SERVING, nil
}

// GetMetadata fetches scanner capabilities, version, and supported ecosystems.
func (c *Client) GetMetadata(ctx context.Context) (*analyzerv1.GetMetadataResponse, error) {
	return c.client.GetMetadata(ctx, &analyzerv1.GetMetadataRequest{})
}

// Analyze sends a list of components to the analyzer and maps returned findings into Rampart domain.RawFinding.
func (c *Client) Analyze(ctx context.Context, scanID, assetID string, components []domain.SBOMComponent, options map[string]string) ([]domain.RawFinding, error) {
	var protoComponents []*analyzerv1.Component
	for _, comp := range components {
		protoComponents = append(protoComponents, &analyzerv1.Component{
			Ref:      comp.Ref,
			Name:     comp.Name,
			Version:  comp.Version,
			Purl:     comp.Purl,
			PurlBase: comp.PurlBase,
			Licenses: comp.Licenses,
			IsDirect: comp.Direct,
		})
	}

	req := &analyzerv1.AnalyzeRequest{
		ScanId:     scanID,
		AssetId:    assetID,
		Components: protoComponents,
		Options:    options,
	}

	resp, err := c.client.Analyze(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("analyzer rpc Analyze failed: %w", err)
	}

	var findings []domain.RawFinding
	for _, f := range resp.Findings {
		var cwes []int
		for _, cw := range f.Cwes {
			cwes = append(cwes, int(cw))
		}

		finding := domain.RawFinding{
			RuleID:       f.VulnerabilityId,
			Title:        f.Title,
			ToolSeverity: f.Severity,
			Severity:     domain.ParseSeverity(f.Severity),
			CVSSVector:   f.CvssVector,
			CWEs:         cwes,
			VulnIDs:      []string{f.VulnerabilityId},
			Description:  f.Description,
			Category:     domain.CategorySCA,
			Location: domain.Location{
				Package: &domain.PackageLocation{
					Purl:         f.AffectedComponentRef,
					FixedVersion: f.FixedVersion,
				},
			},
		}
		findings = append(findings, finding)
	}

	return findings, nil
}
