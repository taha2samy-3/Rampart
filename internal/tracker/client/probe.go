package client

import (
	"context"
	"fmt"
	"time"

	trackerv1 "rampart/pkg/api/tracker/v1"
)

// ProbeResult captures what a non-mutating health and metadata check of a tracker container learned.
type ProbeResult struct {
	Serving          bool
	Message          string
	Provider         string
	DisplayName      string
	Version          string
	Description      string
	Capabilities     []string
	ConfigSchemaJSON string
	DeclaredSecrets  []*trackerv1.SecretDeclaration
	ExampleYAML      string
	Latency          time.Duration
}

// Probe calls HealthCheck and GetMetadata on an external tracker microservice without sending tenant secrets.
func Probe(ctx context.Context, cfg DialConfig) (ProbeResult, error) {
	var res ProbeResult
	c, err := Dial(cfg)
	if err != nil {
		return res, err
	}
	defer func() { _ = c.Close() }()

	return ProbeClient(ctx, c)
}

// ProbeClient executes HealthCheck + GetMetadata against an already opened Client.
func ProbeClient(ctx context.Context, c *Client) (ProbeResult, error) {
	var res ProbeResult
	started := time.Now()
	serving, msg, err := c.HealthCheck(ctx)
	res.Latency = time.Since(started)
	if err != nil {
		return res, err
	}
	res.Serving = serving
	res.Message = msg

	meta, err := c.GetMetadata(ctx)
	if err != nil {
		return res, fmt.Errorf("health check answered, but GetMetadata failed: %w", err)
	}
	res.Provider = meta.GetProvider()
	res.DisplayName = meta.GetDisplayName()
	res.Version = meta.GetVersion()
	res.Description = meta.GetDescription()
	res.Capabilities = meta.GetCapabilities()
	res.ConfigSchemaJSON = meta.GetConfigSchemaJson()
	res.DeclaredSecrets = meta.GetDeclaredSecrets()
	res.ExampleYAML = meta.GetExampleYaml()
	return res, nil
}
