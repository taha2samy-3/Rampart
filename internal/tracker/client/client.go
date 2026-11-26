package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"rampart/internal/domain"
	trackerv1 "rampart/pkg/api/tracker/v1"
)

// MaxMessageBytes caps gRPC request and response payloads (matches internal/analyzer/client).
const MaxMessageBytes = 64 << 20

// DefaultTimeout bounds tracker RPC calls when the caller provides no deadline.
const DefaultTimeout = 30 * time.Second

// DialConfig holds connection parameters for dialing an external tracker microservice.
type DialConfig struct {
	Target      string
	Secure      bool
	CACertPEM   []byte
	BearerToken string
	Timeout     time.Duration
}

// Client communicates with an external ticketing microservice container over gRPC.
type Client struct {
	conn        *grpc.ClientConn
	client      trackerv1.TrackerServiceClient
	bearerToken string
	timeout     time.Duration
}

// Dial connects to an external tracker container using TLS (with optional custom CA) or plaintext in-cluster gRPC.
func Dial(cfg DialConfig) (*Client, error) {
	if strings.TrimSpace(cfg.Target) == "" {
		return nil, errors.New("tracker client: target address is empty")
	}
	creds := insecure.NewCredentials()
	if cfg.Secure {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if len(cfg.CACertPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CACertPEM) {
				return nil, errors.New("tracker client: invalid CA certificate PEM")
			}
			tlsCfg.RootCAs = pool
		}
		creds = credentials.NewTLS(tlsCfg)
	}
	conn, err := grpc.NewClient(strings.TrimSpace(cfg.Target),
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(MaxMessageBytes),
			grpc.MaxCallRecvMsgSize(MaxMessageBytes),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("tracker client: failed to dial %s: %w", cfg.Target, err)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		conn:        conn,
		client:      trackerv1.NewTrackerServiceClient(conn),
		bearerToken: strings.TrimSpace(cfg.BearerToken),
		timeout:     timeout,
	}, nil
}

// NewFromConn wraps an existing gRPC connection (primarily for in-memory bufconn testing).
func NewFromConn(conn *grpc.ClientConn) *Client {
	return &Client{
		conn:    conn,
		client:  trackerv1.NewTrackerServiceClient(conn),
		timeout: DefaultTimeout,
	}
}

// WithBearerToken attaches an authorization bearer token to outgoing RPC metadata.
func (c *Client) WithBearerToken(token string) *Client {
	c.bearerToken = strings.TrimSpace(token)
	return c
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) callCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	var cancel context.CancelFunc = func() {}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && c.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
	}
	if c.bearerToken != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.bearerToken)
	}
	return ctx, cancel
}

// MapError converts a structured TrackerCallError from a container response into a domain error.
// HTTP statuses map to *domain.TrackerError so IsFatalTrackerError handles 4xx vs 5xx consistently.
func MapError(ce *trackerv1.TrackerCallError) error {
	if ce == nil {
		return nil
	}
	msg := strings.TrimSpace(ce.GetMessage())
	if msg == "" {
		msg = "tracker container reported an error"
	}
	if ce.GetHttpStatus() > 0 {
		return &domain.TrackerError{Status: int(ce.GetHttpStatus()), Message: msg}
	}
	if ce.GetFatal() {
		return &domain.TrackerError{Status: 400, Message: msg}
	}
	return errors.New(msg)
}

// HealthCheck verifies container connectivity and serving status.
func (c *Client) HealthCheck(ctx context.Context) (bool, string, error) {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	resp, err := c.client.HealthCheck(cctx, &trackerv1.HealthCheckRequest{})
	if err != nil {
		return false, "", err
	}
	return resp.GetStatus() == trackerv1.HealthCheckResponse_SERVING, resp.GetMessage(), nil
}

// GetMetadata retrieves provider identity, capabilities, schema, and required secrets.
func (c *Client) GetMetadata(ctx context.Context) (*trackerv1.GetMetadataResponse, error) {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	return c.client.GetMetadata(cctx, &trackerv1.GetMetadataRequest{})
}

// Check verifies tenant credentials and configuration via the tracker container.
func (c *Client) Check(ctx context.Context, target *trackerv1.TargetContext) (*trackerv1.CheckResponse, error) {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	return c.client.Check(cctx, &trackerv1.CheckRequest{Target: target})
}

// CreateIssue creates an upstream ticket via the tracker container.
func (c *Client) CreateIssue(ctx context.Context, target *trackerv1.TargetContext, issue *trackerv1.IssuePayload) (*trackerv1.CreateIssueResponse, error) {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	return c.client.CreateIssue(cctx, &trackerv1.CreateIssueRequest{Target: target, Issue: issue})
}

// FindIssueByLabel searches for an existing ticket matching Rampart's idempotency label.
func (c *Client) FindIssueByLabel(ctx context.Context, target *trackerv1.TargetContext, label string) (*trackerv1.FindIssueByLabelResponse, error) {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	return c.client.FindIssueByLabel(cctx, &trackerv1.FindIssueByLabelRequest{Target: target, Label: label})
}

// Comment adds a comment to an upstream ticket.
func (c *Client) Comment(ctx context.Context, target *trackerv1.TargetContext, ticketRef, body string) (*trackerv1.CommentResponse, error) {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	return c.client.Comment(cctx, &trackerv1.CommentRequest{Target: target, TicketRef: ticketRef, Body: body})
}

// CloseIssue closes an upstream ticket.
func (c *Client) CloseIssue(ctx context.Context, target *trackerv1.TargetContext, ticketRef, reason string) (*trackerv1.CloseResponse, error) {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	return c.client.Close(cctx, &trackerv1.CloseRequest{Target: target, TicketRef: ticketRef, Reason: reason})
}

// ParseWebhook asks the tracker container to verify an inbound webhook signature and normalize its event.
func (c *Client) ParseWebhook(ctx context.Context, target *trackerv1.TargetContext, headers map[string]string, body []byte, secret string) (*trackerv1.ParseWebhookResponse, error) {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	return c.client.ParseWebhook(cctx, &trackerv1.ParseWebhookRequest{
		Target:        target,
		Headers:       headers,
		Body:          body,
		WebhookSecret: secret,
	})
}

// PollStates retrieves current upstream states for a batch of open ticket references.
func (c *Client) PollStates(ctx context.Context, target *trackerv1.TargetContext, refs []string) (*trackerv1.PollStatesResponse, error) {
	cctx, cancel := c.callCtx(ctx)
	defer cancel()
	return c.client.PollStates(cctx, &trackerv1.PollStatesRequest{
		Target:     target,
		TicketRefs: refs,
	})
}
