package connectors

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"syscall"
	"time"

	"rampart/internal/domain"
)

// Checker verifies credentials and connectivity of a connector without side effects (docs/04, docs/20 Milestone 3.1).
type Checker interface {
	Check(ctx context.Context, conn domain.Connector, secret []byte) error
}

// DefaultChecker implements Checker using the SafeClient and SSRF allowlist.
type DefaultChecker struct {
	client       *SafeClient
	allowlist    *domain.PlatformSSRFAllowlist
	slackAuthURL string
}

// NewDefaultChecker creates a new DefaultChecker.
func NewDefaultChecker(client *SafeClient, allowlist *domain.PlatformSSRFAllowlist) *DefaultChecker {
	if client == nil {
		client = NewSafeClientWithConfig(SafeClientConfig{
			Allowlist:     allowlist,
			AllowLoopback: allowlist != nil && allowlist.AllowLoopback,
		})
	}
	return &DefaultChecker{
		client:       client,
		allowlist:    allowlist,
		slackAuthURL: "https://slack.com/api/auth.test",
	}
}

// SetSlackAuthURL overrides the Slack auth.test endpoint (primarily for testing).
func (c *DefaultChecker) SetSlackAuthURL(u string) {
	c.slackAuthURL = u
}

// Check probes the connector's target service to verify authentication and reachability.
func (c *DefaultChecker) Check(ctx context.Context, conn domain.Connector, secret []byte) error {
	switch conn.Type {
	case domain.ConnectorTypeSlack:
		return c.checkSlack(ctx, conn, secret)
	case domain.ConnectorTypeTeams:
		return c.checkTeams(ctx, conn, secret)
	case domain.ConnectorTypeEmail:
		return c.checkEmail(ctx, conn, secret)
	case domain.ConnectorTypeWebhook:
		return c.checkWebhook(ctx, conn, secret)
	case domain.ConnectorTypeJira:
		return c.checkJira(ctx, conn, secret)
	default:
		return fmt.Errorf("unsupported connector type for check: %s", conn.Type)
	}
}

// checkSlack calls auth.test to verify the bot token (https://docs.slack.dev/reference/methods/auth.test).
func (c *DefaultChecker) checkSlack(ctx context.Context, conn domain.Connector, secret []byte) error {
	token := strings.TrimSpace(string(secret))
	if token == "" {
		return errors.New("slack token is empty")
	}

	endpoint := c.slackAuthURL
	if endpoint == "" {
		endpoint = "https://slack.com/api/auth.test"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("building slack auth.test request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	body, _, _, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack auth.test network error: %w", err)
	}

	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("decoding slack auth.test response: %w", err)
	}
	if !result.OK {
		return fmt.Errorf("slack auth.test failed: %s", result.Error)
	}
	return nil
}

// checkTeams validates the Workflows webhook URL against SSRF policy and endpoint syntax.
func (c *DefaultChecker) checkTeams(ctx context.Context, conn domain.Connector, secret []byte) error {
	webhookURL := strings.TrimSpace(string(secret))
	if webhookURL == "" && conn.Spec.Teams != nil {
		// If secret is not resolved directly, URL might be loaded from secret material
		return errors.New("teams webhook URL secret is empty")
	}

	u, err := url.Parse(webhookURL)
	if err != nil {
		return fmt.Errorf("invalid teams webhook URL: %w", err)
	}

	// Validate scheme
	if u.Scheme != "https" {
		if c.allowlist == nil || !c.allowlist.AllowInternalHTTP {
			return errors.New("teams webhook URL must use https")
		}
	}

	// Validate host against SSRF policy
	allowLoopback := c.allowlist != nil && c.allowlist.AllowLoopback
	if !allowLoopback {
		if err := domain.ValidateConnectorURLWithAllowlist(webhookURL, c.allowlist); err != nil {
			return fmt.Errorf("teams webhook URL blocked by SSRF policy: %w", err)
		}
	}

	return nil
}

// checkEmail tests TCP connectivity and SMTP EHLO handshake under SSRF protection.
func (c *DefaultChecker) checkEmail(ctx context.Context, conn domain.Connector, secret []byte) error {
	if conn.Spec.Email == nil {
		return errors.New("email configuration is nil")
	}
	cfg := conn.Spec.Email.SMTP
	if cfg.Host == "" {
		return errors.New("smtp host is empty")
	}
	port := cfg.Port
	if port <= 0 {
		port = 587
	}

	allowLoopback := c.allowlist != nil && c.allowlist.AllowLoopback
	ips, err := net.LookupIP(cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp: failed to resolve host %q: %w", cfg.Host, err)
	}
	for _, ip := range ips {
		if domain.IsBlockedIPWithAllowlistAndHost(ip, cfg.Host, c.allowlist, allowLoopback) {
			return fmt.Errorf("%w: smtp host %q resolves to blocked IP %s (D69)", domain.ErrSSRFBlocked, cfg.Host, ip.String())
		}
	}

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, rc syscall.RawConn) error {
			h, _, err := net.SplitHostPort(address)
			if err != nil {
				h = address
			}
			if ip := net.ParseIP(h); ip != nil {
				if domain.IsAlwaysBlockedIP(ip, allowLoopback) {
					return fmt.Errorf("%w: IP %s is in forbidden range", ErrSSRFDialBlocked, ip.String())
				}
			}
			return nil
		},
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, port)
	isImplicitTLS := cfg.TLS || cfg.TLSMode == domain.EmailTLSModeImplicit || port == 465

	var netConn net.Conn
	if isImplicitTLS {
		tlsConfig := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
		netConn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		netConn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp dial failed: %w", err)
	}
	defer func() { _ = netConn.Close() }()

	_ = netConn.SetDeadline(time.Now().Add(5 * time.Second))
	client, err := smtp.NewClient(netConn, cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client handshake failed: %w", err)
	}
	defer func() { _ = client.Quit() }()

	// Verify EHLO and STARTTLS if mode is starttls
	if !isImplicitTLS && cfg.TLSMode != domain.EmailTLSModeInsecure {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("smtp server does not support mandatory STARTTLS")
		}
	}

	return nil
}

// checkWebhook validates destination URL against SSRF rules.
func (c *DefaultChecker) checkWebhook(ctx context.Context, conn domain.Connector, secret []byte) error {
	if conn.Spec.Webhook == nil || conn.Spec.Webhook.URL == "" {
		return errors.New("webhook url is empty")
	}
	allowLoopback := c.allowlist != nil && c.allowlist.AllowLoopback
	if !allowLoopback {
		if err := domain.ValidateConnectorURLWithAllowlist(conn.Spec.Webhook.URL, c.allowlist); err != nil {
			return fmt.Errorf("webhook url blocked by SSRF policy: %w", err)
		}
	}
	return nil
}

// checkJira validates Jira cloud URL syntax and SSRF policy.
func (c *DefaultChecker) checkJira(ctx context.Context, conn domain.Connector, secret []byte) error {
	if conn.Spec.Jira == nil || conn.Spec.Jira.URL == "" {
		return errors.New("jira url is empty")
	}
	allowLoopback := c.allowlist != nil && c.allowlist.AllowLoopback
	if !allowLoopback {
		if err := domain.ValidateConnectorURLWithAllowlist(conn.Spec.Jira.URL, c.allowlist); err != nil {
			return fmt.Errorf("jira url blocked by SSRF policy: %w", err)
		}
	}
	return nil
}
