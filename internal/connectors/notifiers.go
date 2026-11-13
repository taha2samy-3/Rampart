package connectors

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

var (
	ErrNotifierFailed = errors.New("notifiers: delivery failed")
)

// NotificationMessage represents a canonical message dispatched to notifiers (docs/19 message.v1.json).
type NotificationMessage struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenantId"`
	Title       string            `json:"title"`
	Summary     string            `json:"summary"`
	Severity    string            `json:"severity"` // "critical" | "high" | "medium" | "low" | "info"
	URL         string            `json:"url"`
	FindingID   string            `json:"findingId,omitempty"`
	AppName     string            `json:"appName,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	Fields      map[string]string `json:"fields,omitempty"`
	IsDigest    bool              `json:"isDigest,omitempty"`
	DigestCount int               `json:"digestCount,omitempty"`
}

// Notifier is the common dispatch interface for outbound notifications.
type Notifier interface {
	Send(ctx context.Context, msg NotificationMessage) error
}

// --- Slack Notifier ---

type SlackNotifier struct {
	client  *SafeClient
	token   string
	channel string
}

func NewSlackNotifier(client *SafeClient, token, channel string) *SlackNotifier {
	return &SlackNotifier{
		client:  client,
		token:   token,
		channel: channel,
	}
}

func escapeSlackMrkdwn(text string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
	)
	return r.Replace(text)
}

func (s *SlackNotifier) Send(ctx context.Context, msg NotificationMessage) error {
	apiURL := "https://slack.com/api/chat.postMessage"

	// Format Slack Block Kit message (up to 50 blocks)
	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type": "plain_text",
				"text": truncateString(msg.Title, 150),
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Severity:* `%s` | *Application:* %s\n%s",
					strings.ToUpper(msg.Severity),
					escapeSlackMrkdwn(msg.AppName),
					escapeSlackMrkdwn(truncateString(msg.Summary, 2800))),
			},
		},
	}

	if msg.URL != "" {
		if !strings.HasPrefix(msg.URL, "http://") && !strings.HasPrefix(msg.URL, "https://") {
			return fmt.Errorf("slack: action url %q is invalid (must be absolute http/https url)", msg.URL)
		}
		blocks = append(blocks, map[string]any{
			"type": "actions",
			"elements": []map[string]any{
				{
					"type": "button",
					"text": map[string]any{
						"type": "plain_text",
						"text": "View in Rampart",
					},
					"url":   msg.URL,
					"style": "primary",
				},
			},
		})
	}

	payload := map[string]any{
		"channel": s.channel,
		"text":    fmt.Sprintf("[%s] %s", msg.Severity, escapeSlackMrkdwn(msg.Title)),
		"blocks":  blocks,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	respBody, status, _, err := s.client.DoWithRetry(ctx, req, true)
	if err != nil {
		return fmt.Errorf("slack postMessage error: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("slack error: status %d", status)
	}

	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		TS    string `json:"ts"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("slack api error: %s", resp.Error)
	}
	return nil
}

// --- Teams Notifier ---

type TeamsNotifier struct {
	client     *SafeClient
	webhookURL string
}

func NewTeamsNotifier(client *SafeClient, webhookURL string) *TeamsNotifier {
	return &TeamsNotifier{
		client:     client,
		webhookURL: webhookURL,
	}
}

func (t *TeamsNotifier) Send(ctx context.Context, msg NotificationMessage) error {
	// Construct Adaptive Card payload (D69: Workflows webhook replacement)
	adaptiveCard := map[string]any{
		"type":    "AdaptiveCard",
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"version": "1.4",
		"body": []map[string]any{
			{
				"type":   "TextBlock",
				"size":   "Medium",
				"weight": "Bolder",
				"text":   msg.Title,
			},
			{
				"type": "FactSet",
				"facts": []map[string]string{
					{"title": "Severity", "value": strings.ToUpper(msg.Severity)},
					{"title": "Application", "value": msg.AppName},
				},
			},
			{
				"type": "TextBlock",
				"text": truncateString(msg.Summary, 2000),
				"wrap": true,
			},
		},
	}

	if msg.URL != "" {
		if !strings.HasPrefix(msg.URL, "http://") && !strings.HasPrefix(msg.URL, "https://") {
			return fmt.Errorf("teams: action url %q is invalid (must be absolute http/https url)", msg.URL)
		}
		adaptiveCard["actions"] = []map[string]any{
			{
				"type":  "Action.OpenUrl",
				"title": "Open in Rampart",
				"url":   msg.URL,
			},
		}
	}

	payload := map[string]any{
		"type": "message",
		"attachments": []map[string]any{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content":     adaptiveCard,
			},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Truncate if exceeds Microsoft 28 KB limit (D69)
	if len(bodyBytes) > 28*1024 {
		adaptiveCard["body"] = []map[string]any{
			{
				"type":   "TextBlock",
				"size":   "Medium",
				"weight": "Bolder",
				"text":   msg.Title,
			},
			{
				"type": "TextBlock",
				"text": "Notification truncated due to size. Please view in Rampart.",
				"wrap": true,
			},
		}
		bodyBytes, _ = json.Marshal(payload)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.webhookURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	sanitizedURL := SanitizeURL(t.webhookURL)
	_, status, _, err := t.client.DoWithRetry(ctx, req, true)
	if err != nil {
		return fmt.Errorf("teams webhook delivery error to %s: %v", sanitizedURL, sanitizeErrorURL(err, t.webhookURL))
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("teams webhook endpoint %s returned status %d", sanitizedURL, status)
	}
	return nil
}

// --- Signed Webhook Notifier ---

type WebhookNotifier struct {
	client  *SafeClient
	url     string
	secret  []byte
	format  string
	headers map[string]string
}

func NewWebhookNotifier(client *SafeClient, url string, secret []byte, format string, headers map[string]string) *WebhookNotifier {
	return &WebhookNotifier{
		client:  client,
		url:     url,
		secret:  secret,
		format:  format,
		headers: headers,
	}
}

func (w *WebhookNotifier) Send(ctx context.Context, msg NotificationMessage) error {
	var bodyBytes []byte
	var err error

	if w.format == "raw" {
		bodyBytes, err = json.Marshal(msg)
	} else {
		// CloudEvents v1.0 standard format
		cloudEvent := map[string]any{
			"specversion":     "1.0",
			"id":              msg.ID,
			"source":          "rampart/notifications",
			"type":            "dev.aspm.rampart.notification",
			"datacontenttype": "application/json",
			"time":            msg.Timestamp.Format(time.RFC3339),
			"data":            msg,
		}
		bodyBytes, err = json.Marshal(cloudEvent)
	}
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// Apply custom headers (validated)
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	// Compute HMAC-SHA256 signature with timestamp replay protection (D69)
	ts := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	req.Header.Set("X-Rampart-Timestamp", ts)

	if len(w.secret) > 0 {
		mac := hmac.New(sha256.New, w.secret)
		mac.Write([]byte(ts + "."))
		mac.Write(bodyBytes)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Rampart-Signature-256", "sha256="+sig)
	}

	sanitizedURL := SanitizeURL(w.url)
	_, status, _, err := w.client.DoWithRetry(ctx, req, true)
	if err != nil {
		return fmt.Errorf("webhook delivery to %s failed: %v", sanitizedURL, sanitizeErrorURL(err, w.url))
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("webhook endpoint %s returned status %d", sanitizedURL, status)
	}
	return nil
}

// --- Email Notifier ---

type EmailNotifier struct {
	smtpConfig domain.EmailSMTPConfig
	from       string
	to         []string
	auth       smtp.Auth
	allowlist  *domain.PlatformSSRFAllowlist
}

func NewEmailNotifier(cfg domain.EmailSMTPConfig, from string, to []string, username, password string) *EmailNotifier {
	return NewEmailNotifierWithAllowlist(cfg, from, to, username, password, nil)
}

func NewEmailNotifierWithAllowlist(cfg domain.EmailSMTPConfig, from string, to []string, username, password string, allowlist *domain.PlatformSSRFAllowlist) *EmailNotifier {
	var a smtp.Auth
	if username != "" && password != "" {
		a = smtp.PlainAuth("", username, password, cfg.Host)
	}
	return &EmailNotifier{
		smtpConfig: cfg,
		from:       from,
		to:         to,
		auth:       a,
		allowlist:  allowlist,
	}
}

func cleanEmailHeader(val string) string {
	val = strings.ReplaceAll(val, "\r", " ")
	val = strings.ReplaceAll(val, "\n", " ")
	return strings.TrimSpace(val)
}

func sanitizeErrorURL(err error, rawURL string) error {
	if err == nil {
		return nil
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return SanitizeError(err)
	}
	if rawURL != "" {
		sanitized := SanitizeURL(rawURL)
		errStr := strings.ReplaceAll(err.Error(), rawURL, sanitized)
		return errors.New(errStr)
	}
	return err
}

func (e *EmailNotifier) Send(ctx context.Context, msg NotificationMessage) error {
	cleanTitle := cleanEmailHeader(msg.Title)
	cleanApp := cleanEmailHeader(msg.AppName)
	rawSubject := fmt.Sprintf("[%s] %s - %s", strings.ToUpper(msg.Severity), cleanApp, cleanTitle)
	encodedSubject := mime.QEncoding.Encode("utf-8", rawSubject)

	cleanFrom := cleanEmailHeader(e.from)
	cleanToList := make([]string, 0, len(e.to))
	for _, recipient := range e.to {
		cleanToList = append(cleanToList, cleanEmailHeader(recipient))
	}
	cleanTo := strings.Join(cleanToList, ", ")

	cleanSummary := truncateString(msg.Summary, 16384)
	if len([]rune(msg.Summary)) > 16384 {
		cleanSummary += "\n[Summary truncated due to size limit]"
	}

	mimeHeader := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
		cleanFrom, cleanTo, encodedSubject)
	body := fmt.Sprintf("%s\n\nSeverity: %s\nApplication: %s\nLink: %s\n\n%s",
		msg.Title, strings.ToUpper(msg.Severity), msg.AppName, msg.URL, cleanSummary)

	msgBytes := []byte(mimeHeader + body)

	return sendSMTPGuarded(ctx, e.smtpConfig.Host, e.smtpConfig.Port, e.smtpConfig.TLS, e.smtpConfig.TLSMode, e.auth, cleanFrom, cleanToList, msgBytes, e.allowlist)
}

func sendSMTPGuarded(ctx context.Context, host string, port int, useTLS bool, tlsMode domain.EmailTLSMode, auth smtp.Auth, from string, to []string, msg []byte, allowlist *domain.PlatformSSRFAllowlist) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	allowLoopback := allowlist != nil && allowlist.AllowLoopback

	// 1. Resolve host and check against SSRF
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("smtp: failed to resolve host %q: %w", host, err)
	}
	for _, ip := range ips {
		if domain.IsBlockedIPWithAllowlistAndHost(ip, host, allowlist, allowLoopback) {
			return fmt.Errorf("%w: smtp host %q resolves to blocked IP %s (D69)", domain.ErrSSRFBlocked, host, ip.String())
		}
	}

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			h, _, err := net.SplitHostPort(address)
			if err != nil {
				h = address
			}
			ip := net.ParseIP(h)
			if ip != nil && domain.IsBlockedIPWithAllowlistAndHost(ip, host, allowlist, allowLoopback) {
				return fmt.Errorf("%w: dial to blocked SMTP IP %s", domain.ErrSSRFBlocked, ip.String())
			}
			return nil
		},
	}

	isImplicitTLS := useTLS || tlsMode == domain.EmailTLSModeImplicit || port == 465
	var conn net.Conn
	if isImplicitTLS {
		tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp dial failed: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Apply session deadline to prevent hanging goroutines on slow/unresponsive SMTP servers
	sessionDeadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(sessionDeadline) {
		sessionDeadline = d
	}
	_ = conn.SetDeadline(sessionDeadline)

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp client init failed: %w", err)
	}
	defer func() { _ = client.Quit() }()

	if !isImplicitTLS {
		hasStartTLS, _ := client.Extension("STARTTLS")
		if tlsMode == domain.EmailTLSModeInsecure {
			// Insecure plaintext explicitly permitted
			if hasStartTLS {
				tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
				_ = client.StartTLS(tlsConfig)
			}
		} else {
			// Default: Mandatory STARTTLS
			if !hasStartTLS {
				return fmt.Errorf("smtp server %q does not support mandatory STARTTLS", host)
			}
			tlsConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("smtp starttls failed: %w", err)
			}
		}
	}

	if auth != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth failed: %w", err)
			}
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("smtp mail from failed: %w", err)
	}
	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("smtp rcpt to %q failed: %w", recipient, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data failed: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp write message failed: %w", err)
	}
	return w.Close()
}

func truncateString(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	if maxRunes <= 3 {
		return string(runes[:maxRunes])
	}
	return string(runes[:maxRunes-3]) + "..."
}

// NewNotificationMessage builds a standard NotificationMessage.
func NewNotificationMessage(tenantID, appName, title, summary, severity, url, findingID string) NotificationMessage {
	return NotificationMessage{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		AppName:   appName,
		Title:     title,
		Summary:   summary,
		Severity:  severity,
		URL:       url,
		FindingID: findingID,
		Timestamp: time.Now().UTC(),
	}
}
