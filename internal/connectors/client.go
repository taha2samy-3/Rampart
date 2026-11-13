package connectors

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"syscall"
	"time"

	"rampart/internal/domain"
)

var (
	ErrSSRFDialBlocked  = errors.New("connectors: SSRF guard blocked connection to private or link-local address")
	ErrResponseTooLarge = errors.New("connectors: response body exceeded size limit")
)

const (
	DefaultTimeout         = 10 * time.Second
	MaxResponseBytes int64 = 2 * 1024 * 1024 // 2 MiB max response size per D69
	MaxRetries             = 4
	MaxRetryAfter          = 60 * time.Second // Cap Retry-After to 60 seconds
)

// SafeClient is the hardened outbound HTTP client enforcing SSRF guards, timeouts, and response limits (D69).
type SafeClient struct {
	httpClient *http.Client
}

// SafeClientConfig configures SafeClient options.
type SafeClientConfig struct {
	AllowLoopback bool
	Allowlist     *domain.PlatformSSRFAllowlist
}

// NewSafeClient creates a hardened HTTP client with dial-time SSRF verification (D69).
func NewSafeClient() *SafeClient {
	return NewSafeClientWithConfig(SafeClientConfig{})
}

// NewSafeClientWithConfig creates a SafeClient with specific settings (e.g., allow loopback for local tests).
func NewSafeClientWithConfig(cfg SafeClientConfig) *SafeClient {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			ip := net.ParseIP(host)
			if ip != nil {
				if cfg.AllowLoopback && (ip.IsLoopback() || host == "127.0.0.1" || host == "::1") {
					return nil
				}
				if cfg.Allowlist != nil && cfg.Allowlist.IsIPAllowed(ip) {
					return nil
				}
				if domain.IsBlockedIP(ip) {
					return fmt.Errorf("%w: IP %s is in blocked range", ErrSSRFDialBlocked, ip.String())
				}
			}
			return nil
		},
	}

	transport := &http.Transport{
		Proxy:                 nil, // No ambient proxy bypass
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   DefaultTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("stopped after 3 redirects (D69)")
			}
			// Security guard: Prevent forwarding credentials to different host on redirect
			if len(via) > 0 {
				initialReq := via[0]
				if initialReq.URL.Host != req.URL.Host {
					if initialReq.Header.Get("Authorization") != "" ||
						initialReq.Header.Get("X-Api-Key") != "" ||
						initialReq.Header.Get("X-Rampart-Signature-256") != "" {
						return errors.New("cross-host redirect blocked for authenticated request (D69 credential guard)")
					}
				}
			}
			// Verify redirect target URL scheme and host against SSRF
			if !cfg.AllowLoopback {
				if err := domain.ValidateConnectorURLWithAllowlist(req.URL.String(), cfg.Allowlist); err != nil {
					return fmt.Errorf("%w: redirect target blocked: %v", ErrSSRFDialBlocked, err)
				}
			}
			return nil
		},
	}

	return &SafeClient{httpClient: client}
}

// SanitizeURL removes sensitive query parameters and credentials from URLs for safe logging and error reporting.
func SanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[malformed url]"
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}

// SanitizeError unboxes *url.Error with errors.As to redact sensitive tokens/parameters in URLs (D69).
func SanitizeError(err error) error {
	if err == nil {
		return nil
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		sanitizedURL := SanitizeURL(urlErr.URL)
		return fmt.Errorf("%s %s: %w", urlErr.Op, sanitizedURL, urlErr.Err)
	}
	return err
}

func parseRetryAfter(headerVal string) (time.Duration, error) {
	if headerVal == "" {
		return 0, nil
	}
	// 1. Integer seconds format
	if s, err := strconv.Atoi(headerVal); err == nil && s >= 0 {
		return time.Duration(s) * time.Second, nil
	}
	// 2. HTTP-date format (RFC 1123, RFC 850, ANSIC)
	formats := []string{time.RFC1123, time.RFC850, time.ANSIC}
	for _, f := range formats {
		if t, err := time.Parse(f, headerVal); err == nil {
			d := time.Until(t)
			if d < 0 {
				d = 0
			}
			return d, nil
		}
	}
	return 0, fmt.Errorf("invalid Retry-After value %q", headerVal)
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Do executes an HTTP request with bounded response size and returns the read body.
func (c *SafeClient) Do(req *http.Request) ([]byte, int, http.Header, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	limitedReader := io.LimitReader(resp.Body, MaxResponseBytes+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, resp.StatusCode, resp.Header, err
	}
	if int64(len(body)) > MaxResponseBytes {
		return nil, resp.StatusCode, resp.Header, ErrResponseTooLarge
	}

	return body, resp.StatusCode, resp.Header, nil
}

// DoWithRetry executes an HTTP request with exponential backoff and Retry-After honouring (D69).
func (c *SafeClient) DoWithRetry(ctx context.Context, req *http.Request, idempotent bool) ([]byte, int, http.Header, error) {
	var lastErr error
	backoff := 500 * time.Millisecond

	maxAttempts := 1
	if idempotent {
		maxAttempts = MaxRetries
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, 0, nil, ctx.Err()
		default:
		}

		body, status, headers, err := c.Do(req.WithContext(ctx))
		if err == nil {
			// Success or client error not subject to retry
			if status < 500 && status != http.StatusTooManyRequests {
				return body, status, headers, nil
			}

			// Handle 429 Too Many Requests (Rate limit per D69)
			if status == http.StatusTooManyRequests {
				waitTime := backoff
				if ra := headers.Get("Retry-After"); ra != "" {
					parsedWait, parseErr := parseRetryAfter(ra)
					if parseErr == nil && parsedWait > 0 {
						if parsedWait > MaxRetryAfter {
							return body, status, headers, fmt.Errorf("server requested excessive Retry-After (%v), exceeding limit of %v", parsedWait, MaxRetryAfter)
						}
						waitTime = parsedWait
					}
				}
				// Add jitter
				jitter := time.Duration(rand.Intn(200)) * time.Millisecond
				waitTime += jitter

				if attempt < maxAttempts-1 {
					if err := sleepWithContext(ctx, waitTime); err != nil {
						return nil, status, headers, err
					}
					backoff *= 2
					continue
				}
				return body, status, headers, fmt.Errorf("rate limited (429) after %d attempts", attempt+1)
			}

			// 5xx server error on idempotent request
			if idempotent && attempt < maxAttempts-1 {
				jitter := time.Duration(rand.Intn(100)) * time.Millisecond
				if err := sleepWithContext(ctx, backoff+jitter); err != nil {
					return nil, status, headers, err
				}
				backoff *= 2
				continue
			}
			return body, status, headers, fmt.Errorf("server error (%d)", status)
		}

		// Dial or network error
		lastErr = err
		if errors.Is(err, ErrSSRFDialBlocked) {
			// Do not retry SSRF blocks
			return nil, 0, nil, err
		}

		if idempotent && attempt < maxAttempts-1 {
			jitter := time.Duration(rand.Intn(100)) * time.Millisecond
			if err := sleepWithContext(ctx, backoff+jitter); err != nil {
				return nil, 0, nil, err
			}
			backoff *= 2
			continue
		}
	}

	return nil, 0, nil, lastErr
}
