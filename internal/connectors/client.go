package connectors

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
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
)

// SafeClient is the hardened outbound HTTP client enforcing SSRF guards, timeouts, and response limits (D69).
type SafeClient struct {
	httpClient *http.Client
}

// SafeClientConfig configures SafeClient options.
type SafeClientConfig struct {
	AllowLoopback bool
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
			// Verify redirect target URL scheme and host against SSRF
			if !cfg.AllowLoopback {
				if err := domain.ValidateConnectorURL(req.URL.String()); err != nil {
					return fmt.Errorf("%w: redirect target blocked: %v", ErrSSRFDialBlocked, err)
				}
			}
			return nil
		},
	}

	return &SafeClient{httpClient: client}
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
				retryAfterSec := 0
				if ra := headers.Get("Retry-After"); ra != "" {
					if s, parseErr := strconv.Atoi(ra); parseErr == nil && s > 0 {
						retryAfterSec = s
					}
				}

				waitTime := backoff
				if retryAfterSec > 0 {
					waitTime = time.Duration(retryAfterSec) * time.Second
				}
				// Add jitter
				jitter := time.Duration(rand.Intn(200)) * time.Millisecond
				waitTime += jitter

				if attempt < maxAttempts-1 {
					timer := time.NewTimer(waitTime)
					select {
					case <-ctx.Done():
						timer.Stop()
						return nil, status, headers, ctx.Err()
					case <-timer.C:
						backoff *= 2
						continue
					}
				}
				return body, status, headers, fmt.Errorf("rate limited (429) after %d attempts", attempt+1)
			}

			// 5xx server error on idempotent request
			if idempotent && attempt < maxAttempts-1 {
				jitter := time.Duration(rand.Intn(100)) * time.Millisecond
				time.Sleep(backoff + jitter)
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
			time.Sleep(backoff + jitter)
			backoff *= 2
			continue
		}
	}

	return nil, 0, nil, lastErr
}
