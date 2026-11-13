package ratelimit

import (
	"context"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Bucket represents a single token bucket state.
type bucket struct {
	tokens    float64
	lastCheck time.Time
	rate      float64
	capacity  float64
}

// Limiter manages an in-memory collection of token buckets keyed by arbitrary string.
type Limiter struct {
	mu          sync.Mutex
	buckets     map[string]*bucket
	defaultRate float64
	defaultCap  float64
	maxBuckets  int
	now         func() time.Time
}

// NewLimiter creates a token bucket limiter with default refill rate and burst capacity.
func NewLimiter(defaultRate float64, defaultBurst int) *Limiter {
	if defaultRate <= 0 {
		defaultRate = 50
	}
	if defaultBurst <= 0 {
		defaultBurst = int(defaultRate)
	}
	return &Limiter{
		buckets:     make(map[string]*bucket),
		defaultRate: defaultRate,
		defaultCap:  float64(defaultBurst),
		maxBuckets:  20000,
		now:         time.Now,
	}
}

// Allow reports whether a single event is allowed under key.
// If rate or burst are <= 0, the limiter's defaults are used.
func (l *Limiter) Allow(key string, rate float64, burst int) (bool, time.Duration, int, int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	r := rate
	if r <= 0 {
		r = l.defaultRate
	}
	cap := float64(burst)
	if cap <= 0 {
		cap = l.defaultCap
	}

	b, exists := l.buckets[key]
	if !exists {
		// New bucket starts full
		b = &bucket{
			tokens:    cap - 1, // consume 1 token immediately
			lastCheck: now,
			rate:      r,
			capacity:  cap,
		}
		l.buckets[key] = b
		if len(l.buckets) > l.maxBuckets {
			l.pruneLocked(now)
		}
		return true, 0, int(r), int(math.Max(0, cap-1))
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.lastCheck = now
	b.rate = r
	b.capacity = cap
	b.tokens = math.Min(cap, b.tokens+elapsed*r)

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		rem := int(math.Floor(b.tokens))
		return true, 0, int(r), rem
	}

	// Not allowed: calculate wait duration until 1 token is available
	missing := 1.0 - b.tokens
	waitSec := missing / r
	waitDur := time.Duration(math.Ceil(waitSec*1000)) * time.Millisecond
	if waitDur < time.Second {
		waitDur = time.Second // minimum Retry-After of 1s per RFC
	}

	return false, waitDur, int(r), 0
}

func (l *Limiter) pruneLocked(now time.Time) {
	for k, b := range l.buckets {
		// Prune buckets that have been full for more than 5 minutes
		if b.tokens >= b.capacity && now.Sub(b.lastCheck) > 5*time.Minute {
			delete(l.buckets, k)
		}
	}
	// If still too large, prune anything untouched for > 10m
	if len(l.buckets) > l.maxBuckets {
		for k, b := range l.buckets {
			if now.Sub(b.lastCheck) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
	}
}

// ClientIP extracts the client IP address from an HTTP request (ignoring spoofable headers unless behind trusted proxies).
func ClientIP(r *http.Request) string {
	// RemoteAddr is host:port
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// QuotaStore abstracts the persistence of replica-shared quotas.
type QuotaStore interface {
	IncrementQuota(ctx context.Context, tenantID uuid.UUID, key string, windowStart time.Time, amount int64) (int64, error)
	GetQuotaUsage(ctx context.Context, tenantID uuid.UUID, key string, windowStart time.Time) (int64, error)
}

// CheckAndIncrementQuota checks whether incrementing the quota by amount exceeds limit for the current window.
// Returns (allowed, retryAfter, currentUsed, err).
func CheckAndIncrementQuota(
	ctx context.Context,
	store QuotaStore,
	tenantID uuid.UUID,
	key string,
	window time.Duration,
	limit int64,
	amount int64,
	now time.Time,
) (bool, time.Duration, int64, error) {
	if limit <= 0 {
		return true, 0, 0, nil
	}
	windowStart := now.UTC().Truncate(window)
	used, err := store.IncrementQuota(ctx, tenantID, key, windowStart, amount)
	if err != nil {
		return false, 0, 0, err
	}

	if used > limit {
		// Window resets at windowStart + window
		nextWindow := windowStart.Add(window)
		retryAfter := nextWindow.Sub(now)
		if retryAfter <= 0 {
			retryAfter = time.Second
		}
		return false, retryAfter, used, nil
	}

	return true, 0, used, nil
}

// WriteRateLimitHeaders writes standard RateLimit-* and Retry-After headers.
func WriteRateLimitHeaders(w http.ResponseWriter, limit int, remaining int, retryAfter time.Duration) {
	if limit > 0 {
		w.Header().Set("RateLimit-Limit", strconv.Itoa(limit))
		w.Header().Set("RateLimit-Remaining", strconv.Itoa(remaining))
	}
	if retryAfter > 0 {
		sec := int(math.Ceil(retryAfter.Seconds()))
		if sec < 1 {
			sec = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(sec))
		w.Header().Set("RateLimit-Reset", strconv.Itoa(sec))
	}
}

// Problem429 writes RFC 9457 Problem Details for rate limiting or quota exhaustion.
func Problem429(w http.ResponseWriter, typ, title, detail string, retryAfter time.Duration) {
	WriteRateLimitHeaders(w, 0, 0, retryAfter)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusTooManyRequests)
	sec := int(math.Ceil(retryAfter.Seconds()))
	if sec < 1 {
		sec = 1
	}
	body := `{"type":"https://rampart.aspm.dev/problems/` + typ + `","title":"` + strings.ReplaceAll(title, `"`, `\"`) + `","status":429,"detail":"` + strings.ReplaceAll(detail, `"`, `\"`) + `","retry_after":` + strconv.Itoa(sec) + `}`
	_, _ = w.Write([]byte(body))
}
