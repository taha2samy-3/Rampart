package ratelimit

import (
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/config"
)

// Middleware enforces rate limits on /api/v1 and /ingest/v1 and quotas across replicas.
type Middleware struct {
	limiter        *Limiter
	store          QuotaStore
	authn          *auth.Authenticator
	apiRate        float64
	apiBurst       int
	quotaHourly    int64
	maxReportBytes int64
}

// NewMiddleware creates a new rate limit and quota middleware.
func NewMiddleware(cfg config.LimitsConfig, store QuotaStore, authn *auth.Authenticator) *Middleware {
	apiRate := float64(cfg.APIPerSecond)
	if apiRate <= 0 {
		apiRate = 50
	}
	quotaHourly := int64(cfg.IngestPerHour)
	if quotaHourly <= 0 {
		quotaHourly = 1000
	}
	maxReportBytes := cfg.ReportBytes
	if maxReportBytes <= 0 {
		maxReportBytes = 52428800 // 50 MiB
	}

	return &Middleware{
		limiter:        NewLimiter(apiRate, int(apiRate)),
		store:          store,
		authn:          authn,
		apiRate:        apiRate,
		apiBurst:       int(math.Max(10, apiRate)),
		quotaHourly:    quotaHourly,
		maxReportBytes: maxReportBytes,
	}
}

// Wrap returns an http.Handler that enforces rate limits and quotas.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Inbound connector webhooks have their own tighter per-address and per-connector limiter
		if strings.Contains(path, "/connectors/") && strings.HasSuffix(path, "/webhook") {
			next.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(path, "/api/v1") {
			if !m.handleAPIRateLimit(w, r) {
				return
			}
		} else if strings.HasPrefix(path, "/ingest/v1") {
			if !m.handleIngestRateLimitAndQuota(w, r) {
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) handleAPIRateLimit(w http.ResponseWriter, r *http.Request) bool {
	var user *auth.ContextUser
	if m.authn != nil {
		user, _ = m.authn.AuthenticateRequest(r)
	}

	key := "api:ip:" + ClientIP(r)
	rate := m.apiRate
	burst := m.apiBurst

	if user != nil && user.Subject != "" {
		key = "api:tok:" + user.TenantID.String() + ":" + user.Subject
		if user.RateLimit != nil && *user.RateLimit > 0 {
			rate = float64(*user.RateLimit)
			burst = int(math.Max(5, rate))
		}
	}

	allowed, retryAfter, limit, remaining := m.limiter.Allow(key, rate, burst)
	WriteRateLimitHeaders(w, limit, remaining, retryAfter)

	if !allowed {
		Problem429(
			w,
			"rate-limit-exceeded",
			"Too Many Requests",
			"API rate limit exceeded. Please retry after "+retryAfter.String()+".",
			retryAfter,
		)
		return false
	}
	return true
}

func (m *Middleware) handleIngestRateLimitAndQuota(w http.ResponseWriter, r *http.Request) bool {
	var user *auth.ContextUser
	if m.authn != nil {
		user, _ = m.authn.AuthenticateRequest(r)
	}

	// 1. In-memory token bucket rate limit on /ingest/v1
	key := "ingest:ip:" + ClientIP(r)
	rate := m.apiRate
	burst := m.apiBurst

	if user != nil && user.TenantID != uuid.Nil {
		key = "ingest:tenant:" + user.TenantID.String()
		if user.RateLimit != nil && *user.RateLimit > 0 {
			rate = float64(*user.RateLimit)
			burst = int(math.Max(5, rate))
		}
	}

	allowed, retryAfter, limit, remaining := m.limiter.Allow(key, rate, burst)
	WriteRateLimitHeaders(w, limit, remaining, retryAfter)

	if !allowed {
		Problem429(
			w,
			"rate-limit-exceeded",
			"Too Many Requests",
			"Ingest rate limit exceeded. Please retry after "+retryAfter.String()+".",
			retryAfter,
		)
		return false
	}

	// 2. Report upload quota enforcement across replicas on ingest mutations
	if r.Method == http.MethodPost && (strings.HasSuffix(r.URL.Path, "/reports") || strings.HasSuffix(r.URL.Path, "/uploads") || strings.HasSuffix(r.URL.Path, "/sbom")) {
		// Content-Length check against ReportBytes limit
		if r.ContentLength > m.maxReportBytes {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = w.Write([]byte(`{"type":"https://rampart.aspm.dev/problems/payload-too-large","title":"Report payload exceeds maximum allowed size","status":413}`))
			return false
		}

		if m.store != nil && user != nil && user.TenantID != uuid.Nil {
			quotaLimit := m.quotaHourly
			if user.Quota != nil && *user.Quota > 0 {
				quotaLimit = *user.Quota
			}

			allowedQuota, quotaRetryAfter, _, err := CheckAndIncrementQuota(
				r.Context(),
				m.store,
				user.TenantID,
				"ingest:uploads",
				time.Hour,
				quotaLimit,
				1,
				time.Now(),
			)
			if err != nil {
				// Internal error checking quota: allow request to proceed so quota storage failure doesn't block ingest
				return true
			}
			if !allowedQuota {
				Problem429(
					w,
					"quota-exceeded",
					"Quota Exceeded",
					"Hourly upload quota exceeded for tenant. Please retry after the next window start.",
					quotaRetryAfter,
				)
				return false
			}
		}
	}

	return true
}
