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

// tighten returns the rate and burst for a caller whose token may carry its own rate. A token can only lower the
// platform rate, never raise it (D79, the "tighten, never loosen" rule of D22): whoever can create a token must not
// be able to lift their tenant above the platform's limit.
func (m *Middleware) tighten(tokenRate *int) (float64, int) {
	if tokenRate == nil || *tokenRate <= 0 || float64(*tokenRate) >= m.apiRate {
		return m.apiRate, m.apiBurst
	}
	rate := float64(*tokenRate)
	return rate, int(math.Min(float64(m.apiBurst), math.Max(5, rate)))
}

// Wrap returns an http.Handler that enforces rate limits and quotas.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Inbound webhooks live under /hooks (D78) with their own limiter; this middleware never sees them.
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
		rate, burst = m.tighten(user.RateLimit)
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
		rate, burst = m.tighten(user.RateLimit)
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
			// A token's own quota is counted on its own counter and may only be lower than the tenant's (D79);
			// the tenant's counter always applies, with the platform limit, so no token can raise it.
			counters := []struct {
				key   string
				limit int64
				who   string
			}{}
			if user.Quota != nil && *user.Quota > 0 && *user.Quota < m.quotaHourly && user.Subject != "" {
				counters = append(counters, struct {
					key   string
					limit int64
					who   string
				}{"ingest:uploads:token:" + user.Subject, *user.Quota, "token"})
			}
			counters = append(counters, struct {
				key   string
				limit int64
				who   string
			}{"ingest:uploads", m.quotaHourly, "tenant"})

			for _, c := range counters {
				allowedQuota, quotaRetryAfter, _, err := CheckAndIncrementQuota(r.Context(), m.store, user.TenantID, c.key, time.Hour, c.limit, 1, time.Now())
				if err != nil {
					// Quota storage failure does not block ingest (D73); the in-memory limiter above still applies.
					return true
				}
				if !allowedQuota {
					Problem429(w, "quota-exceeded", "Quota Exceeded",
						"Hourly upload quota exceeded for this "+c.who+". Please retry after the next window start.", quotaRetryAfter)
					return false
				}
			}
		}
	}

	return true
}
