package connectors_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/connectors"
)

func newInboundTestHarness(t *testing.T) *inboundHarness {
	h := newInbound(t, true, 0)
	h.handler.WithRateLimit(100000)
	return h
}

// TestInbound_WebhookSecurity_EdgeCases tests signature validation, malformed headers,
// and body size limits.
func TestInbound_WebhookSecurity_EdgeCases(t *testing.T) {
	h := newInboundTestHarness(t)
	validPayload := h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "user-1", h.label(), "resolution")

	t.Run("missing signature header is rejected with 401", func(t *testing.T) {
		w := h.send(h.jiraURL, validPayload, map[string]string{
			"X-Atlassian-Webhook-Identifier": "d-no-sig",
		})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for missing signature, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("malformed signature header formats are rejected", func(t *testing.T) {
		badHeaders := []string{
			"invalid-signature-format",
			"sha256=",
			"sha256=xyz",  // non-hex
			"sha256=1234", // odd-length hex
			"sha1=abcdef", // wrong algorithm
			"Bearer token",
		}

		for _, badSig := range badHeaders {
			w := h.send(h.jiraURL, validPayload, map[string]string{
				"X-Hub-Signature":                badSig,
				"X-Atlassian-Webhook-Identifier": "d-bad-sig",
			})
			if w.Code != http.StatusUnauthorized {
				t.Errorf("expected 401 for signature %q, got %d", badSig, w.Code)
			}
		}
	})

	t.Run("tampered body fails signature validation", func(t *testing.T) {
		tampered := append([]byte(" "), validPayload...)
		w := h.send(h.jiraURL, tampered, map[string]string{
			"X-Hub-Signature":                "sha256=" + sign(h.secret, validPayload),
			"X-Atlassian-Webhook-Identifier": "d-tampered",
		})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for tampered payload, got %d", w.Code)
		}
	})

	t.Run("wrong secret fails signature validation", func(t *testing.T) {
		wrongSecret := []byte("wrong-secret-value-000000000000")
		w := h.send(h.jiraURL, validPayload, map[string]string{
			"X-Hub-Signature":                "sha256=" + sign(wrongSecret, validPayload),
			"X-Atlassian-Webhook-Identifier": "d-wrong-secret",
		})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for wrong secret, got %d", w.Code)
		}
	})

	t.Run("oversized webhook body (>1MB) is rejected", func(t *testing.T) {
		// 1.5MB of padding
		bigPayload := append(validPayload, bytes.Repeat([]byte(" "), 1500000)...)
		mac := hmac.New(sha256.New, h.secret)
		mac.Write(bigPayload)
		sig := hex.EncodeToString(mac.Sum(nil))

		w := h.send(h.jiraURL, bigPayload, map[string]string{
			"X-Hub-Signature":                "sha256=" + sig,
			"X-Atlassian-Webhook-Identifier": "d-big",
		})
		// Body reader must limit to 1MB and fail or reject
		if w.Code == http.StatusOK {
			t.Fatalf("expected oversized payload to be rejected or failed, got 200")
		}
	})
}

// TestInbound_DeliveryDeduplication_Concurrency tests concurrent deliveries with the same ID.
func TestInbound_DeliveryDeduplication_Concurrency(t *testing.T) {
	h := newInboundTestHarness(t)
	payload := h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "user-1", h.label(), "resolution")
	deliveryID := "concurrent-delivery-test-" + uuid.NewString()

	const concurrency = 10
	var wg sync.WaitGroup
	var successCount int32
	var duplicateCount int32

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := h.jira(payload, deliveryID)
			if w.Code == http.StatusOK {
				if strings.Contains(w.Body.String(), "duplicate_delivery") {
					atomic.AddInt32(&duplicateCount, 1)
				} else {
					atomic.AddInt32(&successCount, 1)
				}
			}
		}()
	}

	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 delivery to succeed, got %d (duplicates: %d)", successCount, duplicateCount)
	}
	if len(h.wf.requests) != 1 {
		t.Fatalf("expected exactly 1 workflow request, got %d", len(h.wf.requests))
	}
}

// TestInbound_JiraEventHandling_EdgeCases tests resolutions, bot filtering, and missing tickets.
func TestInbound_JiraEventHandling_EdgeCases(t *testing.T) {
	t.Run("resolution changed by Rampart bot itself is ignored", func(t *testing.T) {
		h := newInboundTestHarness(t)
		// AccountID matching "rampart-bot" configured in newInbound
		body := h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "rampart-bot", h.label(), "resolution")
		w := h.jira(body, "d-bot")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}
		if len(h.wf.requests) != 0 {
			t.Fatalf("expected 0 workflow requests when bot itself made change, got %d", len(h.wf.requests))
		}
	})

	t.Run("resolution to Fixed does not trigger risk acceptance request", func(t *testing.T) {
		h := newInboundTestHarness(t)
		body := h.jiraPayload("jira:issue_updated", "Fixed", "SEC-77", "user-1", h.label(), "resolution")
		w := h.jira(body, "d-fixed")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}
		if len(h.wf.requests) != 0 {
			t.Fatalf("expected 0 workflow requests for 'Fixed' resolution, got %d", len(h.wf.requests))
		}
	})

	t.Run("ticket without Rampart finding label is ignored", func(t *testing.T) {
		h := newInboundTestHarness(t)
		body := h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "user-1", []string{"unrelated-label"}, "resolution")
		w := h.jira(body, "d-unrelated")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}
		if len(h.wf.requests) != 0 {
			t.Fatalf("expected 0 workflow requests for ticket without finding label, got %d", len(h.wf.requests))
		}
	})

	t.Run("ticket that verifier rejects does not create acceptance", func(t *testing.T) {
		h := newInboundTestHarness(t)
		// Use SEC-999 which is not in fakeVerifier's map
		body := h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-999", "user-1", h.label(), "resolution")
		w := h.jira(body, "d-unverified")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}
		if len(h.wf.requests) != 0 {
			t.Fatalf("expected 0 workflow requests for unverified ticket, got %d", len(h.wf.requests))
		}
	})

	t.Run("unsupported webhook event is ignored gracefully", func(t *testing.T) {
		h := newInboundTestHarness(t)
		body := h.jiraPayload("jira:issue_deleted", "", "SEC-77", "user-1", h.label())
		w := h.jira(body, "d-delete")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for ignored event, got %d", w.Code)
		}
		if len(h.wf.requests) != 0 {
			t.Fatalf("expected 0 workflow requests for deleted event, got %d", len(h.wf.requests))
		}
	})
}

// TestInbound_GitHubEventHandling_EdgeCases tests GitHub webhook transitions.
func TestInbound_GitHubEventHandling_EdgeCases(t *testing.T) {
	h := newInboundTestHarness(t)

	ghPayload := func(action, stateReason, sender string) []byte {
		body, _ := json.Marshal(map[string]any{
			"action": action,
			"issue": map[string]any{
				"number":       12,
				"state":        "closed",
				"state_reason": stateReason,
				"labels": []map[string]string{
					{"name": connectors.FindingLabel(h.finding)},
				},
			},
			"repository": map[string]string{
				"full_name": "acme/shop",
			},
			"sender": map[string]string{
				"login": sender,
			},
		})
		return body
	}

	sendGH := func(body []byte, delivery string) *httptest.ResponseRecorder {
		return h.send(h.githubURL, body, map[string]string{
			"X-Hub-Signature-256": "sha256=" + sign(h.secret, body),
			"X-GitHub-Delivery":   delivery,
			"X-GitHub-Event":      "issues",
		})
	}

	t.Run("closed as completed does NOT trigger risk acceptance", func(t *testing.T) {
		body := ghPayload("closed", "completed", "alice")
		w := sendGH(body, "gh-d-completed")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}
		if len(h.wf.requests) != 0 {
			t.Fatalf("expected 0 workflow requests for completed issue, got %d", len(h.wf.requests))
		}
	})

	t.Run("closed as not_planned triggers risk acceptance", func(t *testing.T) {
		body := ghPayload("closed", "not_planned", "alice")
		w := sendGH(body, "gh-d-not-planned")
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Code)
		}
		if len(h.wf.requests) != 1 {
			t.Fatalf("expected 1 workflow request for not_planned, got %d", len(h.wf.requests))
		}
	})

	t.Run("unsupported action (opened, labeled) is ignored", func(t *testing.T) {
		for _, action := range []string{"opened", "labeled", "assigned", "edited"} {
			body := ghPayload(action, "", "alice")
			w := sendGH(body, "gh-d-"+action)
			if w.Code != http.StatusOK {
				t.Errorf("action %s: expected 200, got %d", action, w.Code)
			}
		}
	})
}
