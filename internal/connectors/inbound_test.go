package connectors_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/workflow"
)

type mockWorkflowService struct {
	requests []domain.RiskAcceptanceRequest
}

func (m *mockWorkflowService) Request(_ context.Context, _ uuid.UUID, _ string, req domain.RiskAcceptanceRequest) (*workflow.Outcome, error) {
	m.requests = append(m.requests, req)
	return &workflow.Outcome{Acceptance: &domain.RiskAcceptance{ID: uuid.New(), Status: domain.AcceptancePending}}, nil
}

type fakeVerifier struct{ tickets map[string]bool } // "<finding>|<ref>"

func (f fakeVerifier) FindingHasTicket(_ context.Context, _, finding uuid.UUID, ref string) (bool, error) {
	return f.tickets[finding.String()+"|"+ref], nil
}

type fakeNotifier struct{ titles []string }

func (n *fakeNotifier) NotifyTenant(_ context.Context, _ uuid.UUID, title, _, _ string) error {
	n.titles = append(n.titles, title)
	return nil
}

type fakeSettings struct{ maxDays int }

func (f fakeSettings) GetTenantSettings(context.Context, uuid.UUID) (domain.TenantSettings, error) {
	return domain.TenantSettings{RiskAcceptanceMaxDays: f.maxDays}, nil
}

func sign(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// inboundHarness is a Jira connector (two-way) and a GitHub one, each with its own webhook secret, and a ticket
// that Rampart opened for one finding of each.
type inboundHarness struct {
	t         *testing.T
	tenant    uuid.UUID
	finding   uuid.UUID
	secret    []byte
	wf        *mockWorkflowService
	notifier  *fakeNotifier
	handler   *connectors.InboundWebhookHandler
	jiraURL   string
	githubURL string
}

func newInbound(t *testing.T, withSecret bool, maxDays int) *inboundHarness {
	t.Helper()
	h := &inboundHarness{t: t, tenant: uuid.New(), finding: uuid.New(), secret: []byte("webhook-secret-12345"), wf: &mockWorkflowService{}, notifier: &fakeNotifier{}}
	st := ingest.NewMemoryStore()
	jira := domain.Connector{Name: "jira-in", TenantID: h.tenant, Type: domain.ConnectorTypeJira, Spec: domain.ConnectorSpec{
		Type: domain.ConnectorTypeJira, Direction: domain.DirectionBidirectional,
		Jira: &domain.JiraConnectorConfig{URL: "https://acme.atlassian.net", DefaultProject: "SEC", TwoWaySync: true, AccountID: "rampart-bot",
			CredentialsSecretRef: domain.SecretKeyRef{Name: "api", Key: "apiToken"}},
	}}
	gh := domain.Connector{Name: "gh-in", TenantID: h.tenant, Type: domain.ConnectorTypeGitHub, Spec: domain.ConnectorSpec{
		Type: domain.ConnectorTypeGitHub, Direction: domain.DirectionBidirectional,
		GitHub: &domain.GitHubConnectorConfig{Owner: "acme", Repo: "shop", TwoWaySync: true, CredentialsSecretRef: domain.SecretKeyRef{Name: "api", Key: "token"}},
	}}
	if withSecret {
		jira.Spec.Jira.WebhookSecretRef = domain.SecretKeyRef{Name: "hook", Key: "secret"}
		gh.Spec.GitHub.WebhookSecretRef = domain.SecretKeyRef{Name: "hook", Key: "secret"}
	}
	_ = st.SaveConnector(context.Background(), h.tenant, jira)
	_ = st.SaveConnector(context.Background(), h.tenant, gh)

	secrets := &mockSecretResolver{secrets: map[string][]byte{
		// the API credentials are NOT the webhook secret, and are present to prove they are not used as one
		h.tenant.String() + ":connector:jira-in:apiToken":       []byte("the-jira-api-token"),
		h.tenant.String() + ":connector:jira-in:webhook:secret": h.secret,
		h.tenant.String() + ":connector:gh-in:webhook:secret":   h.secret,
	}}
	v := fakeVerifier{tickets: map[string]bool{h.finding.String() + "|SEC-77": true, h.finding.String() + "|#12": true}}
	h.handler = connectors.NewInboundWebhookHandler(st, h.wf, secrets).WithTicketVerifier(v).WithNotifier(h.notifier).WithSettings(fakeSettings{maxDays: maxDays})
	h.jiraURL = fmt.Sprintf("/api/v1/t/%s/connectors/jira-in/webhook", h.tenant)
	h.githubURL = fmt.Sprintf("/api/v1/t/%s/connectors/gh-in/webhook", h.tenant)
	return h
}

func (h *inboundHarness) jiraPayload(event, resolution, key, accountID string, labels []string, changed ...string) []byte {
	items := []map[string]string{}
	for _, c := range changed {
		items = append(items, map[string]string{"field": c})
	}
	body, _ := json.Marshal(map[string]any{
		"webhookEvent": event,
		"changelog":    map[string]any{"items": items},
		"issue": map[string]any{"key": key, "fields": map[string]any{
			"labels": labels, "resolution": map[string]string{"name": resolution}, "status": map[string]string{"name": "Closed"},
		}},
		"user": map[string]string{"displayName": "Bob", "accountId": accountID},
	})
	return body
}

func (h *inboundHarness) send(path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, req)
	return w
}

func (h *inboundHarness) jira(body []byte, delivery string) *httptest.ResponseRecorder {
	return h.send(h.jiraURL, body, map[string]string{"X-Hub-Signature": "sha256=" + sign(h.secret, body), "X-Atlassian-Webhook-Identifier": delivery})
}

func (h *inboundHarness) label() []string {
	return []string{"security", connectors.FindingLabel(h.finding)}
}

func TestInbound_JiraSignedResolutionOnATicketRampartOpened_AsksForAnAcceptance(t *testing.T) {
	h := newInbound(t, true, 0)
	w := h.jira(h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "acc-1", h.label(), "resolution"), "d-1")
	if w.Code != http.StatusOK || len(h.wf.requests) != 1 {
		t.Fatalf("want one request, got %d requests, status %d: %s", len(h.wf.requests), w.Code, w.Body.String())
	}
	r := h.wf.requests[0]
	if r.FindingIDs[0] != h.finding || !r.ExpiresAt.After(time.Now().Add(80*24*time.Hour)) || r.ExpiresAt.After(time.Now().Add(91*24*time.Hour)) {
		t.Fatalf("a request for the finding, ending in about 90 days: %+v", r)
	}
	// The same delivery again is a duplicate.
	if dup := h.jira(h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "acc-1", h.label(), "resolution"), "d-1"); !strings.Contains(dup.Body.String(), "duplicate_delivery") || len(h.wf.requests) != 1 {
		t.Fatalf("duplicate: %s, requests %d", dup.Body.String(), len(h.wf.requests))
	}
}

func TestInbound_NoWebhookSecret_RefusesEverything(t *testing.T) {
	h := newInbound(t, false, 0) // the connector has no webhookSecretRef
	for name, headers := range map[string]map[string]string{"unsigned": nil, "signed with the API token": {"X-Hub-Signature": "sha256=" + sign([]byte("the-jira-api-token"), []byte(`{}`))}} {
		w := h.send(h.jiraURL, []byte(`{}`), headers)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: a connector with no webhook secret must refuse, got %d", name, w.Code)
		}
	}
	if len(h.wf.requests) != 0 {
		t.Fatal("nothing may be requested")
	}
}

func TestInbound_TheAPITokenIsNotTheWebhookSecret(t *testing.T) {
	h := newInbound(t, true, 0)
	body := h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "acc-1", h.label(), "resolution")
	w := h.send(h.jiraURL, body, map[string]string{"X-Hub-Signature": "sha256=" + sign([]byte("the-jira-api-token"), body)})
	if w.Code != http.StatusUnauthorized || len(h.wf.requests) != 0 {
		t.Fatalf("a delivery signed with the API credential must be refused: %d", w.Code)
	}
}

func TestInbound_BadOrMissingSignature_IsRefusedAndRemembersNothing(t *testing.T) {
	h := newInbound(t, true, 0)
	body := h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "acc-1", h.label(), "resolution")
	for name, headers := range map[string]map[string]string{
		"missing":      {"X-Atlassian-Webhook-Identifier": "d-9"},
		"wrong":        {"X-Hub-Signature": "sha256=deadbeef", "X-Atlassian-Webhook-Identifier": "d-9"},
		"no method":    {"X-Hub-Signature": sign(h.secret, body), "X-Atlassian-Webhook-Identifier": "d-9"},
		"other method": {"X-Hub-Signature": "md5=" + sign(h.secret, body), "X-Atlassian-Webhook-Identifier": "d-9"},
	} {
		if w := h.send(h.jiraURL, body, headers); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: want 401, got %d", name, w.Code)
		}
	}
	// The forged requests used the delivery id d-9. The real one must still go through: an unsigned request can
	// neither fill the duplicate cache nor make the genuine delivery look like a repeat.
	if w := h.jira(body, "d-9"); w.Code != http.StatusOK || len(h.wf.requests) != 1 {
		t.Fatalf("the genuine delivery was dropped: %d %s (requests %d)", w.Code, w.Body.String(), len(h.wf.requests))
	}
}

func TestInbound_ALabelOnSomeoneElsesTicket_ProvesNothing(t *testing.T) {
	h := newInbound(t, true, 0)
	// Another ticket, which Rampart did not open for this finding, carries the finding's label.
	w := h.jira(h.jiraPayload("jira:issue_updated", "Won't Do", "OTHER-1", "acc-1", h.label(), "resolution"), "d-2")
	if !strings.Contains(w.Body.String(), "ignored_unknown_ticket") || len(h.wf.requests) != 0 {
		t.Fatalf("a forged label must not open a request: %s", w.Body.String())
	}
	// And a ticket Rampart did open, but for another finding.
	other := uuid.New()
	w = h.jira(h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "acc-1", []string{connectors.FindingLabel(other)}, "resolution"), "d-3")
	if !strings.Contains(w.Body.String(), "ignored_unknown_ticket") || len(h.wf.requests) != 0 {
		t.Fatalf("a ticket for another finding must not decide this one: %s", w.Body.String())
	}
}

func TestInbound_OnlyAResolutionChangeDecides(t *testing.T) {
	h := newInbound(t, true, 0)
	cases := map[string][]byte{
		"a comment":                    h.jiraPayload("comment_created", "Won't Do", "SEC-77", "acc-1", h.label(), "resolution"),
		"a label edited when closed":   h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "acc-1", h.label(), "labels"),
		"Rampart's own account":        h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "rampart-bot", h.label(), "resolution"),
		"a resolution with no mapping": h.jiraPayload("jira:issue_updated", "Done", "SEC-77", "acc-1", h.label(), "resolution"),
	}
	i := 0
	for name, body := range cases {
		i++
		h.jira(body, fmt.Sprintf("d-%d", i))
		if len(h.wf.requests) != 0 {
			t.Fatalf("%s must not open a request", name)
		}
	}
}

func TestInbound_FalsePositive_AsksAPersonToLook_NotForAnAcceptance(t *testing.T) {
	h := newInbound(t, true, 0)
	w := h.jira(h.jiraPayload("jira:issue_updated", "False Positive", "SEC-77", "acc-1", h.label(), "resolution"), "d-4")
	if !strings.Contains(w.Body.String(), "review_requested") || len(h.wf.requests) != 0 || len(h.notifier.titles) != 1 {
		t.Fatalf("a false positive is not an acceptance that ends in 90 days: %s, requests %d, notifications %d", w.Body.String(), len(h.wf.requests), len(h.notifier.titles))
	}
}

func TestInbound_TheAcceptanceNeverRunsLongerThanTheTenantAllows(t *testing.T) {
	h := newInbound(t, true, 30)
	h.jira(h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "acc-1", h.label(), "resolution"), "d-5")
	if len(h.wf.requests) != 1 || h.wf.requests[0].ExpiresAt.After(time.Now().Add(31*24*time.Hour)) {
		t.Fatalf("a tenant that allows 30 days must not be given 90: %+v", h.wf.requests)
	}
}

func TestInbound_ABodyOverTheLimitIsRefused(t *testing.T) {
	h := newInbound(t, true, 0)
	body := bytes.Repeat([]byte("a"), connectors.MaxInboundBody+10)
	if w := h.send(h.jiraURL, body, nil); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", w.Code)
	}
}

func TestInbound_NoVerifier_ActsOnNothing(t *testing.T) {
	h := newInbound(t, true, 0)
	bare := connectors.NewInboundWebhookHandler(ingest.NewMemoryStore(), h.wf, nil)
	_ = bare
	// A handler without a ticket verifier must not act on a signed delivery.
	st := ingest.NewMemoryStore()
	conn := domain.Connector{Name: "jira-in", TenantID: h.tenant, Type: domain.ConnectorTypeJira, Spec: domain.ConnectorSpec{
		Type: domain.ConnectorTypeJira, Direction: domain.DirectionBidirectional,
		Jira: &domain.JiraConnectorConfig{URL: "https://acme.atlassian.net", DefaultProject: "SEC", TwoWaySync: true,
			WebhookSecretRef: domain.SecretKeyRef{Name: "hook", Key: "secret"}, CredentialsSecretRef: domain.SecretKeyRef{Name: "api"}},
	}}
	_ = st.SaveConnector(context.Background(), h.tenant, conn)
	secrets := &mockSecretResolver{secrets: map[string][]byte{h.tenant.String() + ":connector:jira-in:webhook:secret": h.secret}}
	handler := connectors.NewInboundWebhookHandler(st, h.wf, secrets) // no verifier
	body := h.jiraPayload("jira:issue_updated", "Won't Do", "SEC-77", "acc-1", h.label(), "resolution")
	req := httptest.NewRequest(http.MethodPost, h.jiraURL, bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature", "sha256="+sign(h.secret, body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if len(h.wf.requests) != 0 || !strings.Contains(w.Body.String(), "ignored_unknown_ticket") {
		t.Fatalf("without a verifier nothing is acted on: %s", w.Body.String())
	}
}

func TestInbound_GitHub(t *testing.T) {
	h := newInbound(t, true, 0)
	event := func(action, reason, repo string, number int) []byte {
		b, _ := json.Marshal(map[string]any{
			"action":     action,
			"issue":      map[string]any{"number": number, "state_reason": reason, "labels": []map[string]string{{"name": connectors.FindingLabel(h.finding)}}},
			"repository": map[string]string{"full_name": repo}, "sender": map[string]string{"login": "bob"},
		})
		return b
	}
	post := func(body []byte, sig string, delivery string) *httptest.ResponseRecorder {
		return h.send(h.githubURL, body, map[string]string{"X-Hub-Signature-256": sig, "X-GitHub-Delivery": delivery})
	}
	ok := event("closed", "not_planned", "Acme/Shop", 12)
	if w := post(ok, "sha256="+sign([]byte("not-the-secret"), ok), "g-1"); w.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong signature: %d", w.Code)
	}
	if w := post(ok, "sha256="+sign(h.secret, ok), "g-2"); w.Code != http.StatusOK || len(h.wf.requests) != 1 {
		t.Fatalf("closed as not planned on a ticket Rampart opened: %d %s", w.Code, w.Body.String())
	}
	if w := post(event("closed", "not_planned", "evil/repo", 12), "", "g-3"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned: %d", w.Code)
	}
	other := event("closed", "not_planned", "evil/repo", 12)
	post(other, "sha256="+sign(h.secret, other), "g-4")
	completed := event("closed", "completed", "acme/shop", 12)
	post(completed, "sha256="+sign(h.secret, completed), "g-5")
	unknown := event("closed", "not_planned", "acme/shop", 99)
	post(unknown, "sha256="+sign(h.secret, unknown), "g-6")
	if len(h.wf.requests) != 1 {
		t.Fatalf("another repository, a completed issue and a ticket Rampart did not open must not open requests: %d", len(h.wf.requests))
	}
}

func TestInbound_OutboundOnlyDirection_Rejected(t *testing.T) {
	tenantID := uuid.New()
	st := ingest.NewMemoryStore()
	_ = st.SaveConnector(context.Background(), tenantID, domain.Connector{Name: "slack-out", TenantID: tenantID, Type: domain.ConnectorTypeSlack, Spec: domain.ConnectorSpec{
		Type: domain.ConnectorTypeSlack, Direction: domain.DirectionOutbound,
		Slack: &domain.SlackConnectorConfig{TokenSecretRef: domain.SecretKeyRef{Name: "sec", Key: "token"}, DefaultChannel: "#general"},
	}})
	handler := connectors.NewInboundWebhookHandler(st, nil, nil)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/t/%s/connectors/slack-out/webhook", tenantID), strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("an outbound-only connector accepts no webhook: %d", w.Code)
	}
}

func TestInbound_WebhookRateLimitedPerAddress(t *testing.T) {
	st := ingest.NewMemoryStore()
	tenantID := domain.NewID()
	_ = st.SaveConnector(context.Background(), tenantID, domain.Connector{Name: "jira-hook", TenantID: tenantID, Type: domain.ConnectorTypeJira, Spec: domain.ConnectorSpec{
		Type: domain.ConnectorTypeJira, Direction: domain.DirectionBidirectional,
		Jira: &domain.JiraConnectorConfig{
			URL:              "https://acme.atlassian.net",
			DefaultProject:   "SEC",
			TwoWaySync:       true,
			WebhookSecretRef: domain.SecretKeyRef{Name: "sec", Key: "token"},
		},
	}})

	handler := connectors.NewInboundWebhookHandler(st, nil, nil).WithRateLimit(60) // 1 req/sec, burst 5

	url := fmt.Sprintf("/api/v1/t/%s/connectors/jira-hook/webhook", tenantID)

	// First 5 requests consume burst capacity
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(`{}`))
		req.RemoteAddr = "192.0.2.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d should not be rate limited", i)
		}
	}

	// 6th request immediately from the same client IP should be 429
	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(`{}`))
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests on webhook flood, got %d", w.Code)
	}

	// Another client address should still be allowed
	req2 := httptest.NewRequest(http.MethodPost, url, strings.NewReader(`{}`))
	req2.RemoteAddr = "198.51.100.2:54321"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code == http.StatusTooManyRequests {
		t.Fatalf("different client IP should not be rate limited by address 1")
	}
}

func TestInbound_JiraReopenedTicketCreatesNotification(t *testing.T) {
	h := newInbound(t, true, 30)
	body := fmt.Sprintf(`{
		"webhookEvent": "jira:issue_updated",
		"changelog": {"items": [{"field": "resolution"}]},
		"issue": {
			"key": "SEC-77",
			"fields": {
				"labels": ["%s"],
				"status": {"name": "In Progress"}
			}
		},
		"user": {"accountId": "engineer-1", "displayName": "Security Engineer"}
	}`, connectors.FindingLabel(h.finding))

	w := h.jira([]byte(body), "d-reopen-1")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(h.notifier.titles) != 1 || h.notifier.titles[0] != "Ticket reopened in Jira" {
		t.Fatalf("expected 'Ticket reopened in Jira' notification, got: %v", h.notifier.titles)
	}
}

func TestInbound_GitHubReopenedTicketCreatesNotification(t *testing.T) {
	h := newInbound(t, true, 30)
	body := fmt.Sprintf(`{
		"action": "reopened",
		"issue": {
			"number": 12,
			"labels": [{"name": "%s"}]
		},
		"repository": {"full_name": "acme/shop"},
		"sender": {"login": "octocat"}
	}`, connectors.FindingLabel(h.finding))

	sig := sign(h.secret, []byte(body))
	w := h.send(h.githubURL, []byte(body), map[string]string{"X-Hub-Signature-256": "sha256=" + sig, "X-GitHub-Delivery": "gh-reopen-1"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(h.notifier.titles) != 1 || h.notifier.titles[0] != "Ticket reopened in GitHub" {
		t.Fatalf("expected 'Ticket reopened in GitHub' notification, got: %v", h.notifier.titles)
	}
}

func TestInbound_NotAffectedCreatesWorkflowRequest(t *testing.T) {
	h := newInbound(t, true, 30)
	body := fmt.Sprintf(`{
		"webhookEvent": "jira:issue_updated",
		"changelog": {"items": [{"field": "resolution"}]},
		"issue": {
			"key": "SEC-77",
			"fields": {
				"labels": ["%s"],
				"resolution": {"name": "Not Affected"}
			}
		},
		"user": {"accountId": "engineer-1", "displayName": "Security Engineer"}
	}`, connectors.FindingLabel(h.finding))

	w := h.jira([]byte(body), "d-not-aff-1")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(h.wf.requests) != 1 {
		t.Fatalf("expected 1 workflow request, got %d", len(h.wf.requests))
	}
	if !strings.Contains(h.wf.requests[0].Justification, "VEX justification") {
		t.Errorf("justification should reference VEX justification: %s", h.wf.requests[0].Justification)
	}
}
