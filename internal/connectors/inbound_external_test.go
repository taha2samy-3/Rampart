package connectors_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	trackerclient "rampart/internal/tracker/client"
	trackerv1 "rampart/pkg/api/tracker/v1"
)

type externalVerifier struct {
	findingID uuid.UUID
	ref       string
}

func (v externalVerifier) FindingHasTicket(_ context.Context, _, finding uuid.UUID, ref string) (bool, error) {
	return finding == v.findingID && ref == v.ref, nil
}

func (v externalVerifier) FindFindingByTicketRef(_ context.Context, _ uuid.UUID, _, ref string) (uuid.UUID, bool, error) {
	if ref == v.ref {
		return v.findingID, true, nil
	}
	return uuid.Nil, false, nil
}

func TestInboundWebhook_ExternalTrackerDelegation(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()
	findingID := uuid.New()

	svc := &fakeTrackerService{}
	st := &storeWithTrackers{
		MemoryStore: ingest.NewMemoryStore(),
		trackers: []domain.StoredTrackerObject{
			{Origin: "cluster", Name: "jira-container", Spec: []byte(`{"service":{"name":"jira-svc","namespace":"tools","port":50051}}`)},
		},
	}

	conn := domain.Connector{
		ID:       uuid.New(),
		TenantID: tenantID,
		Name:     "jira-ext",
		Type:     domain.ConnectorTypeExternalTracker,
		Spec: domain.ConnectorSpec{
			Type: domain.ConnectorTypeExternalTracker,
			ExternalTracker: &domain.ExternalTrackerConnectorConfig{
				TrackerRef:       domain.ExternalTrackerRef{Scope: "cluster", Name: "jira-container"},
				AccountID:        "bot-acct",
				TwoWaySync:       true,
				WebhookSecretRef: domain.SecretKeyRef{Name: "wh-sec", Key: "webhook"},
				StatusMapping: domain.JiraStatusMapping{
					ResolutionToState: map[string]string{"Fixed": "risk_accepted"},
				},
			},
		},
	}
	_ = st.SaveConnector(ctx, tenantID, conn)

	secrets := &mockSecretResolver{
		secrets: map[string][]byte{
			tenantID.String() + ":" + conn.WebhookSecretStorageKey(): []byte("whsec"),
		},
	}
	wf := &mockWorkflowService{}
	handler := connectors.NewInboundWebhookHandler(st, wf, secrets).
		WithTicketVerifier(externalVerifier{findingID: findingID, ref: "SEC-101"}).
		WithTrackerStore(st).
		WithTrackerDialer(func(trackerclient.DialConfig) (*trackerclient.Client, error) {
			return startFakeTrackerClient(t, svc), nil
		})

	url := domain.InboundWebhookPath(conn)
	if url == "" {
		t.Fatal("expected non-empty webhook path for bidirectional externalTracker")
	}

	// 1. Valid webhook triggers risk acceptance request
	svc.webhookResponse = &trackerv1.ParseWebhookResponse{
		Verified:    true,
		DeliveryId:  "deliv-ext-1",
		ExternalRef: "SEC-101",
		ActorId:     "human-1",
		EventAction: "closed",
		Resolution:  "Fixed",
	}
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`{"ok":true}`)))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || len(wf.requests) != 1 || wf.requests[0].FindingIDs[0] != findingID {
		t.Fatalf("expected risk acceptance request from external webhook: code=%d body=%s reqs=%+v", w.Code, w.Body.String(), wf.requests)
	}

	// 2. Duplicate delivery is ignored cleanly
	reqDup := httptest.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`{"ok":true}`)))
	wDup := httptest.NewRecorder()
	handler.ServeHTTP(wDup, reqDup)
	if wDup.Code != http.StatusOK || len(wf.requests) != 1 {
		t.Fatalf("duplicate webhook must not trigger a second workflow request: code=%d len=%d", wDup.Code, len(wf.requests))
	}

	// 3. Unverified signature is refused with 401
	svc.webhookResponse = &trackerv1.ParseWebhookResponse{Verified: false, RejectReason: "bad hmac"}
	reqBad := httptest.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`{"ok":false}`)))
	wBad := httptest.NewRecorder()
	handler.ServeHTTP(wBad, reqBad)
	if wBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unverified webhook, got %d (%s)", wBad.Code, wBad.Body.String())
	}

	// 4. Own bot change does not trigger workflow loop
	svc.webhookResponse = &trackerv1.ParseWebhookResponse{
		Verified:    true,
		DeliveryId:  "deliv-ext-2",
		ExternalRef: "SEC-101",
		ActorId:     "bot-acct",
		EventAction: "closed",
		Resolution:  "Fixed",
	}
	reqOwn := httptest.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`{"ok":true}`)))
	wOwn := httptest.NewRecorder()
	handler.ServeHTTP(wOwn, reqOwn)
	if wOwn.Code != http.StatusOK || len(wf.requests) != 1 {
		t.Fatalf("own bot change must be ignored cleanly: code=%d len=%d", wOwn.Code, len(wf.requests))
	}
}
