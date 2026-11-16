package query_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/ingest"
	"rampart/internal/query"
)

// D82: connectors are read, described and validated through the API, never created; no secret value is accepted.
func TestConnectorsAPI_ReadDescribeValidate(t *testing.T) {
	st := ingest.NewMemoryStore()
	authn := auth.NewAuthenticatorWithStore(st)
	tenantID := domain.NewID()
	tok := auth.FormatToken(tenantID, "viewer_token_for_connectors_api")
	authn.RegisterToken(tok, &auth.TokenRecord{ID: domain.NewID(), TenantID: tenantID, Subject: "reader", Role: auth.RoleViewer, CreatedAt: time.Now().UTC()})
	conn := domain.Connector{Name: "slack-appsec", Type: domain.ConnectorTypeSlack, Spec: domain.ConnectorSpec{Type: domain.ConnectorTypeSlack,
		Slack: &domain.SlackConnectorConfig{TokenSecretRef: domain.SecretKeyRef{Name: "slack", Key: "token"}, DefaultChannel: "#appsec"}}}
	conn.SetCondition("Connected", "True", "AuthOK", "Connector verified successfully")
	_ = st.SaveConnector(context.Background(), tenantID, conn)

	mux := http.NewServeMux()
	query.NewAPIWithAuth(st, enrich.NewFeedStore(), authn).RegisterRoutes(mux)
	call := func(method, path, body string) (int, map[string]any) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	code, list := call(http.MethodGet, "/api/v1/connectors", "")
	items, _ := list["items"].([]any)
	if code != http.StatusOK || len(items) != 1 {
		t.Fatalf("list: %d %v", code, list)
	}
	first := items[0].(map[string]any)
	if first["name"] != "slack-appsec" || first["managed_by"] != "resource" {
		t.Fatalf("list item: %v", first)
	}

	code, cat := call(http.MethodGet, "/api/v1/connectors/catalogue", "")
	if entries, _ := cat["items"].([]any); code != http.StatusOK || len(entries) != 8 {
		t.Fatalf("catalogue: %d %v", code, cat)
	}

	valid := domain.ConnectorCatalogue()[2].Example // Slack
	valid = strings.ReplaceAll(valid, "<tenant-namespace>", "ns")
	if code, out := call(http.MethodPost, "/api/v1/connectors/validate", valid); code != http.StatusOK || out["valid"] != true {
		t.Fatalf("a catalogue example must validate: %d %v", code, out)
	}
	wrapped, _ := json.Marshal(map[string]string{"resource": valid})
	if code, out := call(http.MethodPost, "/api/v1/connectors/validate", string(wrapped)); code != http.StatusOK || out["valid"] != true {
		t.Fatalf("the UI's JSON form must validate too: %d %v", code, out)
	}
	for name, body := range map[string]string{
		"missing channel":  "kind: Connector\nmetadata: {name: s}\nspec: {type: slack, slack: {tokenSecretRef: {name: x, key: token}}}",
		"private address":  "kind: Connector\nmetadata: {name: w}\nspec: {type: webhook, webhook: {url: http://10.0.0.5/hook}}",
		"a Secret first":   "kind: Secret\nmetadata: {name: s}\nstringData: {token: xoxb-secret}",
		"unsupported type": "kind: Connector\nmetadata: {name: g}\nspec: {type: gitlab}",
	} {
		if code, out := call(http.MethodPost, "/api/v1/connectors/validate", body); code != http.StatusOK || out["valid"] != false || out["error"] == "" {
			t.Errorf("%s: want valid=false with the reason, got %d %v", name, code, out)
		}
	}
	// Writing is not offered.
	if code, _ := call(http.MethodPost, "/api/v1/connectors", valid); code != http.StatusMethodNotAllowed && code != http.StatusNotFound {
		t.Errorf("POST /api/v1/connectors must not exist, got %d", code)
	}
}
