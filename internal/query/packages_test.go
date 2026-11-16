package query_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/ingest"
	"rampart/internal/query"
)

// D94: the installed packages, what each may reach and needs, and which connectors use it.
func TestListIntegrationPackages(t *testing.T) {
	ctx := context.Background()
	st := ingest.NewMemoryStore()
	tenant := uuid.New()
	spec := `{"kind":"notifier","runtime":"declarative","version":"1.2.0","description":"Google Chat","secrets":[{"name":"webhookUrl"}],"egress":["chat.googleapis.com"],"send":{"request":{"url":"{{ secrets.webhookUrl }}"}}}`
	_ = st.SaveIntegrationPackage(ctx, domain.IntegrationPackageRecord{TenantID: tenant, Name: "google-chat", Kind: "notifier", Runtime: "declarative", Version: "1.2.0", Spec: []byte(spec)})
	_ = st.SaveIntegrationPackage(ctx, domain.IntegrationPackageRecord{TenantID: tenant, Name: "broken", Kind: "notifier", Runtime: "wasm", Spec: []byte(`{}`), Error: "runtime wasm is tier 2"})
	_ = st.SaveIntegrationPackage(ctx, domain.IntegrationPackageRecord{TenantID: uuid.New(), Name: "other-tenant", Spec: []byte(spec)})
	_ = st.SaveConnector(ctx, tenant, domain.Connector{TenantID: tenant, Name: "chat-sec", Type: domain.ConnectorTypePlugin, Spec: domain.ConnectorSpec{Type: domain.ConnectorTypePlugin, Plugin: &domain.PluginConnectorConfig{Name: "google-chat"}}})

	authn := auth.NewAuthenticatorWithStore(st)
	api := query.NewAPIWithAuth(st, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	req := httptest.NewRequest("GET", "/api/v1/integration-packages", nil)
	req.Header.Set("Authorization", "Bearer "+authn.DefaultAdminToken(tenant))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var out struct {
		Items []query.PackageItem `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 200 || len(out.Items) != 2 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if p := out.Items[1]; p.Name != "google-chat" || p.Egress[0] != "chat.googleapis.com" || p.Secrets[0] != "webhookUrl" || len(p.UsedBy) != 1 || p.UsedBy[0] != "chat-sec" {
		t.Fatalf("google-chat: %+v", p)
	}
	if out.Items[0].Error == "" {
		t.Fatal("a package that does not validate shows its error")
	}
}

// D98: GET /api/v1/parsers lists the tenant's parser packages after the built-ins, and only that tenant's.
func TestListParsersIncludesTenantPackages(t *testing.T) {
	ctx := context.Background()
	st := ingest.NewMemoryStore()
	tenant, other := uuid.New(), uuid.New()
	spec := `{"kind":"parser","runtime":"mapping","version":"1.0.0","family":"pip-audit","category":"sca",
	  "detect":{"probes":[{"jsonHasKeys":["dependencies"]}]},"input":{"format":"json","records":"$.dependencies[*].vulns[*]","parent":"dep"},
	  "map":{"ruleId":"rec.id","title":"rec.id"}}`
	_ = st.SaveIntegrationPackage(ctx, domain.IntegrationPackageRecord{TenantID: tenant, Name: "pip-audit", Kind: "parser", Runtime: "mapping", Version: "1.0.0", Spec: []byte(spec)})
	_ = st.SaveIntegrationPackage(ctx, domain.IntegrationPackageRecord{TenantID: other, Name: "other-tenants", Kind: "parser", Runtime: "mapping", Version: "1.0.0", Spec: []byte(spec)})

	authn := auth.NewAuthenticatorWithStore(st)
	api := query.NewAPIWithAuth(st, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	req := httptest.NewRequest("GET", "/api/v1/parsers", nil)
	req.Header.Set("Authorization", "Bearer "+authn.DefaultAdminToken(tenant))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var out struct {
		Parsers []struct {
			ID           string `json:"id"`
			SupportLevel string `json:"support_level"`
		} `json:"parsers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var mine, theirs bool
	for _, p := range out.Parsers {
		mine = mine || (p.ID == "mapping:pip-audit" && p.SupportLevel == "community")
		theirs = theirs || p.ID == "mapping:other-tenants"
	}
	if !mine || theirs {
		t.Fatalf("want this tenant's package and not the other's: %s", w.Body.String())
	}
}
