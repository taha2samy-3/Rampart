package connectors_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/connectors"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

// The acceptance test of docs/23 §6.8 (D94): a new notifier, described only as an IntegrationPackage, delivers a
// message with no Go code, CRD or UI change for that tool.
func TestPluginNotifierDeliversThroughThePackage(t *testing.T) {
	var got string
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	hookURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/v1/spaces/sec/messages"

	ctx := context.Background()
	st := ingest.NewMemoryStore()
	tenant := uuid.New()
	spec := `{"kind":"notifier","runtime":"declarative","version":"1.0.0","secrets":[{"name":"webhookUrl"}],"egress":["localhost"],
		"configSchema":{"type":"object","properties":{"prefix":{"type":"string"}}},
		"send":{"request":{"url":"{{ secrets.webhookUrl }}","json":{"text":"{{ config.prefix }} *{{ message.title }}* ({{ message.severity }})\n<{{ message.url }}|Open>"}},"expect":"status == 200"}}`
	if err := st.SaveIntegrationPackage(ctx, domain.IntegrationPackageRecord{TenantID: tenant, Name: "google-chat", Kind: "notifier", Runtime: "declarative", Version: "1.0.0", Spec: []byte(spec)}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveConnector(ctx, tenant, domain.Connector{TenantID: tenant, Name: "chat-sec", Type: domain.ConnectorTypePlugin, Spec: domain.ConnectorSpec{
		Type: domain.ConnectorTypePlugin, Plugin: &domain.PluginConnectorConfig{Name: "google-chat", Config: json.RawMessage(`{"prefix":"[rampart]"}`),
			Secrets: map[string]domain.SecretKeyRef{"webhookUrl": {Name: "chat", Key: "url"}}},
	}}); err != nil {
		t.Fatal(err)
	}
	resolver := &mockSecretResolver{secrets: map[string][]byte{tenant.String() + ":connector:chat-sec:webhookUrl": []byte(hookURL)}}
	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{AllowLoopback: true, Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true}})
	router := connectors.NewNotificationRouter(st, resolver, client)

	errs := router.RouteNotification(ctx, tenant, connectors.NewNotificationMessage(tenant.String(), "checkout", "Log4Shell in checkout", "1 critical", "critical", "https://rampart.example/f/1", "f-1"))
	if len(errs) > 0 || hits != 1 {
		t.Fatalf("delivered %d times, errors %v", hits, errs)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(got), &body); err != nil || !strings.HasPrefix(body["text"], "[rampart] *Log4Shell in checkout* (critical)") {
		t.Fatalf("body: %s", got)
	}

	// The same connector pointed at a host the package does not declare sends nothing.
	resolver.secrets[tenant.String()+":connector:chat-sec:webhookUrl"] = []byte("https://attacker.example/x")
	if errs := router.RouteNotification(ctx, tenant, connectors.NewNotificationMessage(tenant.String(), "a", "t", "s", "critical", "", "")); len(errs) == 0 || hits != 1 {
		t.Fatalf("an undeclared host must be refused: %v, %d", errs, hits)
	}
}
