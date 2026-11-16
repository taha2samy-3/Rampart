package operator_test

import (
	"context"
	"encoding/json"
	"testing"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/operator"
)

// D94: a package installs as data, a plugin connector is checked against it, and its declared secrets are synced
// under their own names.
func TestIntegrationPackageAndPluginConnector(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	secrets := operator.NewMockSecretProvider()
	secStore := newMemorySecretStore()
	op := operator.NewOperator(store, secrets, secStore, nil)
	if _, err := op.ReconcileTenant(ctx, &operator.TenantCR{Metadata: operator.Metadata{Name: "acme"}, Spec: operator.TenantSpec{DisplayName: "Acme", Namespaces: []string{"acme-ns"}}}); err != nil {
		t.Fatal(err)
	}
	spec := map[string]any{}
	_ = json.Unmarshal([]byte(`{"kind":"notifier","runtime":"declarative","version":"1.0.0","secrets":[{"name":"webhookUrl"}],
		"egress":["chat.googleapis.com"],"send":{"request":{"url":"{{ secrets.webhookUrl }}","json":{"text":"{{ message.title }}"}}}}`), &spec)
	st, err := op.ReconcileIntegrationPackage(ctx, &operator.PolicyCR{Metadata: operator.Metadata{Name: "google-chat", Namespace: "acme-ns", Generation: 1}, Spec: spec})
	if err != nil || st.GetCondition("Ready").Status != "True" {
		t.Fatalf("package: %+v %v", st, err)
	}
	bad, _ := op.ReconcileIntegrationPackage(ctx, &operator.PolicyCR{Metadata: operator.Metadata{Name: "runs-code", Namespace: "acme-ns"}, Spec: map[string]any{"kind": "notifier", "runtime": "wasm", "version": "1.0.0", "egress": []any{"a.example"}}})
	if c := bad.GetCondition("Ready"); c.Status != "False" || c.Reason != "InvalidSpec" {
		t.Fatalf("a code runtime in a tenant namespace is refused: %+v", c)
	}

	conn := func(name, pkg string, secs map[string]domain.SecretKeyRef) *operator.ConnectorCR {
		return &operator.ConnectorCR{Metadata: operator.Metadata{Name: name, Namespace: "acme-ns", Generation: 1},
			Spec: domain.ConnectorSpec{Type: domain.ConnectorTypePlugin, Plugin: &domain.PluginConnectorConfig{Name: pkg, Secrets: secs}}}
	}
	secrets.Secrets["acme-ns/chat:url"] = []byte("https://chat.googleapis.com/v1/spaces/x")
	ok, err := op.ReconcileConnector(ctx, conn("chat-sec", "google-chat", map[string]domain.SecretKeyRef{"webhookUrl": {Name: "chat", Key: "url"}}))
	if err != nil || ok.GetCondition("Ready").Status != "True" || ok.GetCondition("Connected").Reason != "NotProbed" {
		t.Fatalf("plugin connector: %+v %v", ok.Conditions, err)
	}
	tn, _ := store.GetTenantByNamespace(ctx, "acme-ns")
	if b := secStore.secrets[tn.ID.String()+":connector:chat-sec:webhookUrl"]; string(b) != "https://chat.googleapis.com/v1/spaces/x" {
		t.Fatalf("the declared secret is synced under its name: %q", b)
	}
	for why, cr := range map[string]*operator.ConnectorCR{
		"UnknownIntegration": conn("a", "no-such", nil),
		"PackageInvalid":     conn("b", "runs-code", nil),
		"InvalidSpec":        conn("c", "google-chat", nil), // the declared secret is missing
	} {
		st, _ := op.ReconcileConnector(ctx, cr)
		if c := st.GetCondition("Ready"); c.Status != "False" || c.Reason != why {
			t.Errorf("%s: %+v", why, c)
		}
	}
}
