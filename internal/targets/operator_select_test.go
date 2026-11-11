package targets

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"rampart/internal/config"
)

// D3 safety: on a developer machine the operator must never pick up ~/.kube/config or $KUBECONFIG.
// Starting `rampart -target=all` next to a kubeconfig that points at a production cluster must not
// start reconciling that cluster.
func TestOperatorIgnoresImplicitKubeconfigs(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".kube"), 0o700); err != nil {
		t.Fatal(err)
	}
	kc := `apiVersion: v1
kind: Config
current-context: prod
clusters: [{name: prod, cluster: {server: "https://prod.invalid"}}]
contexts: [{name: prod, context: {cluster: prod, user: u}}]
users: [{name: u, user: {token: x}}]
`
	for _, p := range []string{filepath.Join(home, ".kube", "config"), filepath.Join(home, "other")} {
		if err := os.WriteFile(p, []byte(kc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", filepath.Join(home, "other"))
	t.Setenv("KUBERNETES_SERVICE_HOST", "")

	cfg := config.DefaultConfig() // operator.mode = auto
	r := NewRunner(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if rc, _, err := r.operatorRESTConfig(); rc != nil || err != nil {
		t.Fatalf("auto mode must not use an implicit kubeconfig, got %v %v", rc, err)
	}

	// an explicit kubeconfig is honoured
	cfg.Operator.Kubeconfig = filepath.Join(home, "other")
	rc, src, err := r.operatorRESTConfig()
	if err != nil || rc == nil || rc.Host != "https://prod.invalid" || src == "" {
		t.Fatalf("explicit kubeconfig: %v %q %v", rc, src, err)
	}
}
