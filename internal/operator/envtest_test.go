package operator_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"rampart/internal/config/apply"
	"rampart/internal/operator"
	"rampart/internal/secrets"
)

// These tests run the real controllers against a real kube-apiserver and etcd (envtest). They are
// skipped unless KUBEBUILDER_ASSETS points at the binaries:
//
//	KUBEBUILDER_ASSETS=$(setup-envtest use -p path) go test ./internal/operator
func startEnv(t *testing.T) (client.Client, *apply.MemoryConfigStore, *captureSecretStore) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set; skipping envtest")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "deploy", "crds")}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("starting envtest: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	store := apply.NewMemoryConfigStore()
	cap := &captureSecretStore{}
	cipher, _ := secrets.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	mgr, err := operator.NewManager(operator.ManagerConfig{
		REST: cfg, Store: store, SecretStore: &operator.EncryptingSecretStore{Inner: cap, Cipher: cipher},
		Logger:                  slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		SkipNameValidation:      true,
		RetryInterval:           time.Second,
		SecretReaderClusterRole: "rampart-tenant-secret-reader", ServiceAccountName: "rampart", ServiceAccountNamespace: "rampart-system",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = mgr.Start(ctx) }()

	c, err := client.New(cfg, client.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		t.Fatal(err)
	}
	return c, store, cap
}

func cr(kind, ns, name string, spec map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	u.SetGroupVersionKind(schema.GroupVersionKind{Group: operator.Group, Version: operator.Version, Kind: kind})
	u.SetName(name)
	if ns != "" {
		u.SetNamespace(ns)
	}
	return u
}

func ready(t *testing.T, c client.Client, obj *unstructured.Unstructured, wantReason string) map[string]any {
	t.Helper()
	var last map[string]any
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		cur := &unstructured.Unstructured{}
		cur.SetGroupVersionKind(obj.GroupVersionKind())
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(obj), cur); err == nil {
			conds, _, _ := unstructured.NestedSlice(cur.Object, "status", "conditions")
			for _, x := range conds {
				m := x.(map[string]any)
				last = m
				if m["type"] == "Ready" && m["reason"] == wantReason {
					st, _, _ := unstructured.NestedMap(cur.Object, "status")
					return st
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s %s never reached Ready reason %q; last condition: %v", obj.GetKind(), obj.GetName(), wantReason, last)
	return nil
}

// The Phase 0 exit criterion: applying an Application shows Ready=True.
func TestApplyingAnApplicationShowsReadyTrue(t *testing.T) {
	c, store, _ := startEnv(t)
	ctx := context.Background()

	tenant := cr("Tenant", "", "acme", map[string]any{"displayName": "Acme", "namespaces": []any{"team-payments"}})
	if err := c.Create(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	st := ready(t, c, tenant, "Reconciled")
	if st["tenantId"] == "" || st["tenantId"] == nil {
		t.Errorf("tenant status must carry the tenant id: %v", st)
	}

	// the operator created the namespace and bound the secret reader inside it (D1, doc 04)
	var ns corev1.Namespace
	if err := c.Get(ctx, types.NamespacedName{Name: "team-payments"}, &ns); err != nil {
		t.Fatalf("namespace was not created: %v", err)
	}
	var rb rbacv1.RoleBinding
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-payments", Name: "rampart-secret-reader"}, &rb); err != nil {
		t.Fatalf("secret-reader binding missing: %v", err)
	}
	if rb.RoleRef.Name != "rampart-tenant-secret-reader" || rb.RoleRef.Kind != "ClusterRole" {
		t.Errorf("binding must reference the secret-reader ClusterRole only: %+v", rb.RoleRef)
	}

	app := cr("Application", "team-payments", "checkout", map[string]any{"displayName": "Checkout", "businessCriticality": "critical", "internetFacing": true})
	if err := c.Create(ctx, app); err != nil {
		t.Fatal(err)
	}
	st = ready(t, c, app, "Reconciled")
	if st["applicationId"] == nil || st["observedGeneration"] == nil {
		t.Errorf("application status incomplete: %v", st)
	}
	tn, _ := store.GetTenantByNamespace(ctx, "team-payments")
	if tn == nil {
		t.Fatal("namespace ownership was not recorded (D20)")
	}
	if a, _ := store.GetApplicationBySlug(ctx, tn.ID, "checkout"); a == nil || a.BusinessCriticality != "critical" {
		t.Errorf("application not stored: %+v", a)
	}
}

// D17/D20: an Application in a namespace no Tenant lists is not ready; it recovers by itself when a
// Tenant lists the namespace, without anyone touching the Application.
func TestApplicationWaitsForItsTenantThenRecovers(t *testing.T) {
	c, _, _ := startEnv(t)
	ctx := context.Background()
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "late"}}); err != nil {
		t.Fatal(err)
	}
	app := cr("Application", "late", "svc", map[string]any{"displayName": "Svc"})
	if err := c.Create(ctx, app); err != nil {
		t.Fatal(err)
	}
	ready(t, c, app, "TenantNotFound")

	if err := c.Create(ctx, cr("Tenant", "", "late-tenant", map[string]any{"displayName": "Late", "namespaces": []any{"late"}})); err != nil {
		t.Fatal(err)
	}
	ready(t, c, app, "Reconciled")
}

// A namespace has one owner (D20): the second tenant is not ready and says why.
func TestSecondTenantCannotTakeANamespace(t *testing.T) {
	c, _, _ := startEnv(t)
	ctx := context.Background()
	a := cr("Tenant", "", "owner-a", map[string]any{"displayName": "A", "namespaces": []any{"shared"}})
	b := cr("Tenant", "", "owner-b", map[string]any{"displayName": "B", "namespaces": []any{"shared"}})
	if err := c.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	ready(t, c, a, "Reconciled")
	if err := c.Create(ctx, b); err != nil {
		t.Fatal(err)
	}
	ready(t, c, b, "NamespaceOwnedByOtherTenant")
}

// The Secret a ScanSource references is synced encrypted, and a missing Secret is a clear condition.
func TestScanSourceSyncsItsSecretEncrypted(t *testing.T) {
	c, _, cap := startEnv(t)
	ctx := context.Background()
	if err := c.Create(ctx, cr("Tenant", "", "sec", map[string]any{"displayName": "S", "namespaces": []any{"sec-ns"}})); err != nil {
		t.Fatal(err)
	}
	src := cr("ScanSource", "sec-ns", "github", map[string]any{"scannerFamily": "semgrep", "secretRef": map[string]any{"name": "gh", "key": "token"}})
	// the namespace is created by the Tenant reconcile; wait for it before creating objects in it
	for i := 0; i < 100; i++ {
		var ns corev1.Namespace
		if c.Get(ctx, types.NamespacedName{Name: "sec-ns"}, &ns) == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := c.Create(ctx, src); err != nil {
		t.Fatal(err)
	}
	ready(t, c, src, "SecretNotFound")

	if err := c.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "sec-ns", Name: "gh"}, Data: map[string][]byte{"token": []byte("ghp_supersecret")}}); err != nil {
		t.Fatal(err)
	}
	ready(t, c, src, "Reconciled") // recovered by the periodic retry, nobody touched the CR
	for _, v := range cap.saved {
		if string(v) == "ghp_supersecret" {
			t.Fatal("the Secret reached the store in plaintext")
		}
	}
	if len(cap.saved) == 0 {
		t.Fatal("the Secret was not synced")
	}
}
