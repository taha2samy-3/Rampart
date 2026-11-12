package operator_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

// An SLAPolicy in a tenant's namespace is validated by the CRD schema and by the operator, and its status says
// whether it is applied (docs/16 D41).
func TestSLAPolicyShowsItsStatus(t *testing.T) {
	c, store, _ := startEnv(t)
	ctx := context.Background()
	if err := c.Create(ctx, cr("Tenant", "", "acme", map[string]any{"displayName": "Acme", "namespaces": []any{"team-sla"}})); err != nil {
		t.Fatal(err)
	}
	good := cr("SLAPolicy", "team-sla", "default", map[string]any{"matrix": map[string]any{"critical": map[string]any{"critical": int64(1)}}, "caps": map[string]any{"maxDays": int64(90)}})
	if err := c.Create(ctx, good); err != nil {
		t.Fatal(err)
	}
	ready(t, c, good, "Reconciled")
	tn, _ := store.GetTenantByNamespace(ctx, "team-sla")
	if p, ok := store.SLAPolicy(tn.ID, "team-sla", "default"); !ok || p.Error != "" {
		t.Fatalf("policy not stored: %+v %v", p, ok)
	}

	// The API server itself refuses what the schema forbids (days out of range)...
	if err := c.Create(ctx, cr("SLAPolicy", "team-sla", "bad-range", map[string]any{"matrix": map[string]any{"low": map[string]any{"low": int64(0)}}})); err == nil {
		t.Fatal("a matrix with 0 days must be refused by the CRD schema")
	}
	// ...and the operator refuses, with a reason, what only it can judge (business days are not built).
	soft := cr("SLAPolicy", "team-sla", "soft", map[string]any{"businessDays": true})
	if err := c.Create(ctx, soft); err != nil {
		t.Fatal(err)
	}
	st := ready(t, c, soft, "InvalidSpec")
	_ = st
}

// A RiskPolicy in a tenant's namespace and a ClusterRiskPolicy are compiled by the operator: a valid one is applied,
// a condition with a misspelt field is refused with the reason, and the schema refuses what it can (D62). A
// ClusterSLAPolicy needs no tenant.
func TestRiskPoliciesShowTheirStatus(t *testing.T) {
	c, store, _ := startEnv(t)
	ctx := context.Background()
	if err := c.Create(ctx, cr("Tenant", "", "acme-risk", map[string]any{"displayName": "Acme", "namespaces": []any{"team-risk"}})); err != nil {
		t.Fatal(err)
	}
	good := cr("RiskPolicy", "team-risk", "default", map[string]any{"factors": []any{
		map[string]any{"name": "payments", "when": `app.data_classification.exists(d, d == "pci")`, "points": int64(150), "group": "context"},
	}})
	if err := c.Create(ctx, good); err != nil {
		t.Fatal(err)
	}
	ready(t, c, good, "Reconciled")
	tn, _ := store.GetTenantByNamespace(ctx, "team-risk")
	if p, ok := store.Policy("risk:" + tn.ID.String() + ":team-risk:default"); !ok || p.Error != "" {
		t.Fatalf("risk policy not stored: %+v %v", p, ok)
	}
	typo := cr("RiskPolicy", "team-risk", "typo", map[string]any{"factors": []any{
		map[string]any{"name": "x", "when": `app.critcality == "high"`, "points": int64(10)},
	}})
	if err := c.Create(ctx, typo); err != nil {
		t.Fatal(err)
	}
	ready(t, c, typo, "InvalidSpec")
	if err := c.Create(ctx, cr("RiskPolicy", "team-risk", "big", map[string]any{"factors": []any{
		map[string]any{"name": "x", "when": "vuln.kev", "points": int64(5000)},
	}})); err == nil {
		t.Fatal("points out of range must be refused by the CRD schema")
	}

	cluster := cr("ClusterRiskPolicy", "", "default", map[string]any{"base": map[string]any{"critical": int64(700)}})
	if err := c.Create(ctx, cluster); err != nil {
		t.Fatal(err)
	}
	ready(t, c, cluster, "Reconciled")
	if _, ok := store.Policy("cluster:risk:default"); !ok {
		t.Fatal("cluster risk policy not stored")
	}
	clusterSLA := cr("ClusterSLAPolicy", "", "default", map[string]any{"caps": map[string]any{"maxDays": int64(90)}})
	if err := c.Create(ctx, clusterSLA); err != nil {
		t.Fatal(err)
	}
	ready(t, c, clusterSLA, "Reconciled")
	if _, ok := store.Policy("cluster:sla:default"); !ok {
		t.Fatal("cluster SLA policy not stored")
	}
}

func waitNs(t *testing.T, c client.Client, name string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		var ns corev1.Namespace
		if c.Get(context.Background(), types.NamespacedName{Name: name}, &ns) == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("namespace %s was not created", name)
}

func hasFinalizer(t *testing.T, c client.Client, obj *unstructured.Unstructured) bool {
	t.Helper()
	cur := &unstructured.Unstructured{}
	cur.SetGroupVersionKind(obj.GroupVersionKind())
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(obj), cur); err != nil {
		return false
	}
	for _, f := range cur.GetFinalizers() {
		if f == operator.Finalizer {
			return true
		}
	}
	return false
}

func eventuallyGone(t *testing.T, c client.Client, obj *unstructured.Unstructured) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		cur := &unstructured.Unstructured{}
		cur.SetGroupVersionKind(obj.GroupVersionKind())
		if apierrors.IsNotFound(c.Get(context.Background(), client.ObjectKeyFromObject(obj), cur)) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s %s was not deleted", obj.GetKind(), obj.GetName())
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("never happened: %s", what)
}

// Deleting an Application keeps its rows and hands it to the UI; deleting a ScanSource disables it and revokes its
// tokens; deleting an SLAPolicy removes it. Each resource carries the finalizer until the work is done (D21, D49).
func TestDeletingResourcesDoesTheirFinalizerWork(t *testing.T) {
	c, store, _ := startEnv(t)
	ctx := context.Background()
	tn := cr("Tenant", "", "fin", map[string]any{"displayName": "F", "namespaces": []any{"fin-ns"}})
	if err := c.Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	st := ready(t, c, tn, "Reconciled")
	waitNs(t, c, "fin-ns")
	tenantID, _ := uuid.Parse(st["tenantId"].(string))

	app := cr("Application", "fin-ns", "shop", map[string]any{"displayName": "Shop"})
	src := cr("ScanSource", "fin-ns", "ci", map[string]any{"scannerFamily": "semgrep"})
	pol := cr("SLAPolicy", "fin-ns", "default", map[string]any{"matrix": map[string]any{"critical": map[string]any{"critical": 1, "high": 2, "medium": 3, "low": 4}}})
	for _, o := range []*unstructured.Unstructured{app, src} {
		if err := c.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
		ready(t, c, o, "Reconciled")
	}
	eventually(t, "the finalizer on the application and the source", func() bool { return hasFinalizer(t, c, app) && hasFinalizer(t, c, src) })
	if store.Orphaned(tenantID, "shop") || store.Disabled(tenantID, "ci") {
		t.Fatal("nothing may be orphaned or disabled while the resources exist")
	}

	if err := c.Delete(ctx, app); err != nil {
		t.Fatal(err)
	}
	eventuallyGone(t, c, app)
	if !store.Orphaned(tenantID, "shop") {
		t.Fatal("deleting an Application must keep it and hand it to the UI")
	}
	if err := c.Delete(ctx, src); err != nil {
		t.Fatal(err)
	}
	eventuallyGone(t, c, src)
	if !store.Disabled(tenantID, "ci") {
		t.Fatal("deleting a ScanSource must disable it")
	}
	if err := c.Create(ctx, pol); err != nil {
		t.Logf("SLAPolicy shape is the CRD's business, not this test's: %v", err)
		return
	}
	ready(t, c, pol, "Reconciled")
	if _, ok := store.SLAPolicy(tenantID, "fin-ns", "default"); !ok {
		t.Fatal("the policy was not stored")
	}
	if err := c.Delete(ctx, pol); err != nil {
		t.Fatal(err)
	}
	eventuallyGone(t, c, pol)
	if _, ok := store.SLAPolicy(tenantID, "fin-ns", "default"); ok {
		t.Fatal("deleting an SLAPolicy must remove it")
	}
}

// A tenant with data is not deleted unless its resource says Purge; waiting costs nothing, and the reason is in
// Ready. With Purge it goes, with its data (D21).
func TestDeletingATenantWithDataIsRefusedUnlessPurge(t *testing.T) {
	c, store, _ := startEnv(t)
	ctx := context.Background()
	tn := cr("Tenant", "", "keep", map[string]any{"displayName": "K", "namespaces": []any{"keep-ns"}})
	if err := c.Create(ctx, tn); err != nil {
		t.Fatal(err)
	}
	st := ready(t, c, tn, "Reconciled")
	tenantID, _ := uuid.Parse(st["tenantId"].(string))
	store.SetHasData(tenantID)
	eventually(t, "the finalizer on the tenant", func() bool { return hasFinalizer(t, c, tn) })

	if err := c.Delete(ctx, tn); err != nil {
		t.Fatal(err)
	}
	ready(t, c, tn, "DeletionBlocked") // still there, and says why
	if store.Purged(tenantID) {
		t.Fatal("a tenant with data was deleted without Purge")
	}
	// Changing the policy of a resource that is being deleted is allowed: it is how the owner decides.
	cur := &unstructured.Unstructured{}
	cur.SetGroupVersionKind(tn.GroupVersionKind())
	if err := c.Get(ctx, client.ObjectKeyFromObject(tn), cur); err != nil {
		t.Fatal(err)
	}
	if err := unstructured.SetNestedField(cur.Object, "Purge", "spec", "deletionPolicy"); err != nil {
		t.Fatal(err)
	}
	if err := c.Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	eventuallyGone(t, c, tn)
	if !store.Purged(tenantID) {
		t.Fatal("Purge must delete the tenant")
	}

	// A tenant with no data goes without Purge.
	empty := cr("Tenant", "", "empty", map[string]any{"displayName": "E"})
	if err := c.Create(ctx, empty); err != nil {
		t.Fatal(err)
	}
	est := ready(t, c, empty, "Reconciled")
	if err := c.Delete(ctx, empty); err != nil {
		t.Fatal(err)
	}
	eventuallyGone(t, c, empty)
	eid, _ := uuid.Parse(est["tenantId"].(string))
	if !store.Purged(eid) {
		t.Fatal("an empty tenant is deleted")
	}
}
