package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"rampart/internal/config/apply"
)

// Group and version of the Rampart custom resources.
const (
	Group   = "rampart.aspm.dev"
	Version = "v1alpha1"
)

var (
	gvkTenant      = schema.GroupVersionKind{Group: Group, Version: Version, Kind: "Tenant"}
	gvkApplication = schema.GroupVersionKind{Group: Group, Version: Version, Kind: "Application"}
	gvkScanSource  = schema.GroupVersionKind{Group: Group, Version: Version, Kind: "ScanSource"}
	gvkSLAPolicy   = schema.GroupVersionKind{Group: Group, Version: Version, Kind: "SLAPolicy"}
	// D62: risk policies and the cluster-wide defaults.
	gvkRiskPolicy        = schema.GroupVersionKind{Group: Group, Version: Version, Kind: "RiskPolicy"}
	gvkClusterRiskPolicy = schema.GroupVersionKind{Group: Group, Version: Version, Kind: "ClusterRiskPolicy"}
	gvkClusterSLAPolicy  = schema.GroupVersionKind{Group: Group, Version: Version, Kind: "ClusterSLAPolicy"}
)

// ManagerConfig configures the operator process (D1, D3, D6 operator.*).
type ManagerConfig struct {
	// REST is the cluster to reconcile: the in-cluster config or an explicit kubeconfig. The
	// caller never passes a developer's default kubeconfig (see targets.operatorRESTConfig).
	REST        *rest.Config
	Store       apply.ConfigStore
	SecretStore SecretMaterialStore // encrypts before storing (EncryptingSecretStore)
	Logger      *slog.Logger

	// LeaderElectionNamespace is where the Lease lives; empty disables leader election
	// (single process, or tests).
	LeaderElectionNamespace string

	// SkipNameValidation lets several managers run in one process (tests).
	SkipNameValidation bool

	// RetryInterval is how soon a resource that is not Ready is looked at again (default 30 s).
	RetryInterval time.Duration

	// SecretReaderClusterRole is bound in every tenant namespace so the operator can read the
	// Secrets that CRs reference, and nowhere else (D1). Empty skips the binding.
	SecretReaderClusterRole string
	ServiceAccountName      string
	ServiceAccountNamespace string
}

// NewManager builds a controller-runtime manager with the Rampart controllers.
func NewManager(cfg ManagerConfig) (manager.Manager, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	opts := manager.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"}, // the ops port already serves /metrics (D6)
		// Health is the ops port's job too.
		HealthProbeBindAddress:  "0",
		LeaderElection:          cfg.LeaderElectionNamespace != "",
		LeaderElectionID:        "rampart-operator." + Group,
		LeaderElectionNamespace: cfg.LeaderElectionNamespace,
		Logger:                  slogr(cfg.Logger),
	}
	if cfg.SkipNameValidation {
		skip := true
		opts.Controller.SkipNameValidation = &skip
	}
	mgr, err := ctrl.NewManager(cfg.REST, opts)
	if err != nil {
		return nil, fmt.Errorf("operator: creating manager: %w", err)
	}
	logger := cfg.Logger

	var secrets SecretProvider
	if cfg.SecretStore != nil {
		// The API reader is uncached: a cached Secret client would need list/watch on Secrets in
		// every namespace, which D1 forbids. GET by name in a tenant namespace is all we need.
		secrets = &apiSecretProvider{reader: mgr.GetAPIReader()}
	}
	op := NewOperator(cfg.Store, secrets, cfg.SecretStore, logger)
	k := &kube{c: mgr.GetClient(), reader: mgr.GetAPIReader(), cfg: cfg, logger: logger}

	tenants := &cr[TenantCR, TenantStatus]{k: k, gvk: gvkTenant, reconcile: func(ctx context.Context, c *TenantCR) (*TenantStatus, error) {
		st, err := op.ReconcileTenant(ctx, c)
		if err == nil && st.GetCondition("Ready") != nil && st.GetCondition("Ready").Status == "True" {
			if kerr := k.ensureTenantNamespaces(ctx, c); kerr != nil {
				st.SetCondition("Ready", "False", "NamespaceError", kerr.Error())
			}
		}
		return st, err
	}, status: func(c *TenantCR) *TenantStatus { return &c.Status }, finalize: op.FinalizeTenant}
	apps := &cr[ApplicationCR, ApplicationStatus]{k: k, gvk: gvkApplication, reconcile: func(ctx context.Context, c *ApplicationCR) (*ApplicationStatus, error) {
		return op.ReconcileApplication(ctx, c)
	}, status: func(c *ApplicationCR) *ApplicationStatus { return &c.Status }, finalize: op.FinalizeApplication}
	sources := &cr[ScanSourceCR, ScanSourceStatus]{k: k, gvk: gvkScanSource, reconcile: func(ctx context.Context, c *ScanSourceCR) (*ScanSourceStatus, error) {
		return op.ReconcileScanSource(ctx, c)
	}, status: func(c *ScanSourceCR) *ScanSourceStatus { return &c.Status }, finalize: op.FinalizeScanSource}

	slaPolicies := &cr[SLAPolicyCR, SLAPolicyStatus]{k: k, gvk: gvkSLAPolicy, reconcile: func(ctx context.Context, c *SLAPolicyCR) (*SLAPolicyStatus, error) {
		return op.ReconcileSLAPolicy(ctx, c)
	}, status: func(c *SLAPolicyCR) *SLAPolicyStatus { return &c.Status }, finalize: op.FinalizeSLAPolicy}

	policyCR := func(gvk schema.GroupVersionKind, r *PolicyReconciler) *cr[PolicyCR, PolicyStatus] {
		return &cr[PolicyCR, PolicyStatus]{k: k, gvk: gvk, reconcile: r.Reconcile, status: func(c *PolicyCR) *PolicyStatus { return &c.Status }, finalize: r.Finalize}
	}
	riskPolicies := policyCR(gvkRiskPolicy, NewRiskPolicyReconciler(cfg.Store))
	clusterRisk := policyCR(gvkClusterRiskPolicy, NewClusterRiskPolicyReconciler(cfg.Store))
	clusterSLA := policyCR(gvkClusterSLAPolicy, NewClusterSLAPolicyReconciler(cfg.Store))

	gen := builder.WithPredicates(predicate.GenerationChangedPredicate{}) // status writes do not retrigger
	// Cluster policies belong to no namespace and wait for no tenant.
	for name, c := range map[string]struct {
		gvk schema.GroupVersionKind
		r   reconcile.Reconciler
	}{"clusterriskpolicy": {gvkClusterRiskPolicy, clusterRisk}, "clusterslapolicy": {gvkClusterSLAPolicy, clusterSLA}} {
		if err := ctrl.NewControllerManagedBy(mgr).Named(name).For(newObj(c.gvk), gen).Complete(c.r); err != nil {
			return nil, err
		}
	}
	if err := ctrl.NewControllerManagedBy(mgr).Named("tenant").For(newObj(gvkTenant), gen).Complete(tenants); err != nil {
		return nil, err
	}
	// A Tenant appearing or changing its namespaces can make waiting Applications and ScanSources
	// ready, so it requeues the resources in the namespaces it lists (D17, D20).
	for name, c := range map[string]struct {
		gvk schema.GroupVersionKind
		r   reconcile.Reconciler
	}{"application": {gvkApplication, apps}, "scansource": {gvkScanSource, sources}, "slapolicy": {gvkSLAPolicy, slaPolicies}, "riskpolicy": {gvkRiskPolicy, riskPolicies}} {
		gvk := c.gvk
		if err := ctrl.NewControllerManagedBy(mgr).Named(name).For(newObj(gvk), gen).
			Watches(newObj(gvkTenant), handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
				return k.requestsInTenantNamespaces(ctx, gvk, o)
			})).Complete(c.r); err != nil {
			return nil, err
		}
	}
	return mgr, nil
}

// Run starts the manager and blocks until ctx ends.
func Run(ctx context.Context, cfg ManagerConfig) error {
	mgr, err := NewManager(cfg)
	if err != nil {
		return err
	}
	return mgr.Start(ctx)
}

func newObj(gvk schema.GroupVersionKind) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gvk)
	return u
}

// kube holds the Kubernetes-side helpers shared by the controllers.
type kube struct {
	c      client.Client
	reader client.Reader
	cfg    ManagerConfig
	logger *slog.Logger
}

func (k *kube) retryInterval() time.Duration {
	if k.cfg.RetryInterval > 0 {
		return k.cfg.RetryInterval
	}
	return 30 * time.Second
}

// requestsInTenantNamespaces maps a Tenant event to the resources of kind gvk in its namespaces.
func (k *kube) requestsInTenantNamespaces(ctx context.Context, gvk schema.GroupVersionKind, o client.Object) []reconcile.Request {
	u, ok := o.(*unstructured.Unstructured)
	if !ok {
		return nil
	}
	namespaces, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "namespaces")
	var out []reconcile.Request
	for _, ns := range namespaces {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(gvk.GroupVersion().WithKind(gvk.Kind + "List"))
		if err := k.reader.List(ctx, list, client.InNamespace(ns)); err != nil {
			k.logger.Warn("listing resources for a tenant event", "kind", gvk.Kind, "namespace", ns, "err", err)
			continue
		}
		for _, it := range list.Items {
			out = append(out, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: it.GetNamespace(), Name: it.GetName()}})
		}
	}
	return out
}

// ensureTenantNamespaces creates the namespaces a Tenant owns if they are missing, and binds the
// secret-reader ClusterRole to the operator inside each (D1, doc 04: "created if missing").
func (k *kube) ensureTenantNamespaces(ctx context.Context, t *TenantCR) error {
	for _, name := range t.Spec.Namespaces {
		ns := &corev1.Namespace{}
		if err := k.reader.Get(ctx, types.NamespacedName{Name: name}, ns); apierrors.IsNotFound(err) {
			ns = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
				"app.kubernetes.io/managed-by": "rampart-operator",
				"rampart.aspm.dev/tenant":      t.Metadata.Name, // informational; never trusted for binding (D20)
			}}}
			if err := k.c.Create(ctx, ns); err != nil && !apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("creating namespace %q: %w", name, err)
			}
		} else if err != nil {
			return fmt.Errorf("reading namespace %q: %w", name, err)
		}
		if k.cfg.SecretReaderClusterRole == "" || k.cfg.ServiceAccountName == "" {
			continue
		}
		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "rampart-secret-reader", Namespace: name,
				Labels: map[string]string{"app.kubernetes.io/managed-by": "rampart-operator"}},
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: k.cfg.SecretReaderClusterRole},
			Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: k.cfg.ServiceAccountName, Namespace: k.cfg.ServiceAccountNamespace}},
		}
		if err := k.c.Create(ctx, rb); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("binding the secret reader in %q: %w", name, err)
		}
	}
	return nil
}

// cr is a generic controller for one kind: read the object, reconcile it with the store, write the
// status back only when it changed (D21: status is throttled, no update loops).
type cr[T any, S any] struct {
	k         *kube
	gvk       schema.GroupVersionKind
	reconcile func(context.Context, *T) (*S, error)
	status    func(*T) *S
	// finalize runs when the resource is deleted. It returns done=false to keep the resource (and the status to
	// write, if any) and try again later. A kind without one has no finalizer.
	finalize func(context.Context, *T) (*S, bool, error)
}

func (r *cr[T, S]) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	u := newObj(r.gvk)
	if err := r.k.c.Get(ctx, req.NamespacedName, u); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}
	if u.GetDeletionTimestamp() != nil {
		return r.finalizeDeleted(ctx, u)
	}
	if r.finalize != nil && !controllerutil.ContainsFinalizer(u, Finalizer) {
		controllerutil.AddFinalizer(u, Finalizer)
		if err := r.k.c.Update(ctx, u); err != nil {
			return reconcile.Result{}, err
		}
	}
	var obj T
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &obj); err != nil {
		return reconcile.Result{}, fmt.Errorf("decoding %s %s: %w", r.gvk.Kind, req.NamespacedName, err)
	}
	if m := metaOf(&obj); m != nil {
		m.Generation = u.GetGeneration()
	}
	st, rerr := r.reconcile(ctx, &obj)
	if st == nil {
		return reconcile.Result{}, rerr
	}
	if err := r.writeStatus(ctx, u, st); err != nil {
		return reconcile.Result{}, err
	}
	if rerr != nil {
		return reconcile.Result{}, rerr // backoff
	}
	// A resource waiting for something outside the cluster (a Tenant, a Secret) is retried, so it
	// recovers without anyone touching it.
	if readyFalse(st) {
		return reconcile.Result{RequeueAfter: r.k.retryInterval()}, nil
	}
	return reconcile.Result{}, nil
}

// finalizeDeleted does the work a deletion needs (docs/16 D21, D49), then lets the resource go. The work can be
// repeated: if the operator stops halfway, the next pass does it again.
func (r *cr[T, S]) finalizeDeleted(ctx context.Context, u *unstructured.Unstructured) (reconcile.Result, error) {
	if r.finalize == nil || !controllerutil.ContainsFinalizer(u, Finalizer) {
		return reconcile.Result{}, nil
	}
	var obj T
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &obj); err != nil {
		return reconcile.Result{}, fmt.Errorf("decoding %s %s/%s: %w", r.gvk.Kind, u.GetNamespace(), u.GetName(), err)
	}
	if m := metaOf(&obj); m != nil {
		m.Generation = u.GetGeneration()
	}
	st, done, err := r.finalize(ctx, &obj)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !done {
		if st != nil {
			if err := r.writeStatus(ctx, u, st); err != nil {
				return reconcile.Result{}, err
			}
		}
		return reconcile.Result{RequeueAfter: r.k.retryInterval()}, nil
	}
	controllerutil.RemoveFinalizer(u, Finalizer)
	return reconcile.Result{}, client.IgnoreNotFound(r.k.c.Update(ctx, u))
}

func (r *cr[T, S]) writeStatus(ctx context.Context, u *unstructured.Unstructured, st *S) error {
	want, err := runtime.DefaultUnstructuredConverter.ToUnstructured(st)
	if err != nil {
		return err
	}
	have, _, _ := unstructured.NestedMap(u.Object, "status")
	if equalStatus(have, want) {
		return nil
	}
	u.Object["status"] = want
	return r.k.c.Status().Update(ctx, u)
}

func readyFalse[S any](st *S) bool {
	b, _ := json.Marshal(st)
	var m struct {
		Conditions []Condition `json:"conditions"`
	}
	_ = json.Unmarshal(b, &m)
	for _, c := range m.Conditions {
		if c.Type == "Ready" && c.Status != "True" {
			return true
		}
	}
	return false
}

// equalStatus compares two status maps ignoring condition transition times, which only move when a
// condition actually changes.
func equalStatus(a, b map[string]any) bool {
	return canonical(a) == canonical(b)
}

func canonical(m map[string]any) string {
	cp := runtime.DeepCopyJSON(map[string]any(m))
	if conds, ok := cp["conditions"].([]any); ok {
		for _, c := range conds {
			if cm, ok := c.(map[string]any); ok {
				delete(cm, "lastTransitionTime")
			}
		}
	}
	b, _ := json.Marshal(cp)
	return string(b)
}

func metaOf(obj any) *Metadata {
	switch v := obj.(type) {
	case *TenantCR:
		return &v.Metadata
	case *ApplicationCR:
		return &v.Metadata
	case *ScanSourceCR:
		return &v.Metadata
	case *SLAPolicyCR:
		return &v.Metadata
	}
	return nil
}

// apiSecretProvider reads Secrets straight from the API server (uncached).
type apiSecretProvider struct{ reader client.Reader }

func (p *apiSecretProvider) GetSecret(ctx context.Context, namespace, name, key string) ([]byte, error) {
	var s corev1.Secret
	if err := p.reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &s); err != nil {
		return nil, err
	}
	v, ok := s.Data[key]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s has no key %q", namespace, name, key)
	}
	return v, nil
}
