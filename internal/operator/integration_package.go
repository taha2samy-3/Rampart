package operator

import (
	"context"
	"encoding/json"
	"fmt"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/integrations/declarative"
)

// IntegrationPackageReconciler installs a tier-1 package in its tenant (docs/19 §6 and §7, docs/16 D94). A namespaced
// IntegrationPackage is data only: the operator validates it and stores it; nothing is pulled or executed. A package
// that does not validate is stored with its error, Ready=False, and never used.
type IntegrationPackageReconciler struct {
	store apply.ConfigStore
}

// NewIntegrationPackageReconciler returns the reconciler.
func NewIntegrationPackageReconciler(store apply.ConfigStore) *IntegrationPackageReconciler {
	return &IntegrationPackageReconciler{store: store}
}

func (r *IntegrationPackageReconciler) packages() (domain.IntegrationPackages, bool) {
	p, ok := r.store.(domain.IntegrationPackages)
	return p, ok
}

// Reconcile validates and stores the package.
func (r *IntegrationPackageReconciler) Reconcile(ctx context.Context, cr *PolicyCR) (*PolicyStatus, error) {
	status := &cr.Status
	tenant, err := r.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}
	if tenant == nil {
		status.SetCondition("Ready", "False", "TenantNotFound", fmt.Sprintf("no tenant lists namespace %q", cr.Metadata.Namespace))
		return status, nil
	}
	pkgs, ok := r.packages()
	if !ok {
		status.SetCondition("Ready", "False", "StorageError", "the store does not keep integration packages")
		return status, fmt.Errorf("store does not keep integration packages")
	}
	if cr.Spec == nil {
		cr.Spec = make(map[string]any)
	}
	if cr.Spec["kind"] == nil || cr.Spec["kind"] == "" {
		cr.Spec["kind"] = "parser"
	}
	if cr.Spec["runtime"] == nil || cr.Spec["runtime"] == "" {
		cr.Spec["runtime"] = "mapping"
	}
	raw, _ := json.Marshal(cr.Spec)
	rec := domain.IntegrationPackageRecord{TenantID: tenant.ID, Name: cr.Metadata.Name, Spec: raw, Generation: cr.Metadata.Generation}
	spec, perr := declarative.Parse(raw)
	if spec != nil {
		rec.Kind, rec.Runtime, rec.Version = spec.Kind, spec.Runtime, spec.Version
	} else {
		rec.Kind, _ = cr.Spec["kind"].(string)
		rec.Runtime, _ = cr.Spec["runtime"].(string)
		rec.Version, _ = cr.Spec["version"].(string)
	}
	if perr != nil {
		rec.Error = perr.Error()
	}
	if err := pkgs.SaveIntegrationPackage(ctx, rec); err != nil {
		status.SetCondition("Ready", "False", "StorageError", err.Error())
		return status, err
	}
	status.ObservedGeneration = cr.Metadata.Generation
	if perr != nil {
		status.SetCondition("Ready", "False", "InvalidSpec", perr.Error())
		return status, nil
	}
	status.SetCondition("Ready", "True", "Installed", fmt.Sprintf("%s %s %s installed", spec.Runtime, spec.Kind, spec.Version))
	return status, nil
}

// Finalize removes the package. Connectors that use it go Ready=False on their next reconcile.
func (r *IntegrationPackageReconciler) Finalize(ctx context.Context, cr *PolicyCR) (*PolicyStatus, bool, error) {
	tenant, err := r.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		return nil, false, err
	}
	pkgs, ok := r.packages()
	if tenant == nil || !ok {
		return nil, true, nil
	}
	return nil, true, pkgs.DeleteIntegrationPackage(ctx, tenant.ID, cr.Metadata.Name)
}
