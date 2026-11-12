package operator

import (
	"context"
	"fmt"
)

// Finalizer is the name the operator puts on the resources whose deletion has work to do (docs/16 D21, D49).
const Finalizer = "rampart.aspm.dev/finalizer"

// Deletion policies of a Tenant.
const (
	TenantRetain = "Retain" // the default: refuse to delete a tenant that has data
	TenantPurge  = "Purge"  // delete the tenant with everything that belongs to it
)

// FinalizeApplication keeps the application and its findings and hands the application to the UI.
func (op *Operator) FinalizeApplication(ctx context.Context, cr *ApplicationCR) (*ApplicationStatus, bool, error) {
	tenant, err := op.apps.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		return nil, false, err
	}
	if tenant == nil {
		return nil, true, nil // the tenant is gone, and with it the rows
	}
	return nil, true, op.apps.store.OrphanApplication(ctx, tenant.ID, cr.Metadata.Name)
}

// FinalizeScanSource disables the source, revokes its tokens and removes the secret material copied for it.
func (op *Operator) FinalizeScanSource(ctx context.Context, cr *ScanSourceCR) (*ScanSourceStatus, bool, error) {
	tenant, err := op.scanSources.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		return nil, false, err
	}
	if tenant == nil {
		return nil, true, nil
	}
	n, err := op.scanSources.store.DisableScanSource(ctx, tenant.ID, cr.Metadata.Name)
	if err != nil {
		return nil, false, err
	}
	op.logger.Info("scan source disabled", "name", cr.Metadata.Name, "namespace", cr.Metadata.Namespace, "tokensRevoked", n)
	return nil, true, nil
}

// FinalizeSLAPolicy removes the policy; the due dates are recomputed against what is left.
func (op *Operator) FinalizeSLAPolicy(ctx context.Context, cr *SLAPolicyCR) (*SLAPolicyStatus, bool, error) {
	tenant, err := op.slaPolicies.store.GetTenantByNamespace(ctx, cr.Metadata.Namespace)
	if err != nil {
		return nil, false, err
	}
	if tenant == nil {
		return nil, true, nil
	}
	return nil, true, op.slaPolicies.store.DeleteSLAPolicy(ctx, tenant.ID, cr.Metadata.Namespace, cr.Metadata.Name)
}

// FinalizeTenant refuses to delete a tenant that has data unless the resource says Purge. It is not done (and
// says why in Ready) until then; the deletion simply waits, and nothing is lost by waiting.
func (op *Operator) FinalizeTenant(ctx context.Context, cr *TenantCR) (*TenantStatus, bool, error) {
	st := &cr.Status
	existing, err := op.tenants.store.GetTenantBySlug(ctx, cr.Metadata.Name)
	if err != nil {
		return nil, false, err
	}
	if existing == nil {
		return nil, true, nil
	}
	has, err := op.tenants.store.TenantHasData(ctx, existing.ID)
	if err != nil {
		return nil, false, err
	}
	if has && cr.Spec.DeletionPolicy != TenantPurge {
		st.SetCondition("Ready", "False", "DeletionBlocked",
			fmt.Sprintf("tenant %q has data and is not deleted. Set spec.deletionPolicy to %s to delete it together with its data, or restore the resource.", cr.Metadata.Name, TenantPurge))
		return st, false, nil
	}
	if err := op.tenants.store.PurgeTenant(ctx, existing.ID); err != nil {
		return nil, false, err
	}
	op.logger.Warn("tenant deleted", "slug", cr.Metadata.Name, "withData", has)
	return nil, true, nil
}
