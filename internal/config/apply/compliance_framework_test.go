package apply_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/config/apply"
)

// D102: a ComplianceFramework (one tenant) and a ClusterComplianceFramework (every tenant) are applied like the
// other policies: a valid spec is in force, an invalid one is stored with its reason and reported, and a name that
// is the id of a built-in framework is refused.
func TestApply_ComplianceFrameworks(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	applier := apply.NewApplier(store)
	if _, err := applier.ApplyDocument(ctx, []byte(`{"kind":"Tenant","metadata":{"name":"acme"},"spec":{"namespaces":["acme-sec"]}}`)); err != nil {
		t.Fatal(err)
	}
	tn, _ := store.GetTenantByNamespace(ctx, "acme-sec")

	good := `apiVersion: rampart.aspm.dev/v1alpha1
kind: ComplianceFramework
metadata: {name: acme-secpol, namespace: acme-sec}
spec:
  displayName: ACME secure coding policy
  version: "2026.1"
  appliesTo: {complianceScope: pci}
  evidenceWindowDays: 30
  controls:
    - {id: SC-1, name: No hard-coded credentials, match: {categories: [secret]}}
    - {id: SC-2, name: No injection, match: {cwes: [78, 89], minSeverity: high}, evidence: {categories: [sast, dast]}}
    - {id: SC-3, name: Threat model reviewed, manual: true}
`
	msg, err := applier.ApplyDocument(ctx, []byte(good))
	if err != nil || msg != "complianceframework.rampart.aspm.dev/acme-secpol configured" {
		t.Fatalf("a valid framework: %q %v", msg, err)
	}
	if p, ok := store.Policy("compliance:" + tn.ID.String() + ":acme-sec:acme-secpol"); !ok || p.Error != "" {
		t.Fatalf("framework not stored as valid: %+v %v", p, ok)
	}

	bad := `{"kind":"ComplianceFramework","metadata":{"name":"acme-secpol","namespace":"acme-sec"},
		"spec":{"displayName":"x","version":"1","controls":[{"id":"C1","name":"no match"}]}}`
	_, err = applier.ApplyDocument(ctx, []byte(bad))
	if err == nil || !strings.Contains(err.Error(), "stored but is not applied") {
		t.Fatalf("an invalid framework must be reported, got %v", err)
	}
	if p, _ := store.Policy("compliance:" + tn.ID.String() + ":acme-sec:acme-secpol"); p.Error == "" {
		t.Fatal("the refused spec must be stored with its reason")
	}

	builtIn := `{"kind":"ComplianceFramework","metadata":{"name":"owasp-top10-2025","namespace":"acme-sec"},
		"spec":{"displayName":"x","version":"1","controls":[{"id":"C1","name":"n","manual":true}]}}`
	if _, err := applier.ApplyDocument(ctx, []byte(builtIn)); err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Fatalf("a built-in id must be refused, got %v", err)
	}

	cluster := `{"kind":"ClusterComplianceFramework","metadata":{"name":"group-baseline"},
		"spec":{"displayName":"Group baseline","version":"1","controls":[{"id":"B-1","name":"No secrets","match":{"categories":["secret"]}}]}}`
	if msg, err := applier.ApplyDocument(ctx, []byte(cluster)); err != nil || msg != "clustercomplianceframework.rampart.aspm.dev/group-baseline configured" {
		t.Fatalf("a valid cluster framework: %q %v", msg, err)
	}
	if p, ok := store.Policy("cluster:compliance:group-baseline"); !ok || p.Error != "" {
		t.Fatalf("cluster framework not stored: %+v %v", p, ok)
	}
	clusterBad := `{"kind":"ClusterComplianceFramework","metadata":{"name":"broken"},
		"spec":{"displayName":"Broken","version":"1","controls":[{"id":"B-1","name":"n","match":{"categories":["nope"]}}]}}`
	if _, err := applier.ApplyDocument(ctx, []byte(clusterBad)); err == nil || !strings.Contains(err.Error(), "stored but is not applied") {
		t.Fatalf("an invalid cluster framework must be reported, got %v", err)
	}
}
