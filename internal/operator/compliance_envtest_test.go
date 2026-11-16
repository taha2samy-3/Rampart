package operator_test

import (
	"context"
	"strings"
	"testing"
	"time"
)

// D102: a ComplianceFramework in a tenant's namespace and a ClusterComplianceFramework are validated by the
// operator: a valid one is Ready, an invalid one is Ready=False InvalidSpec with the parser's reason, a name that is
// the id of a built-in framework is refused, and deleting one removes the stored row.
func TestComplianceFrameworksShowTheirStatus(t *testing.T) {
	c, store, _ := startEnv(t)
	ctx := context.Background()
	if err := c.Create(ctx, cr("Tenant", "", "acme-cf", map[string]any{"displayName": "Acme", "namespaces": []any{"team-cf"}})); err != nil {
		t.Fatal(err)
	}
	spec := func(controls ...any) map[string]any {
		return map[string]any{"displayName": "ACME secure coding", "version": "2026.1", "controls": controls}
	}
	good := cr("ComplianceFramework", "team-cf", "acme-secpol", map[string]any{
		"displayName": "ACME secure coding", "version": "2026.1", "appliesTo": map[string]any{"complianceScope": "pci"},
		"evidenceWindowDays": int64(30),
		"controls": []any{
			map[string]any{"id": "SC-1", "name": "No hard-coded credentials", "match": map[string]any{"categories": []any{"secret"}}},
			map[string]any{"id": "SC-2", "name": "No injection", "match": map[string]any{"cwes": []any{int64(89)}, "minSeverity": "high"}},
			map[string]any{"id": "SC-3", "name": "Threat model reviewed", "manual": true},
		},
	})
	if err := c.Create(ctx, good); err != nil {
		t.Fatal(err)
	}
	ready(t, c, good, "Reconciled")
	tn, _ := store.GetTenantByNamespace(ctx, "team-cf")
	key := "compliance:" + tn.ID.String() + ":team-cf:acme-secpol"
	if p, ok := store.Policy(key); !ok || p.Error != "" {
		t.Fatalf("framework not stored: %+v %v", p, ok)
	}

	// The schema accepts a control with neither match nor manual; the parser refuses it.
	invalid := cr("ComplianceFramework", "team-cf", "no-match", spec(map[string]any{"id": "C-1", "name": "Nothing to match"}))
	if err := c.Create(ctx, invalid); err != nil {
		t.Fatal(err)
	}
	st := ready(t, c, invalid, "InvalidSpec")
	if msg := conditionMessage(st); !strings.Contains(msg, "C-1") {
		t.Fatalf("the reason must name the control: %q", msg)
	}

	builtIn := cr("ComplianceFramework", "team-cf", "owasp-top10-2025", spec(map[string]any{"id": "C-1", "name": "n", "manual": true}))
	if err := c.Create(ctx, builtIn); err != nil {
		t.Fatal(err)
	}
	st = ready(t, c, builtIn, "InvalidSpec")
	if msg := conditionMessage(st); !strings.Contains(msg, "built-in") {
		t.Fatalf("a built-in id must be refused with a clear message: %q", msg)
	}

	if err := c.Create(ctx, cr("ComplianceFramework", "team-cf", "big-window", map[string]any{
		"displayName": "x", "version": "1", "evidenceWindowDays": int64(400),
		"controls": []any{map[string]any{"id": "C-1", "name": "n", "manual": true}},
	})); err == nil {
		t.Fatal("evidenceWindowDays out of range must be refused by the CRD schema")
	}

	cluster := cr("ClusterComplianceFramework", "", "group-baseline", spec(
		map[string]any{"id": "B-1", "name": "No secrets", "match": map[string]any{"categories": []any{"secret"}}}))
	if err := c.Create(ctx, cluster); err != nil {
		t.Fatal(err)
	}
	ready(t, c, cluster, "Reconciled")
	if p, ok := store.Policy("cluster:compliance:group-baseline"); !ok || p.Error != "" {
		t.Fatalf("cluster framework not stored: %+v %v", p, ok)
	}

	// The finalizer removes the row.
	if err := c.Delete(ctx, good); err != nil {
		t.Fatal(err)
	}
	eventuallyGone(t, c, good)
	if !waitFor(func() bool { _, ok := store.Policy(key); return !ok }) {
		t.Fatal("deleting the framework must remove the stored row")
	}
	if err := c.Delete(ctx, cluster); err != nil {
		t.Fatal(err)
	}
	eventuallyGone(t, c, cluster)
	if !waitFor(func() bool { _, ok := store.Policy("cluster:compliance:group-baseline"); return !ok }) {
		t.Fatal("deleting the cluster framework must remove the stored row")
	}
}

func conditionMessage(status map[string]any) string {
	conds, _ := status["conditions"].([]any)
	for _, x := range conds {
		if m, ok := x.(map[string]any); ok && m["type"] == "Ready" {
			s, _ := m["message"].(string)
			return s
		}
	}
	return ""
}

func waitFor(cond func() bool) bool {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
