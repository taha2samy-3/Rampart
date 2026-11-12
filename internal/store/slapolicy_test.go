package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/config/apply"
	"rampart/internal/domain"
)

// A tenant's SLAPolicy replaces the built-in one: new findings get its due dates, and when it changes every
// active finding is recomputed (docs/04: "enqueue recompute job when changed").
func TestSLAPolicy_ChangesDueDates(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	ingestRules(t, h, map[string]string{"rule.a": "9.8", "rule.b": "2.0"}, "main")
	// Another tenant, which must not be affected. It is made directly: a second harness would start a second
	// River worker that takes this test's jobs and cannot read their reports.
	other := &uploadHarness{t: t, tenant: uuid.New(), store: h.store, sys: h.sys, scorer: h.scorer}
	if err := h.sys.CreateTenant(ctx, &domain.Tenant{ID: other.tenant, Slug: "other-" + uuid.NewString()[:8], DisplayName: "Other", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	seedFindings(t, ctx, h.store, other.tenant, 3) // the first of the seeded findings is fixed: take an active one
	oapp, _ := h.store.LookupApplication(ctx, other.tenant, "shop")
	var oall []*domain.Finding
	every, _ := h.store.ListFindings(ctx, other.tenant)
	for _, f := range every {
		if f.State.IsActive() && len(oall) == 0 {
			oall = append(oall, f)
		}
	}
	if err := h.scorer.ScoreBatch(ctx, other.tenant, oapp.ID, oall); err != nil {
		t.Fatal(err)
	}
	if err := h.store.UpdateFindingRisk(ctx, other.tenant, oall); err != nil {
		t.Fatal(err)
	}
	ids := findingIDs(t, h)
	app, _ := h.store.GetApplication(ctx, h.tenant, mustFinding(t, h, ids["rule.a"]).ApplicationID)
	crit := strings.ToLower(app.BusinessCriticality)

	dueOf := func(hh *uploadHarness, rule string) time.Time {
		var f *domain.Finding
		if hh == other {
			f, _, _ = h.store.GetFinding(ctx, other.tenant, oall[0].ID)
		} else {
			f = mustFinding(t, hh, findingIDs(t, hh)[rule])
		}
		if f.SLADue == nil {
			t.Fatalf("%s has no due date", rule)
		}
		return *f.SLADue
	}
	builtin := domain.DefaultSLAPolicy()
	fa := mustFinding(t, h, ids["rule.a"])
	if !dueOf(h, "rule.a").Equal(builtin.Due(fa.RiskBand, crit, *fa.SLAStart, nil)) {
		t.Fatal("without a policy object the built-in policy applies")
	}
	otherBefore := dueOf(other, "rule.a")

	// The operator stores a policy for this tenant: every critical finding is due within a day, everything else
	// within two. The tenant is flagged for recompute.
	save := func(spec string, gen int64) {
		t.Helper()
		obj := apply.PolicyObject{Namespace: "team", Name: "default", Spec: []byte(spec), Generation: gen}
		if _, err := domain.ParseSLAPolicySpec(obj.Spec); err != nil { // what the operator and `rampart apply` do first
			obj.Error = err.Error()
		}
		if err := h.sys.SaveSLAPolicy(ctx, h.tenant, obj); err != nil {
			t.Fatal(err)
		}
	}
	all := `{"matrix":{"critical":{"critical":1,"high":1,"medium":1,"low":1},"high":{"critical":1,"high":1,"medium":1,"low":1},"medium":{"critical":2,"high":2,"medium":2,"low":2},"low":{"critical":2,"high":2,"medium":2,"low":2}},"caps":{"maxDays":2}}`
	save(all, 1)
	pending, err := h.sys.TenantsNeedingSLARecompute(ctx)
	if err != nil || !contains(pending, h.tenant) || contains(pending, other.tenant) {
		t.Fatalf("recompute flags: %v %v", pending, err)
	}
	n, err := h.scorer.RecomputeSLA(ctx, h.tenant)
	if err != nil || n != 2 {
		t.Fatalf("recompute: %d %v", n, err)
	}
	if err := h.store.ClearSLARecompute(ctx, h.tenant); err != nil {
		t.Fatal(err)
	}
	if pending, _ := h.sys.TenantsNeedingSLARecompute(ctx); contains(pending, h.tenant) {
		t.Fatal("the flag must clear once the due dates follow the policy")
	}
	fa, fb := mustFinding(t, h, ids["rule.a"]), mustFinding(t, h, ids["rule.b"])
	if got := fa.SLADue.Sub(*fa.SLAStart); got != 24*time.Hour {
		t.Fatalf("the critical finding is due after %v, want 1 day", got)
	}
	if got := fb.SLADue.Sub(*fb.SLAStart); got != 48*time.Hour {
		t.Fatalf("the other finding is due after %v, want 2 days", got)
	}
	if !dueOf(other, "rule.a").Equal(otherBefore) {
		t.Fatal("another tenant's due dates moved when this tenant's policy changed")
	}

	// New findings follow the policy too.
	ingestRules(t, h, map[string]string{"rule.a": "9.8", "rule.b": "2.0", "rule.c": "9.9"}, "main")
	fc := mustFinding(t, h, findingIDs(t, h)["rule.c"])
	if got := fc.SLADue.Sub(*fc.SLAStart); got != 24*time.Hour {
		t.Fatalf("a new critical finding is due after %v, want 1 day", got)
	}

	// Saving the same spec again is not a change; saving another one is.
	save(all, 2)
	if pending, _ := h.sys.TenantsNeedingSLARecompute(ctx); contains(pending, h.tenant) {
		t.Fatal("an identical spec must not trigger a recompute")
	}
	save(strings.Replace(all, `"maxDays":2`, `"maxDays":3`, 1), 3)
	if pending, _ := h.sys.TenantsNeedingSLARecompute(ctx); !contains(pending, h.tenant) {
		t.Fatal("a changed spec must trigger a recompute")
	}
	_, _ = h.scorer.RecomputeSLA(ctx, h.tenant)
	_ = h.store.ClearSLARecompute(ctx, h.tenant)

	// An invalid spec is kept with its reason and is NOT applied: the policy in force stays.
	save(`{"businessDays":true}`, 4)
	if pending, _ := h.sys.TenantsNeedingSLARecompute(ctx); contains(pending, h.tenant) {
		t.Fatal("an invalid spec must not trigger a recompute")
	}
	if _, err := h.scorer.RecomputeSLA(ctx, h.tenant); err != nil {
		t.Fatal(err)
	}
	if got := mustFinding(t, h, ids["rule.a"]); got.SLADue.Sub(*got.SLAStart) != 24*time.Hour {
		t.Fatal("an invalid policy replaced the one in force")
	}
	var reason *string
	if err := h.pool.QueryRow(ctx, `SELECT compile_error FROM policy_object WHERE tenant_id = $1 AND name = 'default'`, h.tenant).Scan(&reason); err != nil || reason == nil || !strings.Contains(*reason, "business days") {
		t.Fatalf("the reason must be stored with the object: %v %v", reason, err)
	}

	// The policy named "default" wins over another one.
	if err := h.sys.SaveSLAPolicy(ctx, h.tenant, apply.PolicyObject{Namespace: "team", Name: "aaa", Spec: []byte(`{"caps":{"maxDays":5}}`), Generation: 1}); err != nil {
		t.Fatal(err)
	}
	save(all, 5) // "default" is valid again
	_, _ = h.scorer.RecomputeSLA(ctx, h.tenant)
	if got := mustFinding(t, h, ids["rule.a"]); got.SLADue.Sub(*got.SLAStart) != 24*time.Hour {
		t.Fatal(`the policy named "default" must win over "aaa"`)
	}
}

func mustFinding(t *testing.T, h *uploadHarness, id interface{ String() string }) *domain.Finding {
	t.Helper()
	uid, err := parseUUID(id.String())
	if err != nil {
		t.Fatal(err)
	}
	f, _, err := h.store.GetFinding(context.Background(), h.tenant, uid)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func contains[T comparable](list []T, v T) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func parseUUID(s string) (uuid.UUID, error) { return uuid.Parse(s) }
