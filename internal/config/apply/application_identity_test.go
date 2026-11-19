package apply_test

import (
	"context"
	"strings"
	"testing"

	"rampart/internal/config/apply"
)

// An Application resource that is one branch of one repository (D140) is applied whole, and the refusals say why: machine is
// designed and not built, a branch needs its repository, a pattern is not one branch, an unknown environment is an error and
// not a silently lower score. A resource that names none of this is applied as before.
func TestApply_ApplicationIsOneBranch(t *testing.T) {
	ctx := context.Background()
	store := apply.NewMemoryConfigStore()
	applier := apply.NewApplier(store)
	if _, err := applier.ApplyDocument(ctx, []byte(`{"kind":"Tenant","metadata":{"name":"acme"},"spec":{"namespaces":["acme-pay"]}}`)); err != nil {
		t.Fatal(err)
	}
	tn, _ := store.GetTenantByNamespace(ctx, "acme-pay")

	app := func(spec string) string {
		return `{"apiVersion":"rampart.aspm.dev/v1alpha1","kind":"Application","metadata":{"name":"payments-main","namespace":"acme-pay"},"spec":` + spec + `}`
	}
	if _, err := applier.ApplyDocument(ctx, []byte(app(`{"displayName":"Payments (main)","type":"repo","repository":"github.com/acme/payments","branch":"main","environment":"production","businessCriticality":"critical"}`))); err != nil {
		t.Fatalf("a repo application: %v", err)
	}
	got, err := store.GetApplicationBySlug(ctx, tn.ID, "payments-main")
	if err != nil || got == nil {
		t.Fatalf("not stored: %v", err)
	}
	if got.Type != "repo" || got.Repository != "github.com/acme/payments" || got.Branch != "main" || got.Environment != "production" || got.BusinessCriticality != "critical" {
		t.Fatalf("stored wrongly: %+v", got)
	}

	for name, c := range map[string]struct{ spec, want string }{
		"machine is designed, not built": {`{"displayName":"x","type":"machine"}`, "designed but not built"},
		"a branch pattern":               {`{"displayName":"x","type":"repo","repository":"github.com/a/b","branch":"release/*"}`, "one branch name"},
		"a branch without its type":      {`{"displayName":"x","branch":"main"}`, "need type repo"},
		"an unknown environment":         {`{"displayName":"x","environment":"prod"}`, "environment"},
	} {
		_, err := applier.ApplyDocument(ctx, []byte(app(c.spec)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error containing %q, got %v", name, c.want, err)
		}
	}

	// a resource that says none of this is applied as before
	if _, err := applier.ApplyDocument(ctx, []byte(`{"apiVersion":"rampart.aspm.dev/v1alpha1","kind":"Application","metadata":{"name":"legacy","namespace":"acme-pay"},"spec":{"displayName":"Legacy"}}`)); err != nil {
		t.Fatalf("an application without type must still apply: %v", err)
	}
	old, _ := store.GetApplicationBySlug(ctx, tn.ID, "legacy")
	if old == nil || old.Type != "" || old.Branch != "" || old.Environment != "" {
		t.Fatalf("a legacy application gained identity: %+v", old)
	}
}
