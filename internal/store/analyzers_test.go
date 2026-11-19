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

func newAnalyzerTenant(t *testing.T, ctx context.Context, sys interface {
	CreateTenant(context.Context, *domain.Tenant) error
}) uuid.UUID {
	t.Helper()
	tn := &domain.Tenant{ID: uuid.New(), Slug: "an-" + uuid.NewString()[:8], DisplayName: "T", CreatedAt: time.Now().UTC()}
	if err := sys.CreateTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	return tn.ID
}

// D143 on PostgreSQL: the analyzers of the cluster are seen by every tenant, a tenant's own by that tenant only, an analyzer whose spec was
// refused is listed with the reason, an edit that fails keeps the spec in force, and the database refuses a kind it does not know.
func TestAnalyzers_StoredAndListedPerTenant_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	a, b := newAnalyzerTenant(t, ctx, sys), newAnalyzerTenant(t, ctx, sys)

	svc := []byte(`{"service":{"name":"sonatype","namespace":"tools","port":50051}}`)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(sys.SaveClusterPolicy(ctx, domain.AnalyzerKindExternal, apply.PolicyObject{Name: "sonatype", Spec: svc, Generation: 1}))
	must(sys.SaveClusterPolicy(ctx, domain.AnalyzerKindSBOM, apply.PolicyObject{Name: "native-matcher", Spec: []byte(`{"engine":"hybrid"}`), Generation: 1}))
	must(sys.SaveTenantPolicy(ctx, a, domain.AnalyzerKindExternal, apply.PolicyObject{Namespace: "a-ns", Name: "mine", Spec: svc, Generation: 1}))
	// the first spec of this one was refused: nothing was ever in force
	must(sys.SaveClusterPolicy(ctx, domain.AnalyzerKindExternal, apply.PolicyObject{Name: "web", Spec: []byte(`{"protocol":"http"}`), Error: "protocol http: no HTTP client is built", Generation: 1}))

	listA, err := appStore.ListAnalyzers(ctx, a)
	must(err)
	var got []string
	byName := map[string]domain.StoredAnalyzerObject{}
	for _, x := range listA {
		got = append(got, x.Origin+"/"+x.Kind+"/"+x.Namespace+"/"+x.Name)
		byName[x.Name] = x
	}
	want := "cluster/external_analyzer//sonatype,cluster/external_analyzer//web,cluster/sbom_analyzer//native-matcher,tenant/external_analyzer/a-ns/mine"
	if strings.Join(got, ",") != want {
		t.Fatalf("tenant A sees\n %s\nwant\n %s", strings.Join(got, ","), want)
	}
	if byName["web"].Error == "" || !strings.Contains(string(byName["web"].Spec), "http") {
		t.Fatalf("an analyzer whose first spec was refused is listed with the spec and the reason: %+v", byName["web"])
	}
	listB, err := appStore.ListAnalyzers(ctx, b)
	must(err)
	for _, x := range listB {
		if x.Origin != "cluster" {
			t.Fatalf("tenant B must not see tenant A's analyzer: %+v", x)
		}
	}
	if len(listB) != 3 {
		t.Fatalf("tenant B sees the three cluster analyzers: %+v", listB)
	}

	// an edit that is refused keeps the spec in force and says why
	must(sys.SaveClusterPolicy(ctx, domain.AnalyzerKindExternal, apply.PolicyObject{Name: "sonatype", Spec: []byte(`{"protocol":"http"}`), Error: "no HTTP client", Generation: 2}))
	listA, _ = appStore.ListAnalyzers(ctx, a)
	for _, x := range listA {
		if x.Name == "sonatype" && (x.Error == "" || !strings.Contains(string(x.Spec), "sonatype")) {
			t.Fatalf("the spec in force stays while the edit is refused: %+v", x)
		}
	}

	// the database knows two analyzer kinds and no other
	if err := sys.SaveClusterPolicy(ctx, "analyzer", apply.PolicyObject{Name: "x", Spec: svc}); err == nil {
		t.Fatal("a kind the database does not know must be refused by the database")
	}
	must(sys.DeleteClusterPolicy(ctx, domain.AnalyzerKindExternal, "web"))
	listA, _ = appStore.ListAnalyzers(ctx, a)
	if len(listA) != 3 {
		t.Fatalf("a deleted analyzer is gone: %d", len(listA))
	}
}

// What happened to an analyzer is the tenant's that caused it, newest first, with its detail; only the newest 200 of an analyzer are kept.
func TestAnalyzerEvents_AreTheTenantsOwnAndBounded_OnPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	appStore, sys := setupStores(t, ctx)
	a, b := newAnalyzerTenant(t, ctx, sys), newAnalyzerTenant(t, ctx, sys)
	ev := func(outcome, msg string) domain.AnalyzerEvent {
		return domain.AnalyzerEvent{Kind: "external", Scope: "cluster", Name: "sonatype", Event: "test", Outcome: outcome, Message: msg,
			Detail: map[string]string{"serving": "SERVING"}, Duration: 42 * time.Millisecond, Actor: "ada"}
	}
	for i, e := range []domain.AnalyzerEvent{ev("failed", "first"), ev("succeeded", "second"), ev("succeeded", "third")} {
		if err := appStore.RecordAnalyzerEvent(ctx, a, e); err != nil {
			t.Fatal(i, err)
		}
		time.Sleep(5 * time.Millisecond) // created_at orders them
	}
	if err := appStore.RecordAnalyzerEvent(ctx, b, ev("failed", "tenant B's")); err != nil {
		t.Fatal(err)
	}
	got, err := appStore.ListAnalyzerEvents(ctx, a, "external", "cluster", "", "sonatype", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Message != "third" || got[2].Message != "first" || got[2].Outcome != "failed" || got[0].Duration != 42*time.Millisecond ||
		got[0].Detail["serving"] != "SERVING" || got[0].Actor != "ada" {
		t.Fatalf("tenant A's events, newest first: %+v", got)
	}
	other, _ := appStore.ListAnalyzerEvents(ctx, b, "external", "cluster", "", "sonatype", 10)
	if len(other) != 1 || other[0].Message != "tenant B's" {
		t.Fatalf("tenant B sees its own event and none of tenant A's: %+v", other)
	}
	// an analyzer with the same name of another kind or scope is another analyzer
	none, _ := appStore.ListAnalyzerEvents(ctx, a, "sbom", "cluster", "", "sonatype", 10)
	if len(none) != 0 {
		t.Fatalf("events are per analyzer: %+v", none)
	}

	for i := 0; i < 210; i++ {
		if err := appStore.RecordAnalyzerEvent(ctx, a, ev("succeeded", "bulk")); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := sys.Pool().QueryRow(ctx, `SELECT count(*) FROM analyzer_event WHERE tenant_id = $1 AND analyzer_name = 'sonatype'`, a).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 200 {
		t.Fatalf("only the newest 200 events of an analyzer are kept, found %d", n)
	}
	// a malformed event is refused by the database (an outcome it does not know)
	bad := ev("maybe", "x")
	if err := appStore.RecordAnalyzerEvent(ctx, a, bad); err == nil {
		t.Fatal("an outcome other than succeeded or failed must be refused")
	}
}
