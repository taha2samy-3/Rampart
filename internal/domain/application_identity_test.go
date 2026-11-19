package domain_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"rampart/internal/domain"
)

func buildApp(t *testing.T, spec domain.ApplicationSpec) (domain.Application, error) {
	t.Helper()
	return spec.ToApplication(uuid.New(), uuid.New(), "payments-main")
}

// An application is one branch of one repository (D140): type repo names both, and takes an environment.
func TestApplicationSpec_RepoIsOneBranchOfOneRepository(t *testing.T) {
	app, err := buildApp(t, domain.ApplicationSpec{DisplayName: "Payments (main)", Type: "repo", Repository: " github.com/acme/payments ", Branch: "main", Environment: "Production"})
	if err != nil {
		t.Fatal(err)
	}
	if app.Type != "repo" || app.Repository != "github.com/acme/payments" || app.Branch != "main" || app.Environment != "production" {
		t.Fatalf("not normalised: %+v", app)
	}
	// an application that says nothing about type is repository-wide, as before, and is not described by an environment
	old, err := buildApp(t, domain.ApplicationSpec{DisplayName: "Old"})
	if err != nil || old.Type != "" || old.Branch != "" || old.Environment != "" {
		t.Fatalf("a spec without type must stay as it was: %+v %v", old, err)
	}
}

func TestApplicationSpec_IdentityRefusals(t *testing.T) {
	for _, c := range []struct {
		name string
		spec domain.ApplicationSpec
		want string
	}{
		{"machine is designed, not built", domain.ApplicationSpec{DisplayName: "x", Type: "machine"}, "designed but not built"},
		{"an unknown type", domain.ApplicationSpec{DisplayName: "x", Type: "image"}, `not one of repo`},
		{"repo needs a branch", domain.ApplicationSpec{DisplayName: "x", Type: "repo", Repository: "github.com/a/b"}, "needs repository and branch"},
		{"repo needs a repository", domain.ApplicationSpec{DisplayName: "x", Type: "repo", Branch: "main"}, "needs repository and branch"},
		{"a branch pattern is not one branch", domain.ApplicationSpec{DisplayName: "x", Type: "repo", Repository: "github.com/a/b", Branch: "release/*"}, "one branch name"},
		{"a repository pattern is not one repository", domain.ApplicationSpec{DisplayName: "x", Type: "repo", Repository: "github.com/a/*", Branch: "main"}, "one repository address"},
		{"branch without type", domain.ApplicationSpec{DisplayName: "x", Branch: "main"}, "need type repo"},
		{"repository without type", domain.ApplicationSpec{DisplayName: "x", Repository: "github.com/a/b"}, "need type repo"},
		{"an unknown environment", domain.ApplicationSpec{DisplayName: "x", Environment: "prod"}, "environment"},
	} {
		_, err := buildApp(t, c.spec)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error containing %q, got %v", c.name, c.want, err)
		}
	}
}

// A person may set the environment; an unknown value is an error, not a silently lower score; the empty string says "not described".
func TestApplicationContextUpdate_Environment(t *testing.T) {
	str := func(s string) *string { return &s }
	u := domain.ApplicationContextUpdate{Environment: str(" Staging ")}
	if err := u.Validate(); err != nil || *u.Environment != "staging" {
		t.Fatalf("%v %v", err, u.Environment)
	}
	bad := domain.ApplicationContextUpdate{Environment: str("prod")}
	if err := bad.Validate(); err == nil {
		t.Fatal("an unknown environment must be refused")
	}
	clear := domain.ApplicationContextUpdate{Environment: str("")}
	if err := clear.Validate(); err != nil {
		t.Fatalf("empty means not described: %v", err)
	}
	prev := domain.Application{BusinessCriticality: "high", Environment: "production"}
	next := clear.Apply(prev)
	if next.Environment != "" || !domain.ScoreContextChanged(prev, next) {
		t.Fatalf("clearing the environment must move the score: %+v", next)
	}
	same := domain.ApplicationContextUpdate{Environment: str("production")}
	if domain.ScoreContextChanged(prev, same.Apply(prev)) {
		t.Fatal("saying the same environment again changes nothing")
	}
}
