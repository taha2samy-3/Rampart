package domain_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

func TestScanSource_ApplicationRefValidation(t *testing.T) {
	cases := []struct {
		name    string
		ref     domain.ApplicationRef
		wantErr bool
	}{
		{"empty all", domain.ApplicationRef{}, true},
		{"whitespace name", domain.ApplicationRef{Name: "   "}, true},
		{"too long name", domain.ApplicationRef{Name: strings.Repeat("a", 256)}, true},
		{"valid name", domain.ApplicationRef{Name: "checkout-payment-service"}, false},
		{"valid selector", domain.ApplicationRef{Selector: &domain.ApplicationSelector{MatchLabels: map[string]string{"app": "checkout"}}}, false},
		{"valid repository", domain.ApplicationRef{Repository: "https://github.com/acme/checkout"}, false},
		{"valid multi-mode", domain.ApplicationRef{Name: "checkout", Repository: "https://github.com/acme/checkout"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ref.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("expected error: %v, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestScanSource_CategoriesValidation(t *testing.T) {
	cases := []struct {
		name       string
		categories []string
		wantErr    bool
	}{
		{"empty categories", []string{}, true},
		{"invalid category", []string{"invalid_discipline"}, true},
		{"valid single category", []string{"sast"}, false},
		{"valid multi categories", []string{"sast", "secret", "sca"}, false},
		{"valid all category", []string{"all"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &domain.ScanSource{
				Name:           "test-source",
				ApplicationRef: domain.ApplicationRef{Name: "checkout-service"},
				Categories:     tc.categories,
			}
			err := src.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("expected error: %v, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestScanSource_PermitsCategory(t *testing.T) {
	// 1. All category permits every finding category
	srcAll := &domain.ScanSource{
		Categories: []string{"all"},
	}
	allCats := []domain.FindingCategory{
		domain.CategorySAST,
		domain.CategorySCA,
		domain.CategorySecret,
		domain.CategoryContainer,
		domain.CategoryDAST,
		domain.CategoryIaC,
		domain.CategoryCSPM,
		domain.CategoryCompliance,
		domain.CategoryLicense,
		domain.CategorySupplyChain,
	}
	for _, c := range allCats {
		if !srcAll.PermitsCategory(c) {
			t.Errorf("srcAll expected to permit %s", c)
		}
	}

	// 2. Specific categories filter correctly
	srcRestricted := &domain.ScanSource{
		Categories: []string{"sast", "secret"},
	}
	if !srcRestricted.PermitsCategory(domain.CategorySAST) {
		t.Errorf("expected permit for sast")
	}
	if !srcRestricted.PermitsCategory(domain.CategorySecret) {
		t.Errorf("expected permit for secret")
	}
	if srcRestricted.PermitsCategory(domain.CategoryDAST) {
		t.Errorf("expected rejection for dast")
	}
	if srcRestricted.PermitsCategory(domain.CategoryContainer) {
		t.Errorf("expected rejection for container")
	}
}

func TestScanSource_AuthSpecValidation(t *testing.T) {
	t.Run("simultaneous multi-auth (token + federation) is valid", func(t *testing.T) {
		auth := domain.AuthSpec{
			TokenSecretRef: &domain.SecretRef{Name: "my-sec", Key: "token"},
			Federation: &domain.FederationSpec{
				Issuer:          "https://sts.amazonaws.com",
				BoundClaims:     map[string]string{"account_id": "123456789012"},
				RepositoryClaim: "repository", RefClaim: "ref",
			},
		}
		if err := auth.Validate(); err != nil {
			t.Fatalf("expected multi-auth to be valid, got: %v", err)
		}
	})

	t.Run("simultaneous multi-auth with federations array is valid", func(t *testing.T) {
		auth := domain.AuthSpec{
			TokenSecretRef: &domain.SecretRef{Name: "my-sec", Key: "token"},
			Federations: []domain.FederationSpec{
				{
					Issuer:      "https://token.actions.githubusercontent.com",
					Provider:    "github",
					BoundClaims: map[string]string{"repository_id": "999", "repository_owner_id": "1"},
				},
				{
					Issuer:          "https://sts.amazonaws.com",
					BoundClaims:     map[string]string{"account_id": "123456789012"},
					RepositoryClaim: "repository", RefClaim: "ref",
				},
			},
		}
		if err := auth.Validate(); err != nil {
			t.Fatalf("expected multi-federation auth to be valid, got: %v", err)
		}
		if len(auth.AllFederations()) != 2 {
			t.Fatalf("expected 2 federations, got %d", len(auth.AllFederations()))
		}
	})

	t.Run("neither specified error", func(t *testing.T) {
		auth := domain.AuthSpec{}
		if err := auth.Validate(); err == nil {
			t.Fatal("expected error when no auth mode specified")
		}
	})

	t.Run("valid standard tokenSecretRef", func(t *testing.T) {
		auth := domain.AuthSpec{
			TokenSecretRef: &domain.SecretRef{Name: "my-sec", Key: "token"},
		}
		if err := auth.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("valid universal federation", func(t *testing.T) {
		auth := domain.AuthSpec{
			Federation: &domain.FederationSpec{
				Issuer:          "https://sts.amazonaws.com",
				BoundClaims:     map[string]string{"account_id": "123456789012", "role_arn": "arn:aws:iam::..."},
				RepositoryClaim: "repository", RefClaim: "ref", // a generic issuer names the claims that bind the job (D80)
			},
		}
		if err := auth.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid federation empty boundClaims", func(t *testing.T) {
		auth := domain.AuthSpec{
			Federation: &domain.FederationSpec{
				Issuer:      "https://sts.amazonaws.com",
				BoundClaims: map[string]string{},
			},
		}
		if err := auth.Validate(); err == nil {
			t.Fatal("expected error for empty boundClaims")
		}
	})
}

func TestScanSource_TrustRuleValidation(t *testing.T) {
	t.Run("generic boundClaims valid for any issuer that names its repository and ref claims (AWS / Azure)", func(t *testing.T) {
		rule := domain.TrustRule{
			Issuer:          "https://sts.amazonaws.com",
			BoundClaims:     map[string]string{"account_id": "123456789012"},
			RepositoryClaim: "repository", RefClaim: "ref",
		}
		if err := rule.Validate(); err != nil {
			t.Fatalf("expected rule with boundClaims to be valid, got: %v", err)
		}
	})

	t.Run("legacy github provider requires repositoryId and repositoryOwnerId", func(t *testing.T) {
		rule := domain.TrustRule{
			Issuer:   "https://token.actions.githubusercontent.com",
			Provider: "github",
		}
		if err := rule.Validate(); err == nil {
			t.Fatal("expected error for missing github repo IDs")
		}
	})
}

func TestScanSource_FullLifecycleValidation(t *testing.T) {
	src := &domain.ScanSource{
		ID:             domain.NewID(),
		TenantID:       domain.NewID(),
		Name:           "checkout-sast",
		ApplicationRef: domain.ApplicationRef{Name: "checkout-payment-service"},
		ApplicationID:  uuid.New(),
		Categories:     []string{"sast", "secret"},
		Type:           "ci",
		Auth: domain.AuthSpec{
			TokenSecretRef: &domain.SecretRef{Name: "checkout-token", Key: "token"},
		},
	}

	if err := src.Validate(); err != nil {
		t.Fatalf("expected valid scansource, got: %v", err)
	}
}

// docs/51 step 1.3: a boundClaims rule must bind the repository and the ref, and GitHub and GitLab by immutable ids (D22, D80).
func TestTrustRule_BoundClaimsMustBindRepositoryAndRef(t *testing.T) {
	bad := []domain.TrustRule{
		{Issuer: "https://token.actions.githubusercontent.com", BoundClaims: map[string]string{"repository": "acme/payments"}},
		{Issuer: "https://token.actions.githubusercontent.com", Provider: "github", BoundClaims: map[string]string{"repository": "acme/payments"}},
		{Issuer: "https://gitlab.com", Provider: "gitlab", BoundClaims: map[string]string{"project_path": "acme/payments"}},
		{Issuer: "https://sts.example", BoundClaims: map[string]string{"sub": "x"}, RepositoryClaim: "repo"},
		{Issuer: "https://sts.example", Provider: "bitbucket", BoundClaims: map[string]string{"sub": "x"}},
	}
	for i, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("rule %d must be refused: %+v", i, r)
		}
	}
	good := []domain.TrustRule{
		{Issuer: "https://token.actions.githubusercontent.com", Provider: "github", BoundClaims: map[string]string{"repository_id": "1", "repository_owner_id": "2"}},
		{Issuer: "https://sts.example", BoundClaims: map[string]string{"sub": "x"}, RepositoryClaim: "repo", RefClaim: "branch"},
	}
	for i, r := range good {
		if err := r.Validate(); err != nil {
			t.Errorf("rule %d must be accepted: %v", i, err)
		}
	}
}
