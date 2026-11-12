package domain

import (
	"testing"

	"github.com/google/uuid"
)

func TestApplicationSpec_ToApplication(t *testing.T) {
	id, tenant := uuid.New(), uuid.New()
	app, err := ApplicationSpec{
		BusinessCriticality: "Critical", DataClassification: []string{"PII", "pci"},
		CompensatingControls: []string{"waf", "apiGateway", "privateNetwork"},
	}.ToApplication(id, tenant, "payments")
	if err != nil {
		t.Fatal(err)
	}
	if app.Name != "payments" || app.BusinessCriticality != "critical" || app.Lifecycle != "production" {
		t.Fatalf("defaults: %+v", app)
	}
	if len(app.DataClassification) != 2 || app.DataClassification[0] != "pii" {
		t.Fatalf("classification: %v", app.DataClassification)
	}
	// The resource spells controls in camelCase, the row in snake_case (D17).
	if app.CompensatingControls[1] != "api_gateway" || app.CompensatingControls[2] != "private_network" {
		t.Fatalf("controls: %v", app.CompensatingControls)
	}
	for name, s := range map[string]ApplicationSpec{
		"unknown criticality":    {BusinessCriticality: "urgent"},
		"unknown classification": {DataClassification: []string{"confidential"}},
		"unknown control":        {CompensatingControls: []string{"antivirus"}},
		"snake_case control":     {CompensatingControls: []string{"api_gateway"}},
	} {
		if _, err := s.ToApplication(id, tenant, "x"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// A WAF or an API gateway counts against what a dynamic scan found over HTTP, and nothing else (docs/06 section 2,
// docs/04's example, D55).
func TestControlCovers(t *testing.T) {
	cases := []struct {
		controls []string
		category FindingCategory
		want     bool
	}{
		{[]string{"waf"}, CategoryDAST, true},
		{[]string{"api_gateway"}, CategoryDAST, true},
		{[]string{"waf"}, CategorySAST, false},
		{[]string{"waf"}, CategorySCA, false},
		{[]string{"mtls", "private_network"}, CategoryDAST, false},
		{nil, CategoryDAST, false},
	}
	for _, c := range cases {
		if got := ControlCovers(c.controls, c.category); got != c.want {
			t.Fatalf("%v on %s: %v, want %v", c.controls, c.category, got, c.want)
		}
	}
}
