package domain

import (
	"encoding/json"
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

func TestApplicationSpec_Selectors(t *testing.T) {
	id, tenant := uuid.New(), uuid.New()
	for name, raw := range map[string]string{
		"workloads are not built": `{"selectors":{"workloads":[{"cluster":"prod"}]}}`,
		"empty pattern":           `{"selectors":{"repositories":[{"url":""}]}}`,
		"match everything":        `{"selectors":{"images":[{"repository":"*"}]}}`,
		"star in the middle":      `{"selectors":{"repositories":[{"url":"https://github.com/*/shop"}]}}`,
	} {
		var s ApplicationSpec
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ToApplication(id, tenant, "x"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
