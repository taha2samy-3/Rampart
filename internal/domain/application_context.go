package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ApplicationContextUpdate is a change of what the score knows about an application: how critical it is, whether the
// internet reaches it, what data it holds, what stands in front of it, and where it is in its life. A field left out
// is left alone. The same values the Application resource takes (docs/04), so a person and a resource say it alike.
type ApplicationContextUpdate struct {
	BusinessCriticality  *string   `json:"business_criticality,omitempty"`
	InternetFacing       *bool     `json:"internet_facing,omitempty"`
	DataClassification   *[]string `json:"data_classification,omitempty"`
	CompensatingControls *[]string `json:"compensating_controls,omitempty"`
	Lifecycle            *string   `json:"lifecycle,omitempty"`
	// Environment is where the application runs (D140): production, staging, test or development; the empty string says it again
	// as "not described".
	Environment *string         `json:"environment,omitempty"`
	Attributes  *map[string]any `json:"attributes,omitempty"`
}

// ErrEmptyUpdate is an update that changes nothing.
var ErrEmptyUpdate = errors.New("nothing to change")

var lifecycles = []string{"planning", "development", "production", "deprecated"}

// Validate normalises the update in place and refuses a value the score does not know, so a typo is an error and not
// a silently lower score (the same rule as the resource, D55).
func (u *ApplicationContextUpdate) Validate() error {
	if u.BusinessCriticality == nil && u.InternetFacing == nil && u.DataClassification == nil && u.CompensatingControls == nil && u.Lifecycle == nil && u.Environment == nil && u.Attributes == nil {
		return ErrEmptyUpdate
	}
	if u.BusinessCriticality != nil {
		v := strings.ToLower(strings.TrimSpace(*u.BusinessCriticality))
		if !slices.Contains([]string{"critical", "high", "medium", "low"}, v) {
			return fmt.Errorf("business_criticality %q is not one of critical, high, medium, low", *u.BusinessCriticality)
		}
		u.BusinessCriticality = &v
	}
	if u.Lifecycle != nil {
		v := strings.ToLower(strings.TrimSpace(*u.Lifecycle))
		if !slices.Contains(lifecycles, v) {
			return fmt.Errorf("lifecycle %q is not one of %s", *u.Lifecycle, strings.Join(lifecycles, ", "))
		}
		u.Lifecycle = &v
	}
	if u.Environment != nil {
		v := strings.ToLower(strings.TrimSpace(*u.Environment))
		if v != "" && !slices.Contains(Environments, v) {
			return fmt.Errorf("environment %q is not one of %s, or empty", *u.Environment, strings.Join(Environments, ", "))
		}
		u.Environment = &v
	}
	if u.DataClassification != nil {
		out := []string{}
		for _, c := range *u.DataClassification {
			c = strings.ToLower(strings.TrimSpace(c))
			if !dataClassifications[c] {
				return fmt.Errorf("data_classification %q is not one of pii, pci, phi, secret, public", c)
			}
			if !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
		u.DataClassification = &out
	}
	if u.CompensatingControls != nil {
		out := []string{}
		for _, c := range *u.CompensatingControls {
			c = strings.TrimSpace(c)
			v, ok := compensatingControls[c] // camelCase, as the resource spells it
			if !ok {
				if slices.Contains([]string{"waf", "api_gateway", "mtls", "private_network"}, c) {
					v, ok = c, true // snake_case, as it is stored
				}
			}
			if !ok {
				return fmt.Errorf("compensating_controls %q is not one of waf, api_gateway, mtls, private_network", c)
			}
			if !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
		u.CompensatingControls = &out
	}
	return nil
}

// Apply returns the application with the update applied.
func (u ApplicationContextUpdate) Apply(a Application) Application {
	if u.BusinessCriticality != nil {
		a.BusinessCriticality = *u.BusinessCriticality
	}
	if u.InternetFacing != nil {
		a.InternetFacing = *u.InternetFacing
	}
	if u.DataClassification != nil {
		a.DataClassification = *u.DataClassification
	}
	if u.CompensatingControls != nil {
		a.CompensatingControls = *u.CompensatingControls
	}
	if u.Lifecycle != nil {
		a.Lifecycle = *u.Lifecycle
	}
	if u.Environment != nil {
		a.Environment = *u.Environment
	}
	if u.Attributes != nil {
		a.Attributes = *u.Attributes
	}
	return a
}

// ScoreContextChanged says whether a change moves the score or the due date of the findings of the application.
func ScoreContextChanged(a, b Application) bool {
	same := func(x, y []string) bool {
		if len(x) != len(y) {
			return false
		}
		sx, sy := slices.Clone(x), slices.Clone(y)
		slices.Sort(sx)
		slices.Sort(sy)
		return slices.Equal(sx, sy)
	}
	return a.BusinessCriticality != b.BusinessCriticality || a.InternetFacing != b.InternetFacing || a.Environment != b.Environment || a.Type != b.Type ||
		!same(a.DataClassification, b.DataClassification) || !same(a.CompensatingControls, b.CompensatingControls) || !mapsEqual(a.Attributes, b.Attributes)
}

func mapsEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}
