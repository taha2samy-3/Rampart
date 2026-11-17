package domain_test

import (
	"strings"
	"testing"

	"rampart/internal/domain"
)

func TestValidateTrackedRefs(t *testing.T) {
	long := strings.Repeat("a", 256)
	for name, c := range map[string]struct {
		refs []string
		ok   bool
	}{
		"nil":                {nil, true},
		"names":              {[]string{"main", "develop", "staging"}, true},
		"prefixes":           {[]string{"release/*", "hotfix-*", "*"}, true},
		"a tag":              {[]string{"v1.2.3"}, true},
		"empty entry":        {[]string{""}, false},
		"a space":            {[]string{"my branch"}, false},
		"a tab":              {[]string{"a\tb"}, false},
		"a middle wildcard":  {[]string{"re*lease"}, false},
		"a leading wildcard": {[]string{"*release"}, false},
		"too long":           {[]string{long}, false},
		"exactly 255":        {[]string{strings.Repeat("a", 255)}, true},
		"50 entries":         {make50("b", 50), true},
		"51 entries":         {make50("b", 51), false},
	} {
		if err := domain.ValidateTrackedRefs(c.refs); (err == nil) != c.ok {
			t.Errorf("%s: ok=%v, got %v", name, c.ok, err)
		}
	}
}

func make50(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = prefix + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
	}
	return out
}

func TestWithTrackedRefs(t *testing.T) {
	base := &domain.IngestionPolicy{MinimumSeverity: "low"}
	got := domain.WithTrackedRefs(base, []string{"develop"})
	if got == base || got.MinimumSeverity != "low" || len(got.TrackedRefs) != 1 {
		t.Fatalf("a copy with the refs and the rest of the policy: %+v", got)
	}
	if len(base.TrackedRefs) != 0 {
		t.Error("the policy it was given must not change")
	}
	if domain.WithTrackedRefs(base, nil) != base || domain.WithTrackedRefs(nil, nil) != nil {
		t.Error("no refs: the policy is returned as it is")
	}
	if p := domain.WithTrackedRefs(nil, []string{"*"}); p == nil || p.TrackedRefs[0] != "*" {
		t.Errorf("refs with no policy: %+v", p)
	}
}
