package domain

import (
	"testing"
)

func TestCodeowners_ParsingAndMatching(t *testing.T) {
	sample := `
# Global default
*       @global-team

# Specific directories
/docs/* docs@example.com
/apps/auth/ sec-team@example.com @auth-lead

# Specific extension
*.go    backend@example.com
`

	co := ParseCodeowners(sample)
	if co == nil || len(co.rules) != 4 {
		t.Fatalf("expected 4 rules, got %+v", co)
	}

	// 1. Root file
	owners := co.Match("README.md")
	if len(owners) != 1 || owners[0] != "@global-team" {
		t.Errorf("README.md owners = %v", owners)
	}

	// 2. Go file in root
	owners = co.Match("main.go")
	if len(owners) != 1 || owners[0] != "backend@example.com" {
		t.Errorf("main.go owners = %v", owners)
	}

	// 3. Docs file
	owners = co.Match("/docs/guide.md")
	if len(owners) != 1 || owners[0] != "docs@example.com" {
		t.Errorf("guide.md owners = %v", owners)
	}

	// 4. Auth service
	owners = co.Match("/apps/auth/login.py")
	if len(owners) != 2 || owners[0] != "sec-team@example.com" || owners[1] != "@auth-lead" {
		t.Errorf("auth owners = %v", owners)
	}
}
