package domain

import (
	"bufio"
	"path/filepath"
	"strings"
)

// CodeownerRule binds a file path pattern to owner email addresses or usernames (docs/21 §6.5).
type CodeownerRule struct {
	Pattern string
	Owners  []string
}

// Codeowners holds ordered rules parsed from a CODEOWNERS file.
type Codeowners struct {
	rules []CodeownerRule
}

// ParseCodeowners parses the contents of a CODEOWNERS file.
// Comments (#) and empty lines are ignored. Last matching rule wins.
func ParseCodeowners(content string) *Codeowners {
	var rules []CodeownerRule

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		pattern := fields[0]
		owners := fields[1:]

		rules = append(rules, CodeownerRule{
			Pattern: pattern,
			Owners:  owners,
		})
	}

	return &Codeowners{rules: rules}
}

// Match returns the owners for a given file path.
// Last matching rule in the file takes precedence.
func (c *Codeowners) Match(path string) []string {
	if c == nil || len(c.rules) == 0 {
		return nil
	}

	cleanPath := filepath.Clean(path)
	var matchedOwners []string

	for _, rule := range c.rules {
		if matchPattern(rule.Pattern, cleanPath) {
			matchedOwners = rule.Owners
		}
	}

	return matchedOwners
}

func matchPattern(pat, path string) bool {
	relPath := strings.TrimPrefix(path, "/")
	cleanPat := strings.TrimPrefix(pat, "/")

	if cleanPat == "*" {
		return true
	}

	// Direct match
	if matched, _ := filepath.Match(cleanPat, relPath); matched {
		return true
	}

	// Base filename match (e.g. *.go)
	if strings.HasPrefix(cleanPat, "*") {
		if matched, _ := filepath.Match(cleanPat, filepath.Base(relPath)); matched {
			return true
		}
	}

	// Directory prefix match
	if strings.HasSuffix(cleanPat, "/*") {
		dir := strings.TrimSuffix(cleanPat, "/*")
		if strings.HasPrefix(relPath, dir+"/") || relPath == dir {
			return true
		}
	}
	if strings.HasSuffix(cleanPat, "/") {
		dir := strings.TrimSuffix(cleanPat, "/")
		if strings.HasPrefix(relPath, dir+"/") || relPath == dir {
			return true
		}
	}

	return false
}
