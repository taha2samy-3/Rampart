package store

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// firstExpandOnly is the first migration held to the expand-only rule (docs/16 D124).
const firstExpandOnly = 46

// A release upgrades in this order: the migrate job runs first (a pre-upgrade hook, D4), then the new pods start, once
// their init container sees the schema; until then the old pods keep serving on the new schema. So every migration
// must leave the previous binary working: it may add (tables, columns with a default or null, indexes, policies) and
// must not remove, rename, or tighten what the previous version reads or writes. A change of that kind is made in two
// releases (add and switch, then remove), and the second migration says so with a `-- contract:` comment.
func TestMigrationsAreExpandOnly(t *testing.T) {
	files, err := filepath.Glob("migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations: %v %d", err, len(files))
	}
	banned := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bDROP\s+(TABLE|COLUMN|CONSTRAINT|INDEX|POLICY|TYPE|FUNCTION|VIEW)\b`),
		regexp.MustCompile(`(?i)\bRENAME\b`),
		regexp.MustCompile(`(?i)\bALTER\s+COLUMN\b[^;]*\b(SET\s+NOT\s+NULL|TYPE)\b`),
		regexp.MustCompile(`(?i)\bTRUNCATE\b`),
		regexp.MustCompile(`(?i)\bREVOKE\b`),
	}
	for _, f := range files {
		n, err := strconv.Atoi(filepath.Base(f)[:5])
		if err != nil || n < firstExpandOnly {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		up := string(raw)
		if i := strings.Index(up, "-- +goose Down"); i >= 0 {
			up = up[:i] // the Down section is for a rollback, not for an upgrade
		}
		if strings.Contains(up, "-- contract:") {
			continue // the second half of a two-release change, said so
		}
		// a new NOT NULL column without a default breaks the old binary's INSERT
		for _, stmt := range strings.Split(up, ";") {
			u := strings.ToUpper(stmt)
			if strings.Contains(u, "ADD COLUMN") && strings.Contains(u, "NOT NULL") && !strings.Contains(u, "DEFAULT") {
				t.Errorf("%s adds a NOT NULL column with no default (D124): %q", filepath.Base(f), strings.TrimSpace(stmt))
			}
		}
		for _, re := range banned {
			if m := re.FindString(up); m != "" {
				t.Errorf("%s is not expand-only (D124): %q. Make it in two releases and mark the second with a `-- contract:` comment.", filepath.Base(f), strings.TrimSpace(m))
			}
		}
	}
}
