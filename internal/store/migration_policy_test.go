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
//
// One more exemption exists for a change the check cannot tell is safe, such as widening a CHECK constraint (the old
// binary never writes the new value): `-- expand-safe: <why>` with a reason of at least ten characters. The marker
// without a reason does not count.
var (
	bannedInExpandOnly = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bDROP\s+(TABLE|COLUMN|CONSTRAINT|INDEX|POLICY|TYPE|FUNCTION|VIEW)\b`),
		regexp.MustCompile(`(?i)\bRENAME\b`),
		regexp.MustCompile(`(?i)\bALTER\s+COLUMN\b[^;]*\b(SET\s+NOT\s+NULL|TYPE)\b`),
		regexp.MustCompile(`(?i)\bTRUNCATE\b`),
		regexp.MustCompile(`(?i)\bREVOKE\b`),
	}
	expandSafeMarker = regexp.MustCompile(`(?m)^--[ \t]*expand-safe:[ \t]*(\S.{9,})$`)
)

// expandOnlyProblems returns what is wrong with the Up part of one migration (the Down part is for a rollback).
func expandOnlyProblems(name, sql string) []string {
	up := sql
	if i := strings.Index(up, "-- +goose Down"); i >= 0 {
		up = up[:i]
	}
	if strings.Contains(up, "-- contract:") {
		return nil // the second half of a two-release change, said so
	}
	if expandSafeMarker.MatchString(up) {
		return nil // judged safe for the old binary, with the reason written down
	}
	var out []string
	// a new NOT NULL column without a default breaks the old binary's INSERT
	for _, stmt := range strings.Split(up, ";") {
		u := strings.ToUpper(stmt)
		if strings.Contains(u, "ADD COLUMN") && strings.Contains(u, "NOT NULL") && !strings.Contains(u, "DEFAULT") {
			out = append(out, name+" adds a NOT NULL column with no default (D124): "+strings.TrimSpace(stmt))
		}
	}
	for _, re := range bannedInExpandOnly {
		if m := re.FindString(up); m != "" {
			out = append(out, name+" is not expand-only (D124): "+strings.TrimSpace(m)+". Make it in two releases and mark the second with a `-- contract:` comment, or say why it is safe with `-- expand-safe: <why>`.")
		}
	}
	return out
}

func TestMigrationsAreExpandOnly(t *testing.T) {
	files, err := filepath.Glob("migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations: %v %d", err, len(files))
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
		for _, p := range expandOnlyProblems(filepath.Base(f), string(raw)) {
			t.Error(p)
		}
	}
}

func TestExpandSafeMarker(t *testing.T) {
	bad := "-- +goose Up\nALTER TABLE t DROP CONSTRAINT IF EXISTS c;\n"
	if len(expandOnlyProblems("x.sql", bad)) == 0 {
		t.Fatal("a DROP CONSTRAINT without a marker must be refused")
	}
	withReason := "-- +goose Up\n-- expand-safe: widens a CHECK; the old binary never writes the new kind\nALTER TABLE t DROP CONSTRAINT IF EXISTS c;\n"
	if p := expandOnlyProblems("x.sql", withReason); len(p) != 0 {
		t.Fatalf("a marker with a reason is accepted: %v", p)
	}
	noReason := "-- +goose Up\n-- expand-safe:\nALTER TABLE t DROP CONSTRAINT IF EXISTS c;\n"
	if len(expandOnlyProblems("x.sql", noReason)) == 0 {
		t.Fatal("a marker with no reason must not count")
	}
	short := "-- +goose Up\n-- expand-safe: ok\nALTER TABLE t DROP CONSTRAINT IF EXISTS c;\n"
	if len(expandOnlyProblems("x.sql", short)) == 0 {
		t.Fatal("a one-word reason must not count")
	}
	inDown := "-- +goose Up\nCREATE TABLE a(x int);\n-- +goose Down\nDROP TABLE a;\n"
	if p := expandOnlyProblems("x.sql", inDown); len(p) != 0 {
		t.Fatalf("the Down part is not checked: %v", p)
	}
}
