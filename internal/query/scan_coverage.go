package query

import (
	"sort"
	"strings"
	"time"

	"rampart/internal/compliance"
	"rampart/internal/domain"
)

// CategoryCoverage is one kind of scan on the application page: which scanners ran it, when last, and what it
// left open (docs/16 D101). It answers what the "radar" of other ASPMs answers, which kinds of testing an
// application has and which it lacks, as a row a reader can read exactly.
type CategoryCoverage struct {
	Category string         `json:"category"`
	Scanners []string       `json:"scanners"`
	LastScan *time.Time     `json:"last_scan,omitempty"`
	Open     map[string]int `json:"open"`
}

// coverageCategories are the kinds of testing every application is read against, in a fixed order so a gap
// is always in the same place.
var coverageCategories = []string{"sast", "sca", "secret", "iac", "container", "dast", "cspm"}

// scanCoverage folds the per-asset, per-scanner coverage into one row per category. A scanner family counts for
// the categories compliance.FamilyCategories gives it, so this page and the compliance page agree on what was
// assessed. A family Rampart does not classify (a generic upload, a parser package) counts for the categories of
// the findings it produced.
func scanCoverage(d domain.AppDetail, findingFamilies map[string][]string) []CategoryCoverage {
	rows := map[string]*CategoryCoverage{}
	get := func(cat string) *CategoryCoverage {
		if rows[cat] == nil {
			rows[cat] = &CategoryCoverage{Category: cat, Scanners: []string{}, Open: map[string]int{}}
		}
		return rows[cat]
	}
	for _, c := range coverageCategories {
		get(c)
	}
	for _, c := range d.Coverage {
		for _, cat := range compliance.CategoriesOf(c.Scanner, findingFamilies) {
			if cat == "compliance" {
				cat = "cspm" // a cluster or cloud benchmark
			}
			r := get(cat)
			if !containsStr(r.Scanners, c.Scanner) {
				r.Scanners = append(r.Scanners, c.Scanner)
			}
			if t := c.LastScan; r.LastScan == nil || t.After(*r.LastScan) {
				r.LastScan = &t
			}
		}
	}
	for cat, bands := range d.OpenByCategory {
		if cat == "secrets" {
			cat = "secret"
		}
		r := get(cat)
		for b, n := range bands {
			r.Open[b] += n
		}
	}
	out := make([]CategoryCoverage, 0, len(rows))
	for _, c := range coverageCategories {
		sort.Strings(rows[c].Scanners)
		out = append(out, *rows[c])
		delete(rows, c)
	}
	var rest []string
	for c := range rows {
		rest = append(rest, c)
	}
	sort.Strings(rest)
	for _, c := range rest { // license, supply chain…: shown only when something produced them
		if rows[c].LastScan != nil || len(rows[c].Open) > 0 {
			sort.Strings(rows[c].Scanners)
			out = append(out, *rows[c])
		}
	}
	return out
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if strings.EqualFold(v, x) {
			return true
		}
	}
	return false
}
