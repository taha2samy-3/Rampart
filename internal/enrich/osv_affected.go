package enrich

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"

	"rampart/internal/normalize"
)

// An OSV record names what it affects as nested JSON: affected[].package, affected[].ranges[].events and
// affected[].versions. The matcher asks "which advisories name this package", which that shape cannot answer, so the
// feed writes one row per interval of every package into vulnerability_affected (migration 00050) as well as keeping the
// record in vulnerability.affected.
//
// The model is the OSV schema's (https://ossf.github.io/osv-schema/): a range is an ordered list of events,
// `introduced` opens an interval (the version is included; "0" is the first version), `fixed` closes it (the version is
// excluded), `last_affected` closes it (the version is included), `limit` bounds an interval that has no end. A package
// is affected by a version that lies in one interval or is in its explicit `versions` list.

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Purl      string `json:"purl"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced"`
			Fixed        string `json:"fixed"`
			LastAffected string `json:"last_affected"`
			Limit        string `json:"limit"`
		} `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}

// osvSeverity is an element of the severity array of an OSV record: a CVSS vector.
type osvSeverity struct {
	Type  string `json:"type"` // CVSS_V2, CVSS_V3, CVSS_V4
	Score string `json:"score"`
}

// Range types of vulnerability_affected.
const (
	rangeSemver    = "SEMVER"
	rangeEcosystem = "ECOSYSTEM"
	rangeVersions  = "VERSIONS"
)

// affectedRow is one row of vulnerability_affected, without the ids of the record.
type affectedRow struct {
	Ecosystem, Name, NameNormalised, PurlBase string
	RangeType                                 string
	Introduced, Fixed, LastAffected, Limit    string
	Versions                                  []string
}

// affectedRows turns the affected array of a record into rows. A GIT range is not stored: its events are commit
// hashes, which a component with a version cannot be compared to. An element without a package name is skipped.
func affectedRows(raw json.RawMessage) []affectedRow {
	if len(raw) == 0 {
		return nil
	}
	var elems []osvAffected
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil
	}
	var rows []affectedRow
	seen := map[string]bool{}
	add := func(r affectedRow) {
		key := strings.Join([]string{r.Ecosystem, r.Name, r.RangeType, r.Introduced, r.Fixed, r.LastAffected, r.Limit, strings.Join(r.Versions, "\x00")}, "\x01")
		if !seen[key] {
			seen[key] = true
			rows = append(rows, r)
		}
	}
	for _, e := range elems {
		name := strings.TrimSpace(e.Package.Name)
		eco := strings.TrimSpace(e.Package.Ecosystem)
		if name == "" || eco == "" {
			// A record that names a purl only still identifies a package.
			if e.Package.Purl == "" {
				continue
			}
		}
		base := PurlBaseOf(eco, name, e.Package.Purl)
		norm := NormalisePackageName(eco, name)
		mk := func(rt string) affectedRow {
			return affectedRow{Ecosystem: eco, Name: name, NameNormalised: norm, PurlBase: base, RangeType: rt}
		}
		for _, rg := range e.Ranges {
			rt := strings.ToUpper(rg.Type)
			if rt != rangeSemver && rt != rangeEcosystem {
				continue
			}
			var open *affectedRow
			closeWith := func(fixed, last string) {
				if open == nil {
					z := mk(rt)
					z.Introduced = "0"
					open = &z
				}
				open.Fixed, open.LastAffected = fixed, last
				add(*open)
				open = nil
			}
			for _, ev := range rg.Events {
				switch {
				case ev.Introduced != "":
					if open != nil {
						add(*open) // an interval that was never closed
					}
					r := mk(rt)
					r.Introduced = ev.Introduced
					open = &r
				case ev.Fixed != "":
					closeWith(ev.Fixed, "")
				case ev.LastAffected != "":
					closeWith("", ev.LastAffected)
				case ev.Limit != "":
					if open != nil {
						open.Limit = ev.Limit
					}
				}
			}
			if open != nil {
				add(*open)
			}
		}
		if len(e.Versions) > 0 {
			r := mk(rangeVersions)
			r.Versions = append([]string(nil), e.Versions...)
			add(r)
		}
	}
	return rows
}

// NormalisePackageName is the ecosystem's rule for "the same package", so a component named `Django` finds the
// advisory for `django`. The rules follow each registry: PyPI names are compared with runs of - _ . as one - and in
// lower case (PEP 503), npm, NuGet and Packagist names are case-insensitive, crates.io treats - and _ as one. Go and
// Maven names are case-sensitive and keep their case. An ecosystem with a release suffix (Debian:12) is judged by its
// base. The matcher must call this with the same arguments (docs/35 E3).
func NormalisePackageName(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	base := ecosystem
	if i := strings.IndexByte(base, ':'); i >= 0 {
		base = base[:i]
	}
	switch strings.ToLower(base) {
	case "pypi":
		var b strings.Builder
		prevSep := false
		for _, r := range strings.ToLower(name) {
			if r == '-' || r == '_' || r == '.' {
				if !prevSep {
					b.WriteByte('-')
				}
				prevSep = true
				continue
			}
			prevSep = false
			b.WriteRune(r)
		}
		return b.String()
	case "npm", "nuget", "packagist":
		return strings.ToLower(name)
	case "crates.io":
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	}
	return name
}

// purlTypes maps an OSV ecosystem to the Package URL type of its packages.
var purlTypes = map[string]string{
	"go": "golang", "npm": "npm", "pypi": "pypi", "maven": "maven", "crates.io": "cargo", "nuget": "nuget",
	"packagist": "composer", "rubygems": "gem", "hex": "hex", "pub": "pub", "swifturl": "swift", "cran": "cran",
}

// PurlBaseOf returns pkg:type/namespace/name for a package, the form the SBOM components carry as purl_base, or "".
// A purl in the record wins; otherwise it is built from the ecosystem and the name when the ecosystem has a purl type.
func PurlBaseOf(ecosystem, name, purl string) string {
	if purl != "" {
		if _, base, err := normalize.CanonicalPURL(purl); err == nil && base != "" {
			return base
		}
	}
	t := purlTypes[strings.ToLower(ecosystem)]
	if t == "" || name == "" {
		return ""
	}
	ns, n := "", name
	switch t {
	case "maven": // group:artifact
		if g, a, ok := strings.Cut(name, ":"); ok {
			ns, n = g, a
		}
	case "npm": // @scope/name
		if strings.HasPrefix(name, "@") {
			if s, rest, ok := strings.Cut(name, "/"); ok {
				ns, n = s, rest
			}
		}
	case "golang", "composer", "swift": // the last path element is the name, the rest the namespace
		if i := strings.LastIndexByte(name, '/'); i > 0 {
			ns, n = name[:i], name[i+1:]
		}
	}
	p := packageurl.NewPackageURL(t, ns, n, "", nil, "").ToString()
	if _, base, err := normalize.CanonicalPURL(p); err == nil && base != "" {
		return base
	}
	return ""
}

// parseWithdrawn reads the `withdrawn` time of a record; nil when there is none or it cannot be read.
func parseWithdrawn(v string) *time.Time {
	if v == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return &t
	}
	return nil
}

// osvCVSS turns the severity array of a record into the entries of vulnerability.cvss. Only a vector is given, never a
// score, so score is left out: the feed does not compute one (there is no CVSS calculator in Rampart yet).
func osvCVSS(sev []osvSeverity, source string) (entries []map[string]any, bestVector string) {
	var versions = map[string]string{"CVSS_V2": "2.0", "CVSS_V3": "3.x", "CVSS_V4": "4.0"}
	order := []string{"CVSS_V4", "CVSS_V3", "CVSS_V2"}
	sort.SliceStable(sev, func(i, j int) bool { return rank(order, sev[i].Type) < rank(order, sev[j].Type) })
	for _, s := range sev {
		v := strings.TrimSpace(s.Score)
		ver, ok := versions[strings.ToUpper(s.Type)]
		if !ok || !strings.HasPrefix(strings.ToUpper(v), "CVSS:") && ver != "2.0" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(v), "CVSS:3.") {
			ver = strings.TrimPrefix(strings.SplitN(v, "/", 2)[0], "CVSS:")
		}
		entries = append(entries, map[string]any{"version": ver, "vector": v, "source": source})
		if bestVector == "" {
			bestVector = v
		}
	}
	return entries, bestVector
}

func rank(order []string, t string) int {
	for i, o := range order {
		if strings.EqualFold(o, t) {
			return i
		}
	}
	return len(order)
}
