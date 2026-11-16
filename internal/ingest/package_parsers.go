package ingest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/integrations"
	"rampart/internal/integrations/mapping"
)

// parserSet is the built-in parsers plus the parser packages a tenant installed (IntegrationPackage, kind parser,
// runtime mapping; docs/19 §4, docs/16 D98). A tenant's package parses only that tenant's uploads. A built-in
// parser wins a tie and owns its name, so a package cannot take over a format Rampart already reads.
type parserSet struct {
	registry *integrations.Registry
	store    any

	mu    sync.Mutex
	cache map[string]cachedParser
}

type cachedParser struct {
	updated time.Time
	parser  integrations.ParserContract
}

func newParserSet(registry *integrations.Registry, store any) *parserSet {
	return &parserSet{registry: registry, store: store, cache: map[string]cachedParser{}}
}

// tenant returns the tenant's installed, valid parser packages. A package that does not compile is skipped: the
// operator already marked it Ready=False with its error.
func (s *parserSet) tenant(ctx context.Context, tenantID uuid.UUID) []integrations.ParserContract {
	pkgs, ok := s.store.(domain.IntegrationPackages)
	if !ok || tenantID == uuid.Nil {
		return nil
	}
	list, err := pkgs.ListIntegrationPackages(ctx, tenantID)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []integrations.ParserContract
	for _, p := range list {
		if p.Kind != "parser" || p.Error != "" {
			continue
		}
		key := tenantID.String() + "/" + p.Name
		if c, ok := s.cache[key]; ok && c.updated.Equal(p.UpdatedAt) {
			out = append(out, c.parser)
			continue
		}
		mp, err := mapping.NewParserFromSpec(p.Name, p.Spec)
		if err != nil {
			continue
		}
		s.cache[key] = cachedParser{updated: p.UpdatedAt, parser: mp}
		out = append(out, mp)
	}
	return out
}

// formatAliases are the names the documents use for a built-in parser whose id differs (docs/04 acceptedFormats).
var formatAliases = map[string]string{"generic": "genericjson", "gitlab-sast": "gitlab", "dependency-track": "dependencytrack"}

// byName finds the parser a client named: a built-in first ("trivy" or "builtin:trivy"), then the tenant's
// package ("pip-audit" or "mapping:pip-audit").
func (s *parserSet) byName(ctx context.Context, tenantID uuid.UUID, hint string) integrations.ParserContract {
	hint = strings.ToLower(strings.TrimSpace(hint))
	if hint == "" {
		return nil
	}
	if alias, ok := formatAliases[hint]; ok {
		hint = alias
	}
	if p, err := s.registry.GetParser("builtin:" + hint); err == nil {
		return p
	}
	if p, err := s.registry.GetParser(hint); err == nil {
		return p
	}
	want := "mapping:" + strings.TrimPrefix(hint, "mapping:")
	for _, p := range s.tenant(ctx, tenantID) {
		if strings.ToLower(p.Descriptor().ID) == want {
			return p
		}
	}
	return nil
}

// detect picks the parser that recognises the head best, over the built-ins and the tenant's packages.
func (s *parserSet) detect(ctx context.Context, tenantID uuid.UUID, head []byte, filename, contentType string) (integrations.ParserContract, int) {
	best, score := s.registry.DetectParser(head, filename, contentType)
	for _, p := range s.tenant(ctx, tenantID) {
		if sc := p.Detect(head, filename, contentType); sc > score {
			best, score = p, sc
		}
	}
	return best, score
}

// formatMismatch says when a report is of another format than the parser the client named. A parser that scores
// 0 on the head says "this is not mine" (the Trivy parser reads SARIF as nothing, Detect returns 0 for it), and
// another parser that recognises the head with confidence says what it is. Without this check, the wrong parser
// walks the file, finds no record and reports a clean scan, and the close step then closes the real findings.
func (s *parserSet) formatMismatch(ctx context.Context, tenantID uuid.UUID, named integrations.ParserContract, head []byte, filename, contentType string) (integrations.ParserContract, bool) {
	if named == nil || len(head) == 0 || named.Detect(head, filename, contentType) > 0 {
		return nil, false
	}
	best, score := s.detect(ctx, tenantID, head, filename, contentType)
	if best == nil || score < 40 || best.Descriptor().ID == named.Descriptor().ID {
		return nil, false
	}
	return best, true
}

// mismatchDetail is the message of a format mismatch: what the client said, what the file looks like.
func mismatchDetail(named, actual integrations.ParserContract) string {
	return fmt.Sprintf("the file is not a %s report: it looks like %s. Send it with format=%s, or leave format empty to detect it",
		named.Descriptor().Name, actual.Descriptor().Name, strings.TrimPrefix(actual.Descriptor().ID, "builtin:"))
}
