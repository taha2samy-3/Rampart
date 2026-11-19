package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"rampart/internal/domain"
	"rampart/internal/integrations"
	"rampart/internal/integrations/lua"
	"rampart/internal/integrations/mapping"
	"rampart/internal/integrations/wasm"
	"rampart/internal/sbom"
)

// parserSet is the parsers a process was given (the registry), the parsers installed for the whole cluster (ClusterParser,
// ClusterSBOMParser) and the tenant's own (Parser, IntegrationPackage; docs/19 §4, docs/29). Nothing is compiled in: every
// parser comes from outside.
// Precedence by name: the registry, then ClusterParser, then the tenant's Parser. A name an administrator installed for the
// cluster is reserved: a tenant's parser of the same name never takes its uploads (it did the same when the shipped
// parsers were compiled in, and a tenant's mapping parser must not be able to misroute a standard scanner).
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

// tenantRuntimeAllowed reports whether a parser stored for a tenant uses a runtime a tenant may use. A row written before
// the check existed, or by a path that did not run it, is not used.
func tenantRuntimeAllowed(raw []byte) bool {
	var head struct {
		Runtime string `json:"runtime" yaml:"runtime"`
		Spec    struct {
			Runtime string `json:"runtime" yaml:"runtime"`
		} `json:"spec" yaml:"spec"`
	}
	if json.Unmarshal(raw, &head) != nil || (head.Runtime == "" && head.Spec.Runtime == "") {
		_ = yaml.Unmarshal(raw, &head)
	}
	rt := head.Runtime
	if rt == "" {
		rt = head.Spec.Runtime
	}
	return rt == "" || rt == "mapping" || rt == "declarative"
}

// compileParser builds a stored parser. A cluster-scoped wasm or lua parser is built by integrations.NewInstalledParser, the
// one constructor every installed parser goes through, so it has the same id and detection wherever it came from.
func (s *parserSet) compileParser(name string, raw []byte, cluster bool) (integrations.ParserContract, error) {
	var meta struct {
		Kind string `json:"kind" yaml:"kind"`
	}
	_ = json.Unmarshal(raw, &meta)
	if meta.Kind == "" {
		_ = yaml.Unmarshal(raw, &meta)
	}
	if meta.Kind == "ClusterSBOMParser" || meta.Kind == "SBOMParser" {
		return sbom.NewWasmSBOMParserFromSpec(name, raw, nil)
	}
	var head struct {
		Runtime string `json:"runtime" yaml:"runtime"`
		Native  string `json:"native" yaml:"native"`
		Spec    struct {
			Runtime string `json:"runtime" yaml:"runtime"`
			Native  string `json:"native" yaml:"native"`
		} `json:"spec" yaml:"spec"`
	}
	_ = json.Unmarshal(raw, &head)
	if head.Runtime == "" && head.Spec.Runtime == "" {
		_ = yaml.Unmarshal(raw, &head)
	}

	runtime := head.Runtime
	if runtime == "" {
		runtime = head.Spec.Runtime
	}
	native := head.Native
	if native == "" {
		native = head.Spec.Native
	}

	if cluster && (runtime == "wasm" || runtime == "lua") {
		return integrations.NewInstalledParser(name, raw)
	}
	switch runtime {
	case "native":
		engine := native
		if engine == "" {
			engine = name
		}
		if p, err := s.registry.GetParser("builtin:" + engine); err == nil {
			return p, nil
		}
		if p, err := s.registry.GetParser(engine); err == nil {
			return p, nil
		}
		return nil, fmt.Errorf("native parser engine %q not registered", engine)
	case "lua":
		return lua.NewLuaParserFromSpec(name, raw)
	case "wasm":
		return wasm.NewWasmParserFromSpec(name, raw, nil)
	case "mapping", "":
		return mapping.NewParserFromSpec(name, raw)
	default:
		return nil, fmt.Errorf("unsupported parser runtime %q", runtime)
	}
}

// tenantAndCluster returns the tenant's and cluster-wide installed, valid parsers.
func (s *parserSet) tenantAndCluster(ctx context.Context, tenantID uuid.UUID) (tenantOut []integrations.ParserContract, clusterOut []integrations.ParserContract) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Check ParserStore (PostgresStore or MemoryConfigStore)
	if pStore, ok := s.store.(domain.ParserStore); ok && tenantID != uuid.Nil {
		list, err := pStore.ListParsers(ctx, tenantID)
		if err == nil {
			for _, p := range list {
				if p.Error != "" {
					continue
				}
				if p.Origin == "tenant" && !tenantRuntimeAllowed(p.Spec) {
					continue // a tenant's parser is data (mapping); code and scripts are for ClusterParser (docs/34 F14)
				}
				key := p.Origin + "/" + tenantID.String() + "/" + p.Name
				if c, ok := s.cache[key]; ok && c.updated.Equal(p.UpdatedAt) {
					if p.Origin == "tenant" {
						tenantOut = append(tenantOut, c.parser)
					} else {
						clusterOut = append(clusterOut, c.parser)
					}
					continue
				}
				cp, err := s.compileParser(p.Name, p.Spec, p.Origin != "tenant")
				if err != nil {
					continue
				}
				s.cache[key] = cachedParser{updated: p.UpdatedAt, parser: cp}
				if p.Origin == "tenant" {
					tenantOut = append(tenantOut, cp)
				} else {
					clusterOut = append(clusterOut, cp)
				}
			}
		}
	}

	// 2. Check legacy IntegrationPackages
	if pkgs, ok := s.store.(domain.IntegrationPackages); ok && tenantID != uuid.Nil {
		list, err := pkgs.ListIntegrationPackages(ctx, tenantID)
		if err == nil {
			for _, p := range list {
				if p.Kind != "parser" || p.Error != "" {
					continue
				}
				key := "pkg/" + tenantID.String() + "/" + p.Name
				if c, ok := s.cache[key]; ok && c.updated.Equal(p.UpdatedAt) {
					tenantOut = append(tenantOut, c.parser)
					continue
				}
				cp, err := s.compileParser(p.Name, p.Spec, false)
				if err != nil {
					continue
				}
				s.cache[key] = cachedParser{updated: p.UpdatedAt, parser: cp}
				tenantOut = append(tenantOut, cp)
			}
		}
	}

	return tenantOut, clusterOut
}

// formatAliases are the names the documents use for a built-in parser whose id differs (docs/04 acceptedFormats).
var formatAliases = map[string]string{"generic": "genericjson", "gitlab-sast": "gitlab"}

// byName finds the parser a client named: the registry first ("trivy" or "builtin:trivy"), then the cluster's parser, then the tenant's.
func (s *parserSet) byName(ctx context.Context, tenantID uuid.UUID, hint string) integrations.ParserContract {
	hint = strings.ToLower(strings.TrimSpace(hint))
	if hint == "" {
		return nil
	}
	if alias, ok := formatAliases[hint]; ok {
		hint = alias
	}

	// 1. The registry owns its names
	if p, err := s.registry.GetParser("builtin:" + hint); err == nil {
		return p
	}
	if p, err := s.registry.GetParser(hint); err == nil {
		return p
	}
	if p, err := s.registry.GetParser("builtin:sbom-" + hint); err == nil {
		return p
	}
	if p, err := s.registry.GetParser("sbom-" + hint); err == nil {
		return p
	}

	tenantParsers, clusterParsers := s.tenantAndCluster(ctx, tenantID)

	matchName := func(p integrations.ParserContract, target string) bool {
		id := strings.ToLower(p.Descriptor().ID)
		name := strings.ToLower(p.Descriptor().Name)
		return id == target ||
			id == "mapping:"+target ||
			id == "lua:"+target ||
			id == "wasm:"+target ||
			id == "builtin:"+target ||
			id == "builtin:sbom-"+target ||
			id == "sbom-"+target ||
			strings.TrimPrefix(id, "mapping:") == target ||
			strings.TrimPrefix(id, "lua:") == target ||
			strings.TrimPrefix(id, "wasm:") == target ||
			strings.TrimPrefix(id, "builtin:") == target ||
			strings.TrimPrefix(id, "builtin:sbom-") == target ||
			strings.TrimPrefix(id, "sbom-") == target ||
			strings.HasPrefix(name, target)
	}

	// 2. Cluster parsers: a name the administrator installed is reserved (see parserSet)
	for _, p := range clusterParsers {
		if matchName(p, hint) {
			return p
		}
	}

	// 3. Tenant parsers
	for _, p := range tenantParsers {
		if matchName(p, hint) {
			return p
		}
	}

	return nil
}

// parserName is the name a client sends in "parser" to select p: its id without the prefix that says where it came from.
func parserName(p integrations.ParserContract) string {
	id := strings.ToLower(p.Descriptor().ID)
	for _, prefix := range []string{"builtin:", "mapping:", "lua:", "wasm:"} {
		id = strings.TrimPrefix(id, prefix)
	}
	return strings.TrimPrefix(id, "sbom-")
}

// available lists the names a client may send in "parser": the built-in and default parsers, then the cluster and the
// tenant's own. It is what an error says when a name is not known, so the list is never a copy kept by hand.
func (s *parserSet) available(ctx context.Context, tenantID uuid.UUID) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p integrations.ParserContract) {
		if n := parserName(p); n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, d := range s.registry.ListParsers() {
		if p, err := s.registry.GetParser(d.ID); err == nil {
			add(p)
		}
	}
	tenantParsers, clusterParsers := s.tenantAndCluster(ctx, tenantID)
	for _, p := range clusterParsers {
		add(p)
	}
	for _, p := range tenantParsers {
		add(p)
	}
	sort.Strings(out)
	return out
}

// detect picks the parser that recognises the head best, with tie-break precedence: Built-in wins ties over packages.
func (s *parserSet) detect(ctx context.Context, tenantID uuid.UUID, head []byte, filename, contentType string) (integrations.ParserContract, int) {
	best, score := s.registry.DetectParser(head, filename, contentType)

	tenantParsers, clusterParsers := s.tenantAndCluster(ctx, tenantID)

	for _, p := range clusterParsers {
		if sc := p.Detect(head, filename, contentType); sc > score {
			best, score = p, sc
		}
	}

	for _, p := range tenantParsers {
		if sc := p.Detect(head, filename, contentType); sc > score {
			best, score = p, sc
		}
	}

	return best, score
}

// formatMismatch says when a report is of another format than the parser the client named.
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
