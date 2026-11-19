package integrations

import (
	"context"
	"fmt"
	"io"
	"iter"
	"sync"

	"gopkg.in/yaml.v3"

	"rampart/internal/config/parsers"
	"rampart/internal/domain"
)

var (
	// LuaParserLoader is registered by internal/integrations/lua on init.
	LuaParserLoader func(name string, raw []byte) (ParserContract, error)

	// WasmParserLoader is registered by internal/integrations/wasm on init.
	WasmParserLoader func(name string, raw []byte) (ParserContract, error)
)

// defaultParserAdapter wraps a parser contract with lazy runtime loading and declarative detection.
type defaultParserAdapter struct {
	name     string
	raw      []byte
	runtime  string
	desc     Descriptor
	detect   domain.DetectSpec
	parser   ParserContract
	loadOnce sync.Once
}

func (a *defaultParserAdapter) getParser() ParserContract {
	a.loadOnce.Do(func() {
		if a.runtime == "lua" && LuaParserLoader != nil {
			a.parser, _ = LuaParserLoader(a.name, a.raw)
		} else if a.runtime == "wasm" && WasmParserLoader != nil {
			a.parser, _ = WasmParserLoader(a.name, a.raw)
		}
	})
	return a.parser
}

func (a *defaultParserAdapter) Descriptor() Descriptor {
	return a.desc
}

func (a *defaultParserAdapter) Detect(head []byte, filename string, contentType string) int {
	return a.detect.Score(head, filename, contentType)
}

func (a *defaultParserAdapter) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	p := a.getParser()
	if p != nil {
		return p.Parse(ctx, r, pc)
	}
	return func(yield func(domain.RawFinding, error) bool) {
		yield(domain.RawFinding{}, fmt.Errorf("runtime not loaded for %s", a.desc.ID))
	}
}

// DefaultRegistry creates an integration registry pre-loaded with the built-in ClusterParser definitions.
func DefaultRegistry() *Registry {
	reg := NewRegistry()

	defaultParsers, err := parsers.ListDefaultParsers()
	if err != nil {
		return reg
	}

	for _, pObj := range defaultParsers {
		name := pObj.Name
		var manifest struct {
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Spec struct {
				Runtime     string            `yaml:"runtime"`
				Category    string            `yaml:"category"`
				Description string            `yaml:"description"`
				Version     string            `yaml:"version"`
				Detect      domain.DetectSpec `yaml:"detect"`
			} `yaml:"spec"`
		}

		if err := yaml.Unmarshal(pObj.Spec, &manifest); err != nil {
			continue
		}

		desc := Descriptor{
			ID:           "builtin:" + name,
			Name:         name + " Parser",
			Kind:         KindParser,
			Category:     manifest.Spec.Category,
			Version:      manifest.Spec.Version,
			SupportLevel: SupportBuiltin,
			Description:  manifest.Spec.Description,
		}

		adapter := &defaultParserAdapter{
			name:    name,
			raw:     pObj.Spec,
			runtime: manifest.Spec.Runtime,
			desc:    desc,
			detect:  manifest.Spec.Detect,
		}
		_ = reg.RegisterParser(adapter)
	}

	return reg
}
