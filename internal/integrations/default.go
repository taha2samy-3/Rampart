package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"rampart/internal/domain"
)

var (
	// LuaParserLoader is registered by internal/integrations/lua on init.
	LuaParserLoader func(name string, raw []byte) (ParserContract, error)

	// WasmParserLoader is registered by internal/integrations/wasm on init.
	WasmParserLoader func(name string, raw []byte) (ParserContract, error)

	// SBOMParserLoader is registered by internal/sbom on init: it builds the reader a ClusterSBOMParser describes.
	SBOMParserLoader func(name string, raw []byte) (ParserContract, error)
)

// defaultParserAdapter wraps a parser contract with lazy runtime loading and declarative detection.
type defaultParserAdapter struct {
	name     string
	raw      []byte
	runtime  string
	desc     Descriptor
	detect   domain.DetectSpec
	parser   ParserContract
	loadErr  error // why the runtime could not be built: a missing module, a spec the runtime refuses
	loadOnce sync.Once
}

func (a *defaultParserAdapter) getParser() ParserContract {
	a.loadOnce.Do(func() {
		var p ParserContract
		var err error
		switch {
		case a.runtime == "lua" && LuaParserLoader != nil:
			p, err = LuaParserLoader(a.name, a.raw)
		case a.runtime == "wasm" && WasmParserLoader != nil:
			p, err = WasmParserLoader(a.name, a.raw)
		default:
			err = fmt.Errorf("no %s runtime is linked into this process", a.runtime)
		}
		if err != nil {
			a.loadErr = err
			return
		}
		a.parser = p
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
		yield(domain.RawFinding{}, fmt.Errorf("runtime not loaded for %s: %w", a.desc.ID, a.loadErr))
	}
}

// installedSpec is what an installed parser says about itself.
type installedSpec struct {
	Runtime     string            `yaml:"runtime"`
	Format      string            `yaml:"format"`
	Category    string            `yaml:"category"`
	Description string            `yaml:"description"`
	Version     string            `yaml:"version"`
	Detect      domain.DetectSpec `yaml:"detect"`
}

// parseInstalled reads a ClusterParser or ClusterSBOMParser given as the whole resource (as a file has it) or as its spec
// alone (as the control plane stores it). It returns the kind the resource states, empty for a spec alone.
func parseInstalled(raw []byte) (kind string, spec installedSpec, err error) {
	var whole struct {
		Kind string        `yaml:"kind"`
		Spec installedSpec `yaml:"spec"`
	}
	if err = yaml.Unmarshal(raw, &whole); err != nil {
		return "", installedSpec{}, err
	}
	if whole.Spec.Runtime != "" || whole.Spec.Format != "" {
		return whole.Kind, whole.Spec, nil
	}
	if err = yaml.Unmarshal(raw, &spec); err != nil {
		return "", installedSpec{}, err
	}
	return whole.Kind, spec, nil
}

// wholeManifest returns a ClusterParser as the whole resource. The control plane keeps the spec alone, and the WASM and Lua
// runtimes read a resource (metadata.name and spec): handed a spec alone they find nothing in it and refuse it. A resource is
// returned as it is.
func wholeManifest(name string, raw []byte) ([]byte, error) {
	var generic map[string]any
	if err := yaml.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	if _, whole := generic["spec"]; whole {
		return raw, nil
	}
	return json.Marshal(map[string]any{
		"apiVersion": "rampart.aspm.dev/v1alpha1", "kind": "ClusterParser",
		"metadata": map[string]any{"name": name}, "spec": generic,
	})
}

// NewInstalledParser builds the report parser a ClusterParser resource describes, from the resource or from its spec alone.
// Every installed parser is built here, whether it came from the control plane or from a directory, so each one has the
// same id (builtin:<name>: the id stored in runs and read by the compliance report and the gate), descriptor and detection.
// "builtin" says it was installed for the whole cluster; it does not say it is compiled in: nothing is.
func NewInstalledParser(name string, raw []byte) (ParserContract, error) {
	raw, err := wholeManifest(name, raw)
	if err != nil {
		return nil, err
	}
	_, spec, err := parseInstalled(raw)
	if err != nil {
		return nil, err
	}
	if spec.Runtime != "wasm" && spec.Runtime != "lua" {
		return nil, fmt.Errorf("installed parser %q: runtime %q is not wasm or lua", name, spec.Runtime)
	}
	return &defaultParserAdapter{
		name:    name,
		raw:     raw,
		runtime: spec.Runtime,
		desc: Descriptor{
			ID:           "builtin:" + name,
			Name:         name + " Parser",
			Kind:         KindParser,
			Category:     spec.Category,
			Version:      spec.Version,
			SupportLevel: SupportBuiltin,
			Description:  spec.Description,
		},
		detect: spec.Detect,
	}, nil
}

// InstalledDescriptor says what an installed parser is without building it: no module is read. It gives what the parser built by
// NewInstalledParser, or by the SBOM loader for a ClusterSBOMParser, gives (a test holds the two together).
func InstalledDescriptor(name string, raw []byte) (Descriptor, error) {
	kind, spec, err := parseInstalled(raw)
	if err != nil {
		return Descriptor{}, err
	}
	if kind == "ClusterSBOMParser" {
		format := spec.Format
		if format == "" {
			format = strings.TrimPrefix(name, domain.SBOMParserNamePrefix)
		}
		return Descriptor{ID: "builtin:sbom-" + format, Name: format + " SBOM Parser", Kind: KindParser, Category: "sca",
			Version: spec.Version, SupportLevel: SupportBuiltin, Description: spec.Description}, nil
	}
	p, err := NewInstalledParser(name, raw)
	if err != nil {
		return Descriptor{}, err
	}
	return p.Descriptor(), nil
}

// ParsersDirEnv names the directory of parser manifests (ClusterParser and ClusterSBOMParser, as YAML or JSON) that a process
// installs at start. It is for a deployment with no control plane (Compose, one binary) and for tests: where the operator runs,
// the same resources reach the server through the database. The directory is read like RAMPART_WASM_DIR, which holds the
// modules these manifests name.
const ParsersDirEnv = "RAMPART_PARSERS_DIR"

// LoadManifestDir installs every ClusterParser and ClusterSBOMParser manifest under dir into reg and returns how many it
// installed. A manifest that cannot be installed is reported in the error (every one, not the first) and does not stop the
// others. Hidden entries are skipped: a mounted ConfigMap keeps its real files under "..data" and links to them.
func LoadManifestDir(reg *Registry, dir string) (int, error) {
	var problems []error
	n := 0
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".") && path != dir {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if d.IsDir() || (ext != ".yaml" && ext != ".yml" && ext != ".json") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			problems = append(problems, err)
			return nil
		}
		var head struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
		}
		if err := yaml.Unmarshal(raw, &head); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", path, err))
			return nil
		}
		name := head.Metadata.Name
		if name == "" {
			name = strings.TrimSuffix(d.Name(), filepath.Ext(d.Name()))
		}
		var p ParserContract
		switch head.Kind {
		case "ClusterParser":
			p, err = NewInstalledParser(name, raw)
		case "ClusterSBOMParser":
			if SBOMParserLoader == nil {
				err = fmt.Errorf("no SBOM reader is linked into this process")
			} else {
				p, err = SBOMParserLoader(name, raw)
			}
		default:
			return nil // not a parser: left alone, so a directory may hold other resources
		}
		if err == nil {
			err = reg.RegisterParser(p)
		}
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", path, err))
			return nil
		}
		n++
		return nil
	})
	if walkErr != nil {
		problems = append(problems, walkErr)
	}
	return n, errors.Join(problems...)
}

// DefaultRegistry is the registry a process uses when it is not given one. It holds nothing but what ParsersDirEnv names:
// no parser is compiled in. A manifest that cannot be installed is skipped here; the server start-up reports it (it calls
// LoadManifestDir itself).
func DefaultRegistry() *Registry {
	reg := NewRegistry()
	if dir := os.Getenv(ParsersDirEnv); dir != "" {
		_, _ = LoadManifestDir(reg, dir)
	}
	return reg
}

// InstalledModuleNames says which WASM module an installed parser needs: the names it is looked up under, or none when it needs no module
// (a Lua parser). A ClusterSBOMParser is looked up as "sbom-<format>" and then "<format>", as the SBOM reader does.
func InstalledModuleNames(name string, raw []byte) []string {
	kind, spec, err := parseInstalled(raw)
	if err != nil {
		return nil
	}
	if kind == "ClusterSBOMParser" {
		format := spec.Format
		if format == "" {
			format = strings.TrimPrefix(name, domain.SBOMParserNamePrefix)
		}
		return []string{"sbom-" + format, format}
	}
	if spec.Runtime == "wasm" {
		return []string{name}
	}
	return nil
}

// RequiredModules is the WASM module this parser runs, by the name it is looked up under; none for a Lua parser.
func (a *defaultParserAdapter) RequiredModules() []string {
	if a.runtime == "wasm" {
		return []string{a.name}
	}
	return nil
}
