package sbom

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"rampart/internal/domain"
	"rampart/internal/graph"
)

// An SBOM reader turns one SBOM document into assets: the components, the dependency edges and the document
// metadata. By default it produces no findings: matching components against vulnerability data is the job of the
// matcher and of the external analyzers. A reader whose spec sets options.extractVulnerabilities (default false) also
// emits the vulnerabilities the document itself states (a CycloneDX VDR), which become findings (D131).
//
// The module reads the document on stdin and writes one JSON object per line on stdout:
//
//	{"type":"metadata","format":"CycloneDX","spec_version":"1.5","serial_number":"...","root_ref":"..."}
//	{"type":"component","ref":"...","name":"...","version":"...","purl":"...","purl_base":"...","scope":"...","licenses":[],"hashes":{},"is_root":false}
//	{"type":"edge","from":"...","to":"...","direct":true}
//	{"type":"vulnerability","id":"CVE-...","affected_ref":"...","severity":"high","score":7.5,"vector":"...","cwes":[79],"source":"NVD","aliases":[],"description":"..."}
//
// A vulnerability line is written only when the host sets EXTRACT_VULNERABILITIES=true in the module's environment; the
// host ignores one it did not ask for.
//
// A line of another type is ignored, so a newer module can add events without breaking an older host.

const (
	// maxEventLine is the longest line the host accepts from a module.
	maxEventLine = 10 << 20
	// DefaultMemoryMB is the memory a module may use when its spec sets no limit.
	DefaultMemoryMB = 1024
	// DefaultTimeout is how long a module may run.
	DefaultTimeout = 2 * time.Minute
	// stderrTail is how much of a module's stderr goes into an error message.
	stderrTail = 2048
)

// ErrNoModule is returned when the module a format needs is not available.
var ErrNoModule = errors.New("sbom: no wasm module for the format")

var wasmCache = wazero.NewCompilationCache()

// Limits bound one run of a module.
type Limits struct {
	MaxMemoryMB int
	Timeout     time.Duration
	// ExtractVulnerabilities asks the module for the vulnerabilities the document states (the spec option of the same name).
	ExtractVulnerabilities bool
}

func (l Limits) withDefaults() Limits {
	if l.MaxMemoryMB <= 0 {
		l.MaxMemoryMB = DefaultMemoryMB
	}
	if l.MaxMemoryMB > 4095 { // a 32-bit module cannot address more
		l.MaxMemoryMB = 4095
	}
	if l.Timeout <= 0 {
		l.Timeout = DefaultTimeout
	}
	return l
}

// Result is what a reader returns.
type Result struct {
	SBOM       *domain.SBOM
	Components []domain.SBOMComponent
	Edges      []domain.DependencyEdge
	// Vulnerabilities are the ones the document states, only when the run asked for them.
	Vulnerabilities []Vulnerability
}

// Vulnerability is one vulnerability a document states about one component (a CycloneDX VDR entry).
type Vulnerability struct {
	ID          string
	Source      string
	Severity    string
	Score       float64
	Vector      string
	CWEs        []int
	AffectedRef string
	Description string
	Detail      string
	Aliases     []string
}

// run executes a module on one document. It is the only place an SBOM module is run.
//
// The run fails, and returns nothing, when the module does not compile, traps, exits with a non-zero code, exceeds
// its limits, writes a line that is not valid JSON, or writes a component or an edge that names nothing. A reader
// that half-works must not store half of an inventory as if it were the whole.
func run(ctx context.Context, code []byte, r io.Reader, name string, lim Limits) (*Result, error) {
	if len(code) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoModule, name)
	}
	lim = lim.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()

	cfg := wazero.NewRuntimeConfig().
		WithCompilationCache(wasmCache).
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(uint32(lim.MaxMemoryMB) * 16) // one page is 64 KiB
	rt := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer func() { _ = rt.Close(context.WithoutCancel(ctx)) }()
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)

	compiled, err := rt.CompileModule(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("%w: compiling %s: %v", ErrWasmExecution, name, err)
	}
	defer func() { _ = compiled.Close(context.WithoutCancel(ctx)) }()

	outReader, outWriter := io.Pipe()
	var stderr tailBuffer
	modConfig := wazero.NewModuleConfig().
		WithStdin(r).
		WithStdout(outWriter).
		WithStderr(&stderr).
		WithArgs(name)
	if lim.ExtractVulnerabilities {
		modConfig = modConfig.WithEnv("EXTRACT_VULNERABILITIES", "true")
	}

	execErr := make(chan error, 1)
	go func() {
		_, err := rt.InstantiateModule(ctx, compiled, modConfig)
		_ = outWriter.Close()
		execErr <- err
	}()

	res, readErr := readEvents(outReader, lim.ExtractVulnerabilities)
	// Stop the module if the host gave up first, so its goroutine does not block on a full pipe.
	_ = outReader.CloseWithError(io.ErrClosedPipe)
	modErr := <-execErr

	if modErr != nil && !exitedZero(modErr) {
		msg := modErr.Error()
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			msg = fmt.Sprintf("the module ran longer than %s", lim.Timeout)
		case strings.Contains(msg, "memory"):
			msg = fmt.Sprintf("the module needs more than %d MB", lim.MaxMemoryMB)
		}
		if tail := stderr.String(); tail != "" {
			msg += " | stderr: " + tail
		}
		return nil, fmt.Errorf("%w: %s: %s", ErrWasmExecution, name, msg)
	}
	if readErr != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrWasmExecution, name, readErr)
	}
	return res, nil
}

// exitedZero reports whether a module ended by proc_exit(0), which wazero reports as an error value.
func exitedZero(err error) bool {
	var ee interface{ ExitCode() uint32 }
	return errors.As(err, &ee) && ee.ExitCode() == 0
}

// readEvents reads the event lines of a module and builds the result.
func readEvents(r io.Reader, extractVulnerabilities bool) (*Result, error) {
	res := &Result{SBOM: &domain.SBOM{ID: domain.NewID(), CreatedAt: time.Now().UTC()}}
	sawMetadata := false

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxEventLine)
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var ev event
		if err := json.Unmarshal(b, &ev); err != nil {
			return nil, fmt.Errorf("line %d is not valid JSON: %v", line, err)
		}
		switch ev.Type {
		case "metadata":
			sawMetadata = true
			if ev.Format != "" {
				res.SBOM.Format = ev.Format
			}
			if ev.SpecVersion != "" {
				res.SBOM.SpecVersion = ev.SpecVersion
			}
			if ev.SerialNumber != "" {
				res.SBOM.Serial = ev.SerialNumber
			}
			if ev.RootRef != "" {
				res.SBOM.RootComponent = ev.RootRef
			}
		case "component":
			if ev.Ref == "" && ev.Purl == "" && ev.Name == "" {
				return nil, fmt.Errorf("line %d: a component has no ref, purl or name", line)
			}
			res.Components = append(res.Components, domain.SBOMComponent{
				Ref: ev.Ref, Name: ev.Name, Version: ev.Version, Purl: ev.Purl, PurlBase: ev.PurlBase,
				Scope: ev.Scope, Licenses: nonEmpty(ev.Licenses), Hashes: ev.Hashes,
			})
		case "edge":
			if ev.From == "" || ev.To == "" {
				return nil, fmt.Errorf("line %d: an edge needs both from and to", line)
			}
			res.Edges = append(res.Edges, domain.DependencyEdge{FromRef: ev.From, ToRef: ev.To})
		case "vulnerability":
			if !extractVulnerabilities {
				continue // not asked for: ignored, like any line of a type the host does not use
			}
			if ev.ID == "" || ev.AffectedRef == "" {
				return nil, fmt.Errorf("line %d: a vulnerability needs an id and the component it affects", line)
			}
			res.Vulnerabilities = append(res.Vulnerabilities, Vulnerability{
				ID: ev.ID, Source: ev.Source, Severity: ev.Severity, Score: ev.Score, Vector: ev.Vector, CWEs: ev.CWEs,
				AffectedRef: ev.AffectedRef, Description: ev.Description, Detail: ev.Detail, Aliases: nonEmpty(ev.Aliases),
			})
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		return nil, fmt.Errorf("reading the module output: %v", err)
	}

	if !sawMetadata && len(res.Components) == 0 {
		// A module that recognises its format always says so; silence means it found nothing it knows in the document.
		return nil, errors.New("the module found nothing it recognises in the document: it is not in this format")
	}
	// Direct is what the root depends on itself, worked out once from the edges, in the one place the graph is built, so
	// the flag stored with a component, the graph of the web UI and the CLI always agree. A module's own idea of "direct"
	// is not used: it cannot know the root of a document that lists no dependencies for it.
	view := graph.BuildView(res.Components, res.Edges, res.SBOM.RootComponent, nil)
	direct := make(map[string]bool, len(view.Nodes))
	for _, n := range view.Nodes {
		direct[n.ID] = n.Direct
	}
	for i := range res.Components {
		res.Components[i].Direct = direct[graph.ComponentID(res.Components[i])]
	}
	res.SBOM.ComponentCount = len(res.Components)
	res.SBOM.Dependencies = res.Edges
	return res, nil
}

// event is one line of module output; fields not used by a type stay empty.
type event struct {
	Type         string            `json:"type"`
	Format       string            `json:"format"`
	SpecVersion  string            `json:"spec_version"`
	SerialNumber string            `json:"serial_number"`
	RootRef      string            `json:"root_ref"`
	Ref          string            `json:"ref"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Purl         string            `json:"purl"`
	PurlBase     string            `json:"purl_base"`
	Scope        string            `json:"scope"`
	IsRoot       bool              `json:"is_root"`
	Licenses     []string          `json:"licenses"`
	Hashes       map[string]string `json:"hashes"`
	From         string            `json:"from"`
	To           string            `json:"to"`
	Direct       bool              `json:"direct"`

	// vulnerability
	ID          string   `json:"id"`
	Source      string   `json:"source"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	Vector      string   `json:"vector"`
	CWEs        []int    `json:"cwes"`
	AffectedRef string   `json:"affected_ref"`
	Description string   `json:"description"`
	Detail      string   `json:"detail"`
	Aliases     []string `json:"aliases"`
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// tailBuffer keeps the last bytes written to it, so a chatty module cannot fill memory with its stderr.
type tailBuffer struct{ b []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > stderrTail {
		t.b = t.b[len(t.b)-stderrTail:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return strings.TrimSpace(string(t.b)) }
