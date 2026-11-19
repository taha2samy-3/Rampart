package wasm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"gopkg.in/yaml.v3"

	"rampart/internal/domain"
	"rampart/internal/integrations"
	"rampart/internal/wasmstore"
)

var (
	ErrInvalidWasmSpec = errors.New("wasm: invalid parser specification")
	ErrWasmExecution   = errors.New("wasm: execution error")

	globalWasmCache = wazero.NewCompilationCache()
)

func init() {
	integrations.WasmParserLoader = func(name string, raw []byte) (integrations.ParserContract, error) {
		return NewWasmParserFromSpec(name, raw, nil)
	}
}

// recordErrorPrefix starts the line a guest writes for a record it could not read.
var recordErrorPrefix = []byte(`{"__record_error"`)

// WasmParserSpec defines the configuration for a WASM-based parser.
type WasmParserSpec struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Family      string `yaml:"family"`
	Category    string `yaml:"category"`
	Description string `yaml:"description"`
	Source      struct {
		OCI    string `yaml:"oci"`
		File   string `yaml:"file"`
		Base64 string `yaml:"base64"`
	} `yaml:"source"`
	Detect domain.DetectSpec `yaml:"detect"`
	Limits struct {
		MaxMemoryMB int `yaml:"maxMemoryMB"`
	} `yaml:"limits"`
}

// WasmParser implements integrations.ParserContract using wazero WebAssembly engine.
type WasmParser struct {
	spec     WasmParserSpec
	desc     integrations.Descriptor
	wasmCode []byte
}

// NewWasmParserFromSpec creates a WasmParser from YAML or JSON manifest.
// wasmBinary is optional; if nil, it attempts to load from spec.Source.File or OCI cache.
func NewWasmParserFromSpec(name string, raw []byte, wasmBinary []byte) (*WasmParser, error) {
	var manifest struct {
		Metadata struct {
			Name string `yaml:"name" json:"name"`
		} `yaml:"metadata" json:"metadata"`
		Spec WasmParserSpec `yaml:"spec" json:"spec"`
	}

	if err := yaml.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidWasmSpec, err)
	}

	spec := manifest.Spec
	if spec.Name == "" {
		spec.Name = manifest.Metadata.Name
	}
	if spec.Name == "" {
		spec.Name = name
	}
	if spec.Source.OCI == "" && spec.Source.File == "" && len(wasmBinary) == 0 {
		return nil, fmt.Errorf("%w: source.oci or source.file is required", ErrInvalidWasmSpec)
	}

	// The module comes from the store (docs/35 B1): checked against the digest table when one is in force. A file named in
	// the resource is read only without a table: a resource must not make the server read an arbitrary path.
	code := wasmBinary
	store := wasmstore.Default()
	if len(code) == 0 && spec.Source.File != "" && !store.Strict() {
		data, err := os.ReadFile(spec.Source.File)
		if err != nil {
			return nil, fmt.Errorf("wasm: reading source file %q: %w", spec.Source.File, err)
		}
		code = data
	}
	if len(code) == 0 {
		data, _, err := store.Load(spec.Name)
		switch {
		case err == nil:
			code = data
		case errors.Is(err, wasmstore.ErrNotFound):
			// left empty: Parse says the bytecode is not loaded, with the name
		default:
			return nil, fmt.Errorf("wasm: %w", err)
		}
	}

	desc := integrations.Descriptor{
		ID:           "wasm:" + spec.Name,
		Name:         spec.Name + " (WASM)",
		Kind:         integrations.KindParser,
		Category:     spec.Category,
		Version:      spec.Version,
		SupportLevel: integrations.SupportCommunity,
		Description:  spec.Description,
	}

	return &WasmParser{
		spec:     spec,
		desc:     desc,
		wasmCode: code,
	}, nil
}

// SetWasmCode allows updating or loading the compiled bytecode (e.g. after pulling from offline OCI registry).
func (p *WasmParser) SetWasmCode(code []byte) {
	p.wasmCode = code
}

func (p *WasmParser) Descriptor() integrations.Descriptor {
	return p.desc
}

func (p *WasmParser) Detect(head []byte, filename string, contentType string) int {
	return p.spec.Detect.Score(head, filename, contentType)
}

func (p *WasmParser) Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error] {
	return func(yield func(domain.RawFinding, error) bool) {
		if len(p.wasmCode) == 0 {
			yield(domain.RawFinding{}, fmt.Errorf("%w: wasm bytecode not loaded for %s", ErrWasmExecution, p.spec.Name))
			return
		}

		// Initialize wazero runtime with zero network, cached compilation, and sandboxed memory
		cfg := wazero.NewRuntimeConfig().WithCompilationCache(globalWasmCache)
		if p.spec.Limits.MaxMemoryMB > 0 {
			// 1 WASM page = 64KB. Pages = MB * 1024 / 64 = MB * 16
			cfg = cfg.WithMemoryLimitPages(uint32(p.spec.Limits.MaxMemoryMB * 16))
		}

		rt := wazero.NewRuntimeWithConfig(ctx, cfg)
		defer func() { _ = rt.Close(ctx) }()

		// Instantiate WASI snapshot preview 1
		wasi_snapshot_preview1.MustInstantiate(ctx, rt)

		// Compile the WebAssembly module
		compiled, err := rt.CompileModule(ctx, p.wasmCode)
		if err != nil {
			yield(domain.RawFinding{}, fmt.Errorf("%w: compiling wasm module: %v", ErrWasmExecution, err))
			return
		}
		defer func() { _ = compiled.Close(ctx) }()

		// Set up standard streaming IO:
		// Stdin: Report input stream
		// Stdout: Newline-delimited JSON findings stream
		outReader, outWriter := io.Pipe()
		var stderrBuf bytes.Buffer

		modConfig := wazero.NewModuleConfig().
			WithStdin(r).
			WithStdout(outWriter).
			WithStderr(&stderrBuf).
			WithArgs(p.spec.Name)
		if pc.RecordError != nil {
			// The guest reports a record it cannot read as a `{"__record_error": {...}}` line and goes on, instead of
			// stopping the report at it (docs/16 D13). Without this the guest stops at the first bad record, as before.
			modConfig = modConfig.WithEnv("RAMPART_RECORD_ERRORS", "1")
		}

		execErrCh := make(chan error, 1)
		go func() {
			defer func() { _ = outWriter.Close() }()
			_, modErr := rt.InstantiateModule(ctx, compiled, modConfig)
			execErrCh <- modErr
		}()

		// Read output stream line by line
		scanner := bufio.NewScanner(outReader)
		// Support up to 1MB line length for findings with large snippets or descriptions
		buf := make([]byte, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		lineNum := 0
		foundCount := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}

			if bytes.HasPrefix(line, recordErrorPrefix) {
				var env struct {
					RecordError domain.RecordError `json:"__record_error"`
				}
				if err := json.Unmarshal(line, &env); err == nil && pc.RecordError != nil {
					pc.RecordError(env.RecordError)
				}
				continue
			}

			var rf domain.RawFinding
			if err := json.Unmarshal(line, &rf); err != nil {
				if pc.RecordError != nil {
					preview := string(line)
					if len(preview) > 80 {
						preview = preview[:80] + "..."
					}
					pc.RecordError(domain.RecordError{
						Where:   fmt.Sprintf("wasm.stdout:line %d", lineNum),
						Message: fmt.Sprintf("invalid json finding: %v (raw: %s)", err, preview),
					})
				}
				continue
			}

			if rf.RuleID == "" && rf.Title == "" {
				if pc.RecordError != nil {
					pc.RecordError(domain.RecordError{
						Where:   fmt.Sprintf("wasm.stdout:line %d", lineNum),
						Message: "finding missing both rule_id and title",
					})
				}
				continue
			}

			// Ensure required default fields if omitted by wasm module
			if rf.Title == "" {
				rf.Title = rf.RuleID
			}
			if rf.RuleID == "" {
				rf.RuleID = rf.Title
			}
			if rf.Category == "" {
				rf.Category = domain.FindingCategory(p.spec.Category)
			}
			if rf.Category == "" {
				rf.Category = domain.CategorySAST
			}
			if rf.ScannerFamily == "" {
				rf.ScannerFamily = p.spec.Family
			}
			if rf.Severity == "" {
				rf.Severity = domain.SeverityMedium
			}

			foundCount++
			if !yield(rf, nil) {
				_ = outReader.Close()
				return
			}
		}

		if err := scanner.Err(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			yield(domain.RawFinding{}, fmt.Errorf("wasm stdout read error: %w", err))
			return
		}

		// Check module exit status
		if modErr := <-execErrCh; modErr != nil {
			// Ignore normal exit code 0
			if !strings.Contains(modErr.Error(), "exit_code(0)") {
				errMsg := modErr.Error()
				if strings.Contains(errMsg, "memory limit") {
					errMsg = fmt.Sprintf("memory limit of %d MB exceeded", p.spec.Limits.MaxMemoryMB)
				}
				if stderrBuf.Len() > 0 {
					errMsg += " | stderr: " + stderrBuf.String()
				}
				yield(domain.RawFinding{}, fmt.Errorf("%w: %s", ErrWasmExecution, errMsg))
			}
		}
	}
}
