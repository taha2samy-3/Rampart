// Package wasmstore finds the compiled WASM modules of the shipped parsers and checks them against a digest table before
// anything runs them (docs/35 B1).
//
// How the modules get here is the deployment's business: an image volume per module, a directory baked into the image, or
// a copy made by a helper in Compose. What Rampart owns is the check: with RAMPART_WASM_DIGESTS set, a module is used
// only if its file is under RAMPART_WASM_DIR and its SHA-256 is the one in the table; a missing, unlisted or changed file
// is an error, and the server refuses to start (see Verify). Without it (development, tests) the old search of the
// working directory and its parents is kept, and nothing is verified.
package wasmstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	// ErrNotFound: no file for the module in any place the store looks.
	ErrNotFound = errors.New("wasm module not found")
	// ErrDigest: the file is not the one the digest table names.
	ErrDigest = errors.New("wasm module does not match its digest")
	// ErrUnlisted: strict mode, and the table has no entry for the module.
	ErrUnlisted = errors.New("wasm module is not in the digest table")
)

// Store finds and checks modules.
type Store struct {
	// Dir holds the modules as <name>.wasm or <name>/parser.wasm.
	Dir string
	// Digests maps a module name to the SHA-256 (hex) of its file. A non-empty table makes the store strict.
	Digests map[string]string
}

// Strict reports whether a digest table is in force.
func (s *Store) Strict() bool { return s != nil && len(s.Digests) > 0 }

// FromEnv builds the store from RAMPART_WASM_DIR and RAMPART_WASM_DIGESTS (a JSON object of name to sha256, an optional
// "sha256:" prefix on each value).
func FromEnv() (*Store, error) {
	s := &Store{Dir: os.Getenv("RAMPART_WASM_DIR")}
	if p := os.Getenv("RAMPART_WASM_DIGESTS"); p != "" {
		table, err := ReadDigests(p)
		if err != nil {
			return nil, err
		}
		s.Digests = table
		if s.Dir == "" {
			return nil, fmt.Errorf("wasmstore: RAMPART_WASM_DIGESTS is set but RAMPART_WASM_DIR is not")
		}
	}
	return s, nil
}

// ReadDigests reads a digest table file.
func ReadDigests(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wasmstore: reading the digest table: %w", err)
	}
	var in map[string]string
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("wasmstore: the digest table %s is not a JSON object of name to sha256: %w", path, err)
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		v = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v), "sha256:"))
		if len(v) != 64 {
			return nil, fmt.Errorf("wasmstore: the digest of %q is not a SHA-256 (64 hex characters)", k)
		}
		if _, err := hex.DecodeString(v); err != nil {
			return nil, fmt.Errorf("wasmstore: the digest of %q is not hexadecimal", k)
		}
		out[k] = v
	}
	return out, nil
}

// Digest is the SHA-256 (hex) of a module.
func Digest(code []byte) string {
	h := sha256.Sum256(code)
	return hex.EncodeToString(h[:])
}

// Load returns the module for the first of names that is found, with the name that matched. In strict mode only Dir is
// searched and the digest is checked; otherwise Dir is searched first, then the development locations.
func (s *Store) Load(names ...string) ([]byte, string, error) {
	var firstErr error
	for _, name := range names {
		if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
			continue // a name is a file name: never a path
		}
		code, err := s.loadOne(name)
		switch {
		case err == nil:
			return code, name, nil
		case errors.Is(err, ErrNotFound):
			continue
		default:
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if firstErr != nil {
		return nil, "", firstErr
	}
	return nil, "", fmt.Errorf("%w: %s", ErrNotFound, strings.Join(names, ", "))
}

func (s *Store) loadOne(name string) ([]byte, error) {
	if s != nil && s.Dir != "" {
		for _, cand := range []string{filepath.Join(s.Dir, name+".wasm"), filepath.Join(s.Dir, name, "parser.wasm")} {
			if data, err := os.ReadFile(cand); err == nil && len(data) > 0 {
				return s.check(name, data)
			}
		}
	}
	if s.Strict() {
		return nil, fmt.Errorf("%w: %s (strict mode searches only %s)", ErrNotFound, name, s.Dir)
	}
	for _, cand := range devCandidates(name) {
		if data, err := os.ReadFile(cand); err == nil && len(data) > 0 {
			return data, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
}

func (s *Store) check(name string, data []byte) ([]byte, error) {
	if !s.Strict() {
		return data, nil
	}
	want, ok := s.Digests[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnlisted, name)
	}
	if got := Digest(data); got != want {
		return nil, fmt.Errorf("%w: %s is %s, the table says %s", ErrDigest, name, got, want)
	}
	return data, nil
}

// devCandidates is the search of a development checkout: the repository's parsers directory from the working
// directory and its parents (tests run in the package directory), and a cache directory.
func devCandidates(name string) []string {
	out := make([]string, 0, 5)
	for _, up := range []string{"", "..", filepath.Join("..", ".."), filepath.Join("..", "..", "..")} {
		out = append(out, filepath.Join(up, "parsers", "wasm", name, "parser.wasm"))
	}
	return append(out, filepath.Join("/var/cache/rampart/wasm", name+".wasm"))
}

// Verify checks that every named module loads and, in strict mode, matches its digest. It returns all the problems.
func (s *Store) Verify(names []string) error {
	var problems []string
	for _, n := range names {
		if _, _, err := s.Load(n); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("wasmstore: %d shipped module(s) cannot be used:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

var (
	defaultOnce  sync.Once
	defaultStore *Store
	defaultErr   error
)

// Default is the store the process uses, built from the environment on first use. A bad environment is an error that
// Load then returns, so a mistake in the table is never turned into "use whatever file is nearby".
func Default() *Store {
	defaultOnce.Do(func() { defaultStore, defaultErr = FromEnv() })
	if defaultErr != nil {
		return &Store{Dir: "\x00invalid", Digests: map[string]string{"\x00": strings.Repeat("0", 64)}}
	}
	return defaultStore
}

// DefaultError is the error FromEnv gave, if any, for the server to report at start-up.
func DefaultError() error {
	Default()
	return defaultErr
}

// SetDefault replaces the process store (tests).
func SetDefault(s *Store) {
	defaultOnce.Do(func() {})
	defaultStore, defaultErr = s, nil
}
