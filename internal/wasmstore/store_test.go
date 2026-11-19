package wasmstore_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"rampart/internal/wasmstore"
)

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestStrictStoreChecksTheDigest(t *testing.T) {
	dir := t.TempDir()
	good, other := []byte("module bytes"), []byte("changed bytes")
	write(t, filepath.Join(dir, "sarif.wasm"), good)
	write(t, filepath.Join(dir, "trivy", "parser.wasm"), other) // the image-volume layout
	s := &wasmstore.Store{Dir: dir, Digests: map[string]string{
		"sarif": wasmstore.Digest(good), "trivy": wasmstore.Digest(good), // trivy's file is not the listed one
	}}
	if code, name, err := s.Load("sarif"); err != nil || string(code) != "module bytes" || name != "sarif" {
		t.Fatalf("a module that matches its digest loads: %v", err)
	}
	if _, _, err := s.Load("trivy"); !errors.Is(err, wasmstore.ErrDigest) {
		t.Fatalf("a changed module is refused: %v", err)
	}
	write(t, filepath.Join(dir, "grype.wasm"), good)
	if _, _, err := s.Load("grype"); !errors.Is(err, wasmstore.ErrUnlisted) {
		t.Fatalf("strict mode refuses a module the table does not list: %v", err)
	}
	if _, _, err := s.Load("nuclei"); !errors.Is(err, wasmstore.ErrNotFound) {
		t.Fatalf("a missing module is not found: %v", err)
	}
}

func TestStrictStoreDoesNotFallBackToNearbyFiles(t *testing.T) {
	s := &wasmstore.Store{Dir: t.TempDir(), Digests: map[string]string{"sarif": wasmstore.Digest([]byte("x"))}}
	// the repository's development copy exists next to the tests; strict mode must not use it
	if _, _, err := s.Load("sarif"); !errors.Is(err, wasmstore.ErrNotFound) {
		t.Fatalf("strict mode searches only its directory: %v", err)
	}
}

func TestNamesAreNeverPaths(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "..", "escape.wasm"), []byte("x"))
	s := &wasmstore.Store{Dir: dir}
	for _, n := range []string{"../escape", "a/b", "..", `a\b`, ""} {
		if _, _, err := s.Load(n); !errors.Is(err, wasmstore.ErrNotFound) {
			t.Errorf("%q must not be read as a path: %v", n, err)
		}
	}
}

func TestVerifyReportsEveryProblem(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "a.wasm"), []byte("a"))
	s := &wasmstore.Store{Dir: dir, Digests: map[string]string{"a": wasmstore.Digest([]byte("a")), "b": wasmstore.Digest([]byte("b"))}}
	err := s.Verify([]string{"a", "b", "c"})
	if err == nil {
		t.Fatal("b and c are missing")
	}
	if msg := err.Error(); !(contains(msg, "b") && contains(msg, "c") && contains(msg, "2 shipped")) {
		t.Fatalf("every problem is named: %v", err)
	}
	if err := s.Verify([]string{"a"}); err != nil {
		t.Fatalf("a verified set is fine: %v", err)
	}
}

func TestReadDigests(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d.json")
	write(t, p, []byte(`{"sarif":"sha256:`+wasmstore.Digest([]byte("x"))+`"}`))
	m, err := wasmstore.ReadDigests(p)
	if err != nil || m["sarif"] != wasmstore.Digest([]byte("x")) {
		t.Fatalf("a prefixed digest is accepted: %v %v", m, err)
	}
	write(t, p, []byte(`{"sarif":"abc"}`))
	if _, err := wasmstore.ReadDigests(p); err == nil {
		t.Fatal("a short digest is refused")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
