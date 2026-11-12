package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVEXCommands(t *testing.T) {
	var gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.RequestURI(), r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if r.Method == "POST" {
			_, _ = w.Write([]byte(`{"format":"openvex","dry_run":true,"statements":2,"matched":3,"applied":2,"unchanged":1,"stale":0,"rejected":[{"vulnerability":"CVE-1","reason":"no package"}],"unmatched":[],"failed":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0"}`))
	}))
	defer srv.Close()

	var out bytes.Buffer
	if err := runVEX([]string{"export", "--server", srv.URL, "--token", "tok", "--app", "a-1", "--format", "cyclonedx"}, &out); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/applications/a-1/vex?format=cyclonedx" || gotAuth != "Bearer tok" || !strings.Contains(out.String(), "openvex") {
		t.Fatalf("export: %s %s %q", gotPath, gotAuth, out.String())
	}
	if err := runVEX([]string{"export", "--server", srv.URL, "--app", "a", "--asset", "b"}, &out); err == nil {
		t.Fatal("--app and --asset together must be refused")
	}

	file := filepath.Join(t.TempDir(), "x.vex.json")
	_ = os.WriteFile(file, []byte(`{"statements":[]}`), 0o600)
	out.Reset()
	if err := runVEX([]string{"import", file, "--server", srv.URL, "--token", "tok", "--dry-run", "--app", "a-1"}, &out); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/vex?application=a-1&dryRun=true" || gotBody != `{"statements":[]}` {
		t.Fatalf("import: %s %q", gotPath, gotBody)
	}
	for _, want := range []string{"would apply 2", "unchanged 1", "rejected CVE-1: no package"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q: %s", want, out.String())
		}
	}
	if err := runVEX([]string{"import", "--server", srv.URL}, &out); err == nil {
		t.Fatal("import without a file must be refused")
	}
}
