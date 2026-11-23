package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupMockRampartServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	validToken := "ci-secret-token-abcdef123456"

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ui-config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"product": "Rampart",
			"version": "0.3.24",
		})
	})

	mux.HandleFunc("/api/v1/me", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer "+validToken {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"title":  "Authentication required",
				"status": 401,
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": map[string]string{
				"id":      "01931f6a-1111-7000-8000-000000000001",
				"name":    "SecOps Admin",
				"email":   "admin@rampart.local",
				"subject": "admin@rampart.local",
			},
			"tenant": map[string]string{
				"id":   "01931f6a-2222-7000-8000-000000000002",
				"slug": "production",
				"name": "Production Environment",
			},
			"role": "admin",
		})
	})

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, validToken
}

func TestCLIVersionEnhanced(t *testing.T) {
	ts, _ := setupMockRampartServer(t)

	// 1. Version default with connected server
	buf := &bytes.Buffer{}
	if err := runVersion([]string{"--server", ts.URL}, buf); err != nil {
		t.Fatalf("runVersion failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Rampart ASPM Platform v") || !strings.Contains(out, "Connected Server") {
		t.Errorf("unexpected version output:\n%s", out)
	}

	// 2. Version with unreachable server
	buf.Reset()
	if err := runVersion([]string{"--server", "http://127.0.0.1:59999", "--timeout", "100ms"}, buf); err != nil {
		t.Fatalf("runVersion with unreachable server failed: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, "unreachable") {
		t.Errorf("expected unreachable notice, got:\n%s", out)
	}

	// 3. Version --short
	buf.Reset()
	if err := runVersion([]string{"--short"}, buf); err != nil {
		t.Fatalf("runVersion --short failed: %v", err)
	}
	if strings.TrimSpace(buf.String()) != Version {
		t.Errorf("expected short version %q, got %q", Version, buf.String())
	}

	// 4. Version --json
	buf.Reset()
	if err := runVersion([]string{"--server", ts.URL, "--json"}, buf); err != nil {
		t.Fatalf("runVersion --json failed: %v", err)
	}
	var jsonMap map[string]any
	if err := json.Unmarshal(buf.Bytes(), &jsonMap); err != nil {
		t.Fatalf("failed to parse json output: %v", err)
	}
	if jsonMap["client_version"] == nil {
		t.Errorf("expected client_version in json, got %v", jsonMap)
	}
	srv, ok := jsonMap["server"].(map[string]any)
	if !ok || srv["connected"] != true {
		t.Errorf("expected server.connected=true, got %v", jsonMap)
	}

	// 5. handleCLI with -v and --version
	handled, err := handleCLI([]string{"-v"})
	if !handled || err != nil {
		t.Errorf("handleCLI -v failed: handled=%v, err=%v", handled, err)
	}
	handled, err = handleCLI([]string{"--version"})
	if !handled || err != nil {
		t.Errorf("handleCLI --version failed: handled=%v, err=%v", handled, err)
	}
}

func TestCLIStatus(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("RAMPART_TOKEN", "")
	t.Setenv("RAMPART_SERVER", "")

	ts, token := setupMockRampartServer(t)

	// 1. Status: Connected + Authenticated
	buf := &bytes.Buffer{}
	if err := runStatus([]string{"--server", ts.URL, "--token", token}, buf); err != nil {
		t.Fatalf("runStatus failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Status:  Connected") || !strings.Contains(out, "Status:  Authenticated") {
		t.Errorf("expected connected and authenticated status, got:\n%s", out)
	}
	if !strings.Contains(out, "admin@rampart.local") || !strings.Contains(out, "production") {
		t.Errorf("expected user and tenant in status, got:\n%s", out)
	}
	if !strings.Contains(out, "ci-s••••3456") {
		t.Errorf("expected masked token in status, got:\n%s", out)
	}

	// 2. Status: Connected + Not Logged In
	buf.Reset()
	if err := runStatus([]string{"--server", ts.URL, "--token", ""}, buf); err != nil {
		t.Fatalf("runStatus not logged in failed: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, "Status:  Connected") || !strings.Contains(out, "Status:  Not logged in") {
		t.Errorf("expected connected and not logged in, got:\n%s", out)
	}

	// 3. Status: Connected + Invalid Token
	buf.Reset()
	if err := runStatus([]string{"--server", ts.URL, "--token", "invalid-token-xyz"}, buf); err != nil {
		t.Fatalf("runStatus invalid token failed: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, "Status:  Failed") || !strings.Contains(out, "HTTP 401") {
		t.Errorf("expected failed auth with HTTP 401, got:\n%s", out)
	}

	// 4. Status: Unreachable Server
	buf.Reset()
	if err := runStatus([]string{"--server", "http://127.0.0.1:59999", "--timeout", "100ms"}, buf); err != nil {
		t.Fatalf("runStatus unreachable failed: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, "Status:  Unreachable") {
		t.Errorf("expected unreachable status, got:\n%s", out)
	}

	// 5. Status: JSON Output
	buf.Reset()
	if err := runStatus([]string{"--server", ts.URL, "--token", token, "--json"}, buf); err != nil {
		t.Fatalf("runStatus --json failed: %v", err)
	}
	var report StatusReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to decode json status report: %v", err)
	}
	if !report.Server.Connected || !report.Auth.Authenticated {
		t.Errorf("expected connected server and authenticated auth in JSON, got %+v", report)
	}
	if report.Auth.User == nil || report.Auth.User.Email != "admin@rampart.local" {
		t.Errorf("expected user email in JSON report, got %+v", report.Auth.User)
	}
}

func TestCLIWhoami(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("RAMPART_TOKEN", "")
	t.Setenv("RAMPART_SERVER", "")

	ts, token := setupMockRampartServer(t)

	// 1. Authenticated
	buf := &bytes.Buffer{}
	if err := runWhoami([]string{"--server", ts.URL, "--token", token}, buf); err != nil {
		t.Fatalf("runWhoami failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Logged in to") || !strings.Contains(out, "admin@rampart.local") || !strings.Contains(out, "production") {
		t.Errorf("unexpected whoami output:\n%s", out)
	}

	// 2. Authenticated with --json
	buf.Reset()
	if err := runWhoami([]string{"--server", ts.URL, "--token", token, "--json"}, buf); err != nil {
		t.Fatalf("runWhoami --json failed: %v", err)
	}
	var res map[string]any
	if err := json.Unmarshal(buf.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse whoami json: %v", err)
	}
	if res["authenticated"] != true || res["role"] != "admin" {
		t.Errorf("unexpected whoami json: %v", res)
	}

	// 3. Not logged in (empty token)
	buf.Reset()
	t.Setenv("RAMPART_TOKEN", "")
	err := runWhoami([]string{"--server", ts.URL, "--token", ""}, buf)
	if err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Errorf("expected 'not logged in' error, got %v", err)
	}

	// 4. Invalid token (HTTP 401)
	buf.Reset()
	err = runWhoami([]string{"--server", ts.URL, "--token", "bad-token"}, buf)
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Errorf("expected HTTP 401 error, got %v", err)
	}
}

func TestCLILogout(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// 1. Logout when credentials exist
	cfgDir := filepath.Join(tmpDir, ".rampart")
	_ = os.MkdirAll(cfgDir, 0700)
	cfgFile := filepath.Join(cfgDir, "credentials.json")
	_ = os.WriteFile(cfgFile, []byte(`{"server":"https://rampart.acme.corp","token":"abc"}`), 0600)

	buf := &bytes.Buffer{}
	if err := runLogout(nil, buf); err != nil {
		t.Fatalf("runLogout failed: %v", err)
	}
	if !strings.Contains(buf.String(), "Successfully logged out") {
		t.Errorf("expected logout confirmation, got: %s", buf.String())
	}
	if _, err := os.Stat(cfgFile); !os.IsNotExist(err) {
		t.Errorf("credentials file should have been deleted")
	}

	// 2. Logout when no credentials exist
	buf.Reset()
	if err := runLogout(nil, buf); err != nil {
		t.Fatalf("runLogout with no credentials failed: %v", err)
	}
	if !strings.Contains(buf.String(), "Already logged out") && !strings.Contains(buf.String(), "No saved credentials") {
		t.Errorf("expected already logged out notice, got: %s", buf.String())
	}
}

func TestCLIAuthSubcommands(t *testing.T) {
	ts, token := setupMockRampartServer(t)

	buf := &bytes.Buffer{}

	// 1. auth status
	if err := runAuth([]string{"status", "--server", ts.URL, "--token", token}, buf); err != nil {
		t.Fatalf("runAuth status failed: %v", err)
	}
	if !strings.Contains(buf.String(), "Rampart ASPM Status") {
		t.Errorf("unexpected auth status output: %s", buf.String())
	}

	// 2. auth whoami
	buf.Reset()
	if err := runAuth([]string{"whoami", "--server", ts.URL, "--token", token}, buf); err != nil {
		t.Fatalf("runAuth whoami failed: %v", err)
	}
	if !strings.Contains(buf.String(), "Logged in to") {
		t.Errorf("unexpected auth whoami output: %s", buf.String())
	}

	// 3. auth logout
	buf.Reset()
	if err := runAuth([]string{"logout"}, buf); err != nil {
		t.Fatalf("runAuth logout failed: %v", err)
	}

	// 4. auth with missing subcommand
	err := runAuth([]string{}, buf)
	if err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Errorf("expected usage error on empty auth, got %v", err)
	}

	// 5. auth with invalid subcommand
	err = runAuth([]string{"unknown-sub"}, buf)
	if err == nil || !strings.Contains(err.Error(), "unknown auth subcommand") {
		t.Errorf("expected error on unknown auth subcommand, got %v", err)
	}
}

func TestCLIHelpAndRouting(t *testing.T) {
	// 1. help command
	handled, err := handleCLI([]string{"help"})
	if !handled || err != nil {
		t.Errorf("handleCLI help failed: handled=%v, err=%v", handled, err)
	}

	// 2. -h and --help
	handled, err = handleCLI([]string{"-h"})
	if !handled || err != nil {
		t.Errorf("handleCLI -h failed: handled=%v, err=%v", handled, err)
	}
	handled, err = handleCLI([]string{"--help"})
	if !handled || err != nil {
		t.Errorf("handleCLI --help failed: handled=%v, err=%v", handled, err)
	}

	// 3. Routing for status, whoami, logout, auth via handleCLI
	for _, cmd := range []string{"status", "whoami", "logout", "auth"} {
		var args []string
		if cmd == "auth" {
			args = []string{"auth", "status", "--timeout", "100ms"}
		} else if cmd == "logout" {
			args = []string{"logout"}
		} else {
			args = []string{cmd, "--timeout", "100ms"}
		}
		handled, _ := handleCLI(args)
		if !handled {
			t.Errorf("handleCLI %s should be handled", cmd)
		}
	}
}

func TestMaskTokenEdgeCases(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"abc", "••••••••"},
		{"12345678", "••••••••"},
		{"ci-token-123456", "ci-t••••3456"},
	}
	for _, tc := range cases {
		got := maskToken(tc.in)
		if got != tc.want {
			t.Errorf("maskToken(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
