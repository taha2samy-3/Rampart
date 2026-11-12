package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/ingest"
	"rampart/internal/jobs"
	"rampart/internal/query"
)

func TestCLIVersion(t *testing.T) {
	handled, err := handleCLI([]string{"version"})
	if err != nil || !handled {
		t.Errorf("expected version command handled without error, got %v", err)
	}
}

func TestCLILogin(t *testing.T) {
	handled, err := handleCLI([]string{"login", "--token", "test-token-xyz"})
	if err != nil || !handled {
		t.Errorf("expected login command handled without error, got %v", err)
	}
}

func TestCLIDeviceLogin(t *testing.T) {
	tokenStore := auth.NewMemoryTokenStore()
	authn := auth.NewAuthenticatorWithStore(tokenStore)
	deviceAuth := auth.NewDeviceAuthManager(tokenStore)

	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	user := &auth.ContextUser{
		Subject:  "dev@example.com",
		Email:    "dev@example.com",
		TenantID: tenantID,
		Role:     auth.RoleMaintainer,
	}

	h := auth.NewHandlers(auth.HandlerDeps{
		Authn:      authn,
		DeviceAuth: deviceAuth,
	})
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	tsAuto := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/device/code":
			res, _ := deviceAuth.CreateDeviceCode("rampart-cli", "", "http://localhost")
			// Simulate user approval in browser
			_ = deviceAuth.VerifyUserCode(r.Context(), res.UserCode, user)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(res)
		case "/auth/device/token":
			mux.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer tsAuto.Close()

	handled, err := handleCLI([]string{"login", "--server", tsAuto.URL})
	if err != nil || !handled {
		t.Fatalf("expected device login to succeed, got %v", err)
	}
}

func TestCLIE2EUploadAndSBOM(t *testing.T) {
	// The CLI reads the commit, branch and repository from the CI environment; the test must not depend on
	// whether it runs inside GitHub Actions or GitLab CI.
	for _, v := range []string{"GITHUB_ACTIONS", "GITLAB_CI", "GITHUB_SHA", "CI_COMMIT_SHA"} {
		t.Setenv(v, "")
	}
	queue := jobs.NewInMemJobQueue()
	gw := ingest.NewGateway(queue)

	tenantID := uuid.MustParse("01931f6a-0000-7000-8000-000000000000")
	authn := auth.NewAuthenticatorWithStore(gw.Store())
	token := authn.DefaultAdminToken(tenantID)
	gw.SetAuthenticator(authn)
	queryAPI := query.NewAPIWithAuth(gw.Store(), nil, authn)

	mux := http.NewServeMux()
	gw.RegisterRoutes(mux)
	queryAPI.RegisterRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 1. Test CLI upload with SARIF fixture
	sarifPath := filepath.Join("..", "..", "internal", "parsers", "sarif", "testdata", "semgrep.sarif")
	handled, err := handleCLI([]string{"upload", sarifPath, "--server", ts.URL, "--token", token})
	if err != nil || !handled {
		t.Fatalf("expected upload command to succeed, got %v", err)
	}

	// 2. Test CLI sbom upload with CycloneDX XML fixture
	xmlPath := filepath.Join("..", "..", "internal", "parsers", "cyclonedx", "testdata", "sample.cdx.xml")
	handled, err = handleCLI([]string{"sbom", "upload", xmlPath, "--server", ts.URL, "--token", token})
	if err != nil || !handled {
		t.Fatalf("expected sbom upload command to succeed, got %v", err)
	}

	// 3. Test CLI apply with sample YAML manifest
	tmpYAML, err := os.CreateTemp("", "manifest-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpYAML.Name()) }()

	manifest := `apiVersion: rampart.aspm.dev/v1alpha1
kind: Tenant
metadata:
  name: acme-corp
spec:
  name: Acme Corporation
`
	_, _ = tmpYAML.WriteString(manifest)
	_ = tmpYAML.Close()

	handled, err = handleCLI([]string{"apply", "-f", tmpYAML.Name()})
	if err != nil || !handled {
		t.Fatalf("expected apply command to succeed, got %v", err)
	}

	// 4. Test CLI sbom graph command
	handled, err = handleCLI([]string{"sbom", "graph", xmlPath})
	if err != nil || !handled {
		t.Fatalf("expected sbom graph command to succeed, got %v", err)
	}

	// 5. Test CLI sbom path command
	handled, err = handleCLI([]string{"sbom", "path", xmlPath, "--target", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"})
	if err != nil || !handled {
		t.Fatalf("expected sbom path command to succeed, got %v", err)
	}

	// 6. The gate evaluates the runs of one build, found by commit, against what the pipeline declared.
	// A report with a rule nobody has reported before, so this build has something new.
	gatePath := filepath.Join(t.TempDir(), "gate.sarif")
	if err := os.WriteFile(gatePath, []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[{"id":"gate.only.rule","properties":{"security-severity":"9.8"}}]}},"results":[{"ruleId":"gate.only.rule","message":{"text":"new problem"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/gate.go"},"region":{"startLine":3}}}]}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCLI("upload", gatePath, "--server", ts.URL, "--token", token, "--commit", "gate-c1", "--branch", "main"); err != nil {
		t.Fatalf("upload with a commit: %v", err)
	}
	if err := runCLI("gate", "--server", ts.URL, "--token", token, "--commit", "gate-c1", "--expect", "semgrep", "--fail-on", "critical", "--wait=false"); err == nil {
		t.Error("a build whose run created a critical finding must fail the gate")
	}
	if err := runCLI("gate", "--server", ts.URL, "--token", token, "--commit", "gate-c1", "--expect", "semgrep", "--fail-on", "critical", "--wait=false"); err == nil {
		t.Error("the verdict must not change on a second call")
	}
	if err := runCLI("gate", "--server", ts.URL, "--token", token, "--commit", "gate-c1", "--expect", "semgrep,trivy", "--fail-on", "critical", "--wait=false"); err == nil {
		t.Error("a declared run that was never uploaded (trivy) must not pass")
	}
	if err := runCLI("gate", "--server", ts.URL, "--token", token, "--expect", "semgrep"); err == nil {
		t.Error("the gate needs a commit or an image digest")
	}
}

func TestCLIMigrateValidation(t *testing.T) {
	// Missing subcommand
	handled, err := handleCLI([]string{"migrate"})
	if !handled || err == nil {
		t.Errorf("expected error when subcommand is missing, got %v", err)
	}

	// Unknown subcommand
	handled, err = handleCLI([]string{"migrate", "invalid-subcommand"})
	if !handled || err == nil {
		t.Errorf("expected error on unknown subcommand, got %v", err)
	}

	// migrate up without direct url (clearing any env var for this test)
	origEnv := os.Getenv("RAMPART_DATABASE_DIRECT_URL")
	_ = os.Unsetenv("RAMPART_DATABASE_DIRECT_URL")
	_ = os.Unsetenv("DATABASE_DIRECT_URL")
	_ = os.Unsetenv("RAMPART_DATABASE_URL")
	_ = os.Unsetenv("DATABASE_URL")
	defer func() {
		if origEnv != "" {
			_ = os.Setenv("RAMPART_DATABASE_DIRECT_URL", origEnv)
		}
	}()

	handled, err = handleCLI([]string{"migrate", "up"})
	if !handled || err == nil {
		t.Errorf("expected error on migrate up without direct-url, got %v", err)
	}

	// migrate wait with unreachable db
	handled, err = handleCLI([]string{"migrate", "wait", "--db-url", "postgres://nobody:pw@127.0.0.1:54399/none?sslmode=disable", "--timeout", "100ms"})
	if !handled || err == nil {
		t.Errorf("expected timeout error on unreachable wait, got %v", err)
	}
}

// The new password never comes from argv, and weak or missing input is refused before any database
// connection is attempted.
func TestAdminSetPasswordValidatesBeforeTouchingTheDatabase(t *testing.T) {
	t.Setenv("RAMPART_DATABASE_SYSTEM_URL", "postgres://unreachable.invalid/db")
	if _, err := handleCLI([]string{"admin"}); err == nil {
		t.Error("admin without a subcommand must be an error")
	}
	if err := runAdmin([]string{"set-password"}, strings.NewReader("short\n")); err == nil || !strings.Contains(err.Error(), "at least 12") {
		t.Errorf("a weak password must be refused: %v", err)
	}
	t.Setenv("RAMPART_DATABASE_SYSTEM_URL", "")
	if err := runAdmin([]string{"set-password"}, strings.NewReader("a-long-enough-secret\n")); err == nil || !strings.Contains(err.Error(), "database URL is required") {
		t.Errorf("a missing database URL must be explained: %v", err)
	}
	if err := runAdmin([]string{"set-password", "--password", "x"}, strings.NewReader("")); err == nil {
		t.Error("there must be no --password flag: it would show up in process listings")
	}
}

func runCLI(args ...string) error {
	handled, err := handleCLI(args)
	if !handled {
		return fmt.Errorf("command %q not handled", args[0])
	}
	return err
}

// In CI the commit comes from the environment, so a pipeline step needs no flag for it.
func TestDetectCI(t *testing.T) {
	t.Setenv("GITLAB_CI", "")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SHA", "abc123")
	t.Setenv("GITHUB_REPOSITORY", "acme/shop")
	t.Setenv("GITHUB_REF_NAME", "feature/x")
	t.Setenv("GITHUB_REF", "refs/pull/12/merge")
	ci := detectCI()
	if ci.Commit != "abc123" || ci.Repository != "github.com/acme/shop" {
		t.Fatalf("github: %+v", ci)
	}
	if ci.Ref != "refs/pull/12/merge" { // a pull request ref is passed whole: it makes the run ephemeral (D10)
		t.Fatalf("a pull request must keep its ref, got %q", ci.Ref)
	}
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_REF_NAME", "main")
	if ci := detectCI(); ci.Ref != "main" {
		t.Fatalf("a branch uses its name, got %q", ci.Ref)
	}
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_COMMIT_SHA", "def456")
	t.Setenv("CI_MERGE_REQUEST_IID", "7")
	t.Setenv("CI_COMMIT_REF_NAME", "topic")
	if ci := detectCI(); ci.Commit != "def456" || ci.Ref != "merge-requests/7" {
		t.Fatalf("gitlab: %+v", ci)
	}
}

func TestCLIFindingsListAndSetState(t *testing.T) {
	findingID := "01931f6a-0000-7000-8000-000000000001"
	var patchedState string
	var patchedJustification string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-cli-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method == "GET" && r.URL.Path == "/api/v1/findings" {
			resp := map[string]any{
				"items": []map[string]any{
					{
						"finding": map[string]any{
							"id":               findingID,
							"rule_id":          "sql-injection",
							"severity":         "critical",
							"state":            "open",
							"title":            "SQL injection in user login",
							"application_name": "payments-api",
						},
						"risk": map[string]any{
							"score": 950,
							"band":  "critical",
						},
					},
				},
				"total": 1,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		if r.Method == "PATCH" && r.URL.Path == "/api/v1/findings/"+findingID {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			patchedState, _ = body["state"].(string)
			patchedJustification, _ = body["justification"].(string)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"finding": map[string]any{
					"id":    findingID,
					"state": patchedState,
				},
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer ts.Close()

	// 1. Test findings list (table)
	var outTable bytes.Buffer
	if err := runFindings([]string{"list", "--server", ts.URL, "--token", "test-cli-token", "-q", "severity:critical"}, &outTable); err != nil {
		t.Fatalf("findings list table failed: %v", err)
	}
	if !strings.Contains(outTable.String(), "SQL injection") || !strings.Contains(outTable.String(), "CRITICAL") {
		t.Errorf("expected table output to contain finding details, got:\n%s", outTable.String())
	}

	// 2. Test findings list (json)
	var outJSON bytes.Buffer
	if err := runFindings([]string{"list", "--server", ts.URL, "--token", "test-cli-token", "-o", "json"}, &outJSON); err != nil {
		t.Fatalf("findings list json failed: %v", err)
	}
	if !strings.Contains(outJSON.String(), "sql-injection") {
		t.Errorf("expected json output to contain rule id, got:\n%s", outJSON.String())
	}

	// 3. Test findings set-state
	var outSet bytes.Buffer
	if err := runFindings([]string{"set-state", findingID, "not_affected", "--justification", "vulnerable_code_not_in_execute_path", "--server", ts.URL, "--token", "test-cli-token"}, &outSet); err != nil {
		t.Fatalf("findings set-state failed: %v", err)
	}
	if patchedState != "not_affected" || patchedJustification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("unexpected patched state: %s, just: %s", patchedState, patchedJustification)
	}
	if !strings.Contains(outSet.String(), "updated to \"not_affected\"") {
		t.Errorf("expected confirmation message, got:\n%s", outSet.String())
	}

	// 4. Test findings CLI routing via handleCLI
	handled, err := handleCLI([]string{"findings", "list", "--server", ts.URL, "--token", "test-cli-token"})
	if !handled || err != nil {
		t.Errorf("handleCLI failed for findings list: handled=%v, err=%v", handled, err)
	}
}
