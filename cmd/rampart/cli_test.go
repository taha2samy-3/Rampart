package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestCLIE2EUploadAndSBOM(t *testing.T) {
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

	// 6. Test CLI gate command (fails on critical findings because semgrep/cdx uploaded findings)
	handled, err = handleCLI([]string{"gate", "--server", ts.URL, "--token", token, "--fail-on", "critical"})
	if !handled || err == nil {
		t.Errorf("expected gate to fail on critical findings, got err: %v", err)
	}
}
