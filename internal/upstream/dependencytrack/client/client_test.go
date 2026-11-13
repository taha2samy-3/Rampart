package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"rampart/internal/domain"
	dtclient "rampart/internal/upstream/dependencytrack/client"
)

func TestClient_GetVersion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/version" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Api-Key") != "valid-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"version": "4.14.6"})
	}))
	defer ts.Close()

	c := dtclient.NewClient(dtclient.Config{
		BaseURL:   ts.URL,
		APIKey:    "valid-key",
		Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true},
	})

	version, err := c.GetVersion(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "4.14.6" {
		t.Errorf("version = %q, want 4.14.6", version)
	}
}

func TestClient_ProbePermissions_TeamSelf(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/team/self" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"uuid": "t1",
				"name": "Rampart Team",
				"permissions": []map[string]string{
					{"name": "VIEW_PORTFOLIO"},
					{"name": "VIEW_VULNERABILITY"},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	c := dtclient.NewClient(dtclient.Config{
		BaseURL:   ts.URL,
		APIKey:    "test-key",
		Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true},
	})

	granted, missing, err := c.ProbePermissions(context.Background())
	if err != nil {
		t.Fatalf("unexpected probe error: %v", err)
	}
	if len(missing) != 0 {
		t.Errorf("expected no missing permissions, got %v", missing)
	}
	if len(granted) != 2 {
		t.Errorf("expected 2 granted permissions, got %v", granted)
	}
}

func TestClient_ProbePermissions_Fallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/team/self":
			// Unsupported or 404
			http.NotFound(w, r)
		case "/api/v1/project":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode([]any{})
		case "/api/v1/vulnerability":
			w.WriteHeader(http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := dtclient.NewClient(dtclient.Config{
		BaseURL:   ts.URL,
		APIKey:    "test-key",
		Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true},
	})

	granted, missing, err := c.ProbePermissions(context.Background())
	if err != nil {
		t.Fatalf("unexpected probe error: %v", err)
	}
	if len(granted) != 1 || granted[0] != "VIEW_PORTFOLIO" {
		t.Errorf("granted = %v, want [VIEW_PORTFOLIO]", granted)
	}
	if len(missing) != 1 || missing[0] != "VIEW_VULNERABILITY" {
		t.Errorf("missing = %v, want [VIEW_VULNERABILITY]", missing)
	}
}

func TestClient_ListProjects_And_GetFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/project":
			w.Header().Set("X-Total-Count", "1")
			_ = json.NewEncoder(w).Encode([]dtclient.Project{
				{
					UUID:          "p-uuid-1",
					Name:          "payment-service",
					Version:       "1.0.0",
					Active:        true,
					LastBomImport: 1670000000000,
				},
			})
		case "/api/v1/project/p-uuid-1":
			_ = json.NewEncoder(w).Encode(dtclient.Project{
				UUID:    "p-uuid-1",
				Name:    "payment-service",
				Version: "1.0.0",
			})
		case "/api/v1/project/p-uuid-1/property":
			_ = json.NewEncoder(w).Encode([]dtclient.Property{
				{Group: "integrations", Name: "rampart.application", Value: "payments-app"},
			})
		case "/api/v1/finding/project/p-uuid-1":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"matrix": "p-uuid-1:comp:vuln"},
			})
		case "/api/v1/metrics/project/p-uuid-1/current":
			_ = json.NewEncoder(w).Encode(dtclient.ProjectMetrics{
				Critical:        1,
				Vulnerabilities: 5,
				LastOccurrence:  1670000050000,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := dtclient.NewClient(dtclient.Config{
		BaseURL:   ts.URL,
		APIKey:    "test-key",
		Allowlist: &domain.PlatformSSRFAllowlist{AllowLoopback: true},
	})

	ctx := context.Background()

	// 1. List
	projects, total, err := c.ListProjects(ctx, 1, 10, true)
	if err != nil {
		t.Fatalf("ListProjects error: %v", err)
	}
	if total != 1 || len(projects) != 1 || projects[0].Name != "payment-service" {
		t.Fatalf("unexpected projects: %+v, total: %d", projects, total)
	}

	// 2. GetProject
	p, err := c.GetProject(ctx, "p-uuid-1")
	if err != nil {
		t.Fatalf("GetProject error: %v", err)
	}
	if p.UUID != "p-uuid-1" {
		t.Errorf("project uuid = %s", p.UUID)
	}

	// 3. Properties
	props, err := c.GetProjectProperties(ctx, "p-uuid-1")
	if err != nil {
		t.Fatalf("GetProjectProperties error: %v", err)
	}
	if len(props) != 1 || props[0].Value != "payments-app" {
		t.Errorf("properties = %+v", props)
	}

	// 4. Findings
	findingsBytes, err := c.GetFindings(ctx, "p-uuid-1", true)
	if err != nil {
		t.Fatalf("GetFindings error: %v", err)
	}
	if len(findingsBytes) == 0 {
		t.Error("expected findings bytes")
	}

	// 5. Metrics
	metrics, err := c.GetProjectMetrics(ctx, "p-uuid-1")
	if err != nil {
		t.Fatalf("GetProjectMetrics error: %v", err)
	}
	if metrics.Critical != 1 || metrics.Vulnerabilities != 5 {
		t.Errorf("metrics = %+v", metrics)
	}
}

