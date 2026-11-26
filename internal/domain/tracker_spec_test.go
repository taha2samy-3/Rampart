package domain

import (
	"strings"
	"testing"
)

func TestParseExternalTrackerSpec_ValidCases(t *testing.T) {
	s, err := ParseExternalTrackerSpec([]byte(`{"service":{"name":"jira-tracker","namespace":"rampart-system","port":50052},"timeoutSeconds":45}`), false)
	if err != nil {
		t.Fatalf("unexpected error for cluster service: %v", err)
	}
	if s.Protocol != "grpc" || !s.IsEnabled() || !s.UseTLS() {
		t.Fatalf("unexpected defaults (TLS is the default): %+v", s)
	}
	if got := s.Target("default"); got != "jira-tracker.rampart-system.svc.cluster.local:50052" {
		t.Fatalf("Target() = %q", got)
	}

	s2, err := ParseExternalTrackerSpec([]byte(`{"enabled":false,"endpoint":"trackers.example.org:443","tls":{"insecure":false}}`), false)
	if err != nil {
		t.Fatalf("unexpected error for cluster endpoint: %v", err)
	}
	if s2.IsEnabled() || !s2.UseTLS() || s2.Target("default") != "trackers.example.org:443" {
		t.Fatalf("unexpected parsed cluster endpoint: %+v", s2)
	}
}

func TestParseExternalTrackerSpec_RejectsInvalidAndSSRF(t *testing.T) {
	cases := []struct {
		name   string
		spec   string
		tenant bool
		want   string
	}{
		{"tenant endpoint blocked", `{"endpoint":"169.254.169.254:80"}`, true, "namespaced ExternalTracker"},
		{"both endpoint and service", `{"endpoint":"a:443","service":{"name":"svc","port":50052}}`, false, "not both"},
		{"no address", `{"enabled":true}`, false, "no address"},
		{"bad port", `{"service":{"name":"svc","port":99999}}`, true, "valid port"},
		{"http refused", `{"protocol":"http","service":{"name":"svc","port":8080}}`, true, "use grpc"},
		{"timeout too large", `{"service":{"name":"svc","port":50052},"timeoutSeconds":900}`, false, "outside 0 to"},
	}
	for _, tc := range cases {
		_, err := ParseExternalTrackerSpec([]byte(tc.spec), tc.tenant)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want substring %q", tc.name, err, tc.want)
		}
	}
}

func TestExternalTrackerSpec_TLSUnlessInsecureWritten(t *testing.T) {
	cases := []struct {
		spec string
		tls  bool
	}{
		{`{"service":{"name":"svc","port":50052}}`, true},
		{`{"service":{"name":"svc","port":50052},"tls":{}}`, true},
		{`{"service":{"name":"svc","port":50052},"tls":{"insecure":false}}`, true},
		{`{"service":{"name":"svc","port":50052},"tls":{"insecure":true}}`, false},
	}
	for _, tc := range cases {
		s, err := ParseExternalTrackerSpec([]byte(tc.spec), true)
		if err != nil {
			t.Fatalf("%s: %v", tc.spec, err)
		}
		if s.UseTLS() != tc.tls {
			t.Errorf("%s: UseTLS() = %v, want %v", tc.spec, s.UseTLS(), tc.tls)
		}
	}
}

func TestParseExternalTrackerSpec_RefusesUnreadSecretRefs(t *testing.T) {
	for _, tc := range []struct{ spec, want string }{
		{`{"service":{"name":"svc","port":1},"tls":{"caSecretRef":{"name":"ca","key":"ca.crt"}}}`, "tls.caSecretRef is not supported"},
		{`{"service":{"name":"svc","port":1},"auth":{"secretRef":{"name":"tok","key":"token"}}}`, "auth.secretRef is not supported"},
	} {
		for _, tenant := range []bool{false, true} {
			if _, err := ParseExternalTrackerSpec([]byte(tc.spec), tenant); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s (tenant=%v): err = %v, want %q", tc.spec, tenant, err, tc.want)
			}
		}
	}
	if _, err := ParseExternalTrackerSpec([]byte(`{"service":{"name":"svc","port":1},"tls":{"caSecretRef":null},"auth":{"secretRef":null}}`), true); err != nil {
		t.Errorf("explicit nulls must be accepted: %v", err)
	}
}

func TestParseTenantSpecs_ServiceOnlyInOwnNamespace(t *testing.T) {
	ok := []string{
		`{"service":{"name":"svc","port":50052}}`,
		`{"service":{"name":"svc","namespace":"acme","port":50052}}`,
	}
	for _, spec := range ok {
		if _, err := ParseTenantExternalTrackerSpec([]byte(spec), "acme"); err != nil {
			t.Errorf("tracker %s: %v", spec, err)
		}
		if _, err := ParseTenantExternalAnalyzerSpec([]byte(spec), "acme"); err != nil {
			t.Errorf("analyzer %s: %v", spec, err)
		}
	}
	other := `{"service":{"name":"jira","namespace":"rampart-system","port":50052}}`
	if _, err := ParseTenantExternalTrackerSpec([]byte(other), "acme"); err == nil || !strings.Contains(err.Error(), "only in its own namespace") {
		t.Errorf("tracker in another namespace: err = %v", err)
	}
	if _, err := ParseTenantExternalAnalyzerSpec([]byte(other), "acme"); err == nil || !strings.Contains(err.Error(), "only in its own namespace") {
		t.Errorf("analyzer in another namespace: err = %v", err)
	}
	// A cluster resource may name any namespace.
	if _, err := ParseExternalTrackerSpec([]byte(other), false); err != nil {
		t.Errorf("cluster tracker: %v", err)
	}
}
