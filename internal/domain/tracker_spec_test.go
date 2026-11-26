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
	if s.Protocol != "grpc" || !s.IsEnabled() || s.UseTLS() {
		t.Fatalf("unexpected defaults: %+v", s)
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
