package domain

import (
	"strings"
	"testing"
	"time"
)

func TestParseExternalAnalyzerSpecAcceptsWhatTheServerCanCall(t *testing.T) {
	s, err := ParseExternalAnalyzerSpec([]byte(`{"service":{"name":"sonatype","namespace":"tools","port":50051}}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if s.Protocol != "grpc" || !s.IsEnabled() || s.Timeout() != DefaultAnalyzerTimeout || s.UseTLS() || s.Target("x") != "sonatype.tools.svc.cluster.local:50051" {
		t.Fatalf("defaults: %+v target %s", s, s.Target("x"))
	}
	// a Service in no namespace is in the resource's own, or in "default" when there is none
	s, _ = ParseExternalAnalyzerSpec([]byte(`{"service":{"name":"a","port":1}}`), true)
	if s.Target("acme") != "a.acme.svc.cluster.local:1" || s.Target("") != "a.default.svc.cluster.local:1" {
		t.Fatalf("namespace defaults: %s %s", s.Target("acme"), s.Target(""))
	}
	c, err := ParseExternalAnalyzerSpec([]byte(`{"enabled":false,"endpoint":" analyzer.example.org:443 ","timeoutSeconds":30,"tls":{"insecure":false}}`), false)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsEnabled() || !c.UseTLS() || c.Timeout() != 30*time.Second || c.Target("") != "analyzer.example.org:443" {
		t.Fatalf("explicit values: %+v", c)
	}
}

func TestParseExternalAnalyzerSpecRefusesWithItsReason(t *testing.T) {
	for _, c := range []struct {
		name, spec string
		tenant     bool
		want       string
	}{
		{"http", `{"protocol":"http","endpoint":"a:1"}`, false, "no HTTP client"},
		{"unknown protocol", `{"protocol":"soap","endpoint":"a:1"}`, false, "neither grpc nor http"},
		{"both", `{"endpoint":"a:1","service":{"name":"a","port":1}}`, false, "not both"},
		{"none", `{}`, false, "no address"},
		{"tenant endpoint", `{"endpoint":"169.254.169.254:80"}`, true, "may name a service, not an endpoint"},
		{"endpoint without port", `{"endpoint":"analyzer"}`, false, "not host:port"},
		{"endpoint bad port", `{"endpoint":"a:99999"}`, false, "no valid port"},
		{"service name", `{"service":{"name":"Bad_Name","port":1}}`, false, "not a Kubernetes name"},
		{"service namespace", `{"service":{"name":"a","namespace":"Bad Ns","port":1}}`, false, "service.namespace"},
		{"service port", `{"service":{"name":"a","port":0}}`, false, "not a port"},
		{"timeout", `{"endpoint":"a:1","timeoutSeconds":601}`, false, "outside 0 to 600"},
		{"private CA", `{"endpoint":"a:1","tls":{"caSecretRef":{"name":"ca"}}}`, false, "cannot read a Secret"},
		{"credential", `{"endpoint":"a:1","auth":{"secretRef":{"name":"tok"}}}`, false, "without the credential"},
		{"not json", `nope`, false, "not a valid external analyzer spec"},
	} {
		_, err := ParseExternalAnalyzerSpec([]byte(c.spec), c.tenant)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want an error with %q, got %v", c.name, c.want, err)
		}
	}
}

func TestParseSBOMAnalyzerSpec(t *testing.T) {
	s, err := ParseSBOMAnalyzerSpec([]byte(`{}`))
	if err != nil || s.Engine != "hybrid" || !s.IsEnabled() {
		t.Fatalf("defaults: %+v %v", s, err)
	}
	s, err = ParseSBOMAnalyzerSpec([]byte(`{"enabled":false,"engine":"osv","rules":{"minConfidence":0.5,"includePreRelease":true},"sources":{"osv":true,"nvd":false},"schedule":"0 3 * * *"}`))
	if err != nil || s.IsEnabled() || s.Engine != "osv" || *s.Rules.MinConfidence != 0.5 || !s.Rules.IncludePreRelease || s.Schedule != "0 3 * * *" {
		t.Fatalf("explicit: %+v %v", s, err)
	}
	for spec, want := range map[string]string{
		`{"engine":"magic"}`:               "none of hybrid, osv, in-process, advisory-db",
		`{"rules":{"minConfidence":1.5}}`:  "outside 0 to 1",
		`{"rules":{"minConfidence":-0.1}}`: "outside 0 to 1",
		`nope`:                             "not a valid SBOM analyzer spec",
		`{"schedule":"every night"}`:       "schedule: ",
		`{"schedule":"61 3 * * *"}`:        "outside 0 to 59",
	} {
		if _, err := ParseSBOMAnalyzerSpec([]byte(spec)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", spec, want, err)
		}
	}
}
