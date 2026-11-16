package domain

import (
	"net"
	"testing"

	"github.com/google/uuid"
)

// D77: the platform allowlist applies only to the tenants and connector types it names.
func TestSSRFAllowlistScopedTo(t *testing.T) {
	tenantA, tenantB := uuid.New(), uuid.New()
	_, cluster, _ := net.ParseCIDR("10.96.0.0/12")
	al := &PlatformSSRFAllowlist{
		AllowedCIDRs:      []*net.IPNet{cluster},
		AllowedHosts:      []string{"dtrack.dtrack.svc"},
		AllowInternalHTTP: true,
		Tenants:           []string{tenantA.String()},
		ConnectorTypes:    []string{string(ConnectorTypeDependencyTrack)},
	}

	if got := al.ScopedTo(tenantA, ConnectorTypeDependencyTrack); !got.Grants() {
		t.Fatal("tenant A's Dependency-Track connector is in scope and must get the exception")
	}
	for name, got := range map[string]*PlatformSSRFAllowlist{
		"other tenant":         al.ScopedTo(tenantB, ConnectorTypeDependencyTrack),
		"other connector type": al.ScopedTo(tenantA, ConnectorTypeWebhook),
		"no tenant":            al.ScopedTo(uuid.Nil, ConnectorTypeDependencyTrack),
	} {
		if got.Grants() {
			t.Errorf("%s: out of scope but the exception still applies: %+v", name, got)
		}
	}

	// Out of scope, the in-cluster address is refused exactly as with no allowlist at all.
	out := al.ScopedTo(tenantB, ConnectorTypeWebhook)
	if err := ValidateConnectorURLWithAllowlist("http://dtrack.dtrack.svc:8080", out); err == nil {
		t.Error("another tenant's webhook could reach the in-cluster host")
	}
	if !IsBlockedIPWithAllowlistAndHost(net.ParseIP("10.96.0.10"), "", out, false) {
		t.Error("another tenant's webhook could reach the cluster service range")
	}
	// In scope, the same address is allowed.
	if err := ValidateConnectorURLWithAllowlist("https://10.96.0.10:8443", al.ScopedTo(tenantA, ConnectorTypeDependencyTrack)); err != nil {
		t.Errorf("in scope, the cluster address must be allowed: %v", err)
	}

	// "*" matches every value; a nil allowlist stays nil.
	all := &PlatformSSRFAllowlist{AllowedHosts: []string{"jira.corp.internal"}, Tenants: []string{"*"}, ConnectorTypes: []string{"*"}}
	if !all.ScopedTo(tenantB, ConnectorTypeJira).Grants() {
		t.Error(`"*" must match every tenant and type`)
	}
	var none *PlatformSSRFAllowlist
	if none.ScopedTo(tenantA, ConnectorTypeJira) != nil {
		t.Error("a nil allowlist must stay nil")
	}
	// The loopback test switch survives scoping, so local test servers keep working.
	if !(&PlatformSSRFAllowlist{AllowLoopback: true}).ScopedTo(tenantB, ConnectorTypeSlack).AllowLoopback {
		t.Error("AllowLoopback must be kept when out of scope")
	}
}

func TestValidateOutboundURLRefusesUnresolvableHost(t *testing.T) {
	if err := ValidateOutboundURL("https://does-not-exist.invalid/x", nil); err == nil {
		t.Error("strict check must refuse a name that does not resolve")
	}
	if err := ValidateConnectorURLWithAllowlist("https://does-not-exist.invalid/x", nil); err != nil {
		t.Errorf("reconcile-time check keeps accepting an unresolved name: %v", err)
	}
}

func TestInboundWebhookPath(t *testing.T) {
	id := uuid.New()
	twoWay := Connector{ID: id, Type: ConnectorTypeJira, Spec: ConnectorSpec{Jira: &JiraConnectorConfig{TwoWaySync: true}}}
	if got := InboundWebhookPath(twoWay); got != "/hooks/jira/"+id.String() {
		t.Errorf("two-way Jira: %q", got)
	}
	for name, c := range map[string]Connector{
		"one-way jira": {ID: id, Type: ConnectorTypeJira, Spec: ConnectorSpec{Jira: &JiraConnectorConfig{}}},
		"webhook":      {ID: id, Type: ConnectorTypeWebhook},
		"slack":        {ID: id, Type: ConnectorTypeSlack},
		"no id":        {Type: ConnectorTypeJira, Spec: ConnectorSpec{Jira: &JiraConnectorConfig{TwoWaySync: true}}},
	} {
		if got := InboundWebhookPath(c); got != "" {
			t.Errorf("%s: expected no inbound path, got %q", name, got)
		}
	}
}
