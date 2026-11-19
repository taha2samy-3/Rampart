package connectors_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"rampart/internal/connectors"
	"rampart/internal/domain"
)

// D77: a request is checked against the allowlist as it applies to the connector that sends it. Another
// tenant's connector, another connector type and an unscoped client get the default policy.
func TestSafeClientScopedAllowlist(t *testing.T) {
	tenantA, tenantB := uuid.New(), uuid.New()
	_, private, _ := net.ParseCIDR("10.255.255.0/24")
	client := connectors.NewSafeClientWithConfig(connectors.SafeClientConfig{Allowlist: &domain.PlatformSSRFAllowlist{
		AllowedCIDRs:      []*net.IPNet{private},
		AllowInternalHTTP: true,
		Tenants:           []string{tenantA.String()},
		ConnectorTypes:    []string{string(domain.ConnectorTypeJira)},
	}})
	const target = "https://10.255.255.1:8443/api/version" // internal HTTP is allowed by host name only (D69)

	send := func(c *connectors.SafeClient) error {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		_, _, _, err := c.Do(req)
		return err
	}

	for name, c := range map[string]*connectors.SafeClient{
		"unscoped":             client,
		"other tenant":         client.Scoped(tenantB, domain.ConnectorTypeJira),
		"other connector type": client.Scoped(tenantA, domain.ConnectorTypeWebhook),
	} {
		if err := send(c); !errors.Is(err, connectors.ErrSSRFDialBlocked) {
			t.Errorf("%s: expected the SSRF guard to refuse the private address, got %v", name, err)
		}
	}
	// In scope the guard lets it through; the address is unroutable, so the request then fails on the network.
	if err := send(client.Scoped(tenantA, domain.ConnectorTypeJira)); errors.Is(err, connectors.ErrSSRFDialBlocked) {
		t.Errorf("in scope: the guard refused an allowed address: %v", err)
	}
}
