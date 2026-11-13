package domain

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	ErrSSRFBlocked = errors.New("ssrf: blocked destination address")

	// Additional blocked IP networks per D69 (CGNAT/Alibaba metadata, benchmarking, reserved, translation)
	blockedCIDRs []*net.IPNet
)

func init() {
	cidrs := []string{
		"100.64.0.0/10", // RFC 6598 Shared Address Space / CGNAT (Alibaba Cloud metadata on 100.100.100.200)
		"198.18.0.0/15", // RFC 2544 Benchmarking inter-network communication
		"240.0.0.0/4",   // RFC 1112 Reserved / Future use
		"0.0.0.0/8",     // RFC 1122 Broadcast / this host
		"64:ff9b::/96",  // RFC 6052 IPv4-IPv6 translation
		"2001:db8::/32", // RFC 3849 Documentation IPv6
		"2002::/16",     // RFC 3056 6to4 relay
	}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			blockedCIDRs = append(blockedCIDRs, ipNet)
		}
	}
}

// IsBlockedIP checks whether an IP falls into private, loopback, link-local, multicast,
// CGNAT, or cloud metadata ranges (D69).
func IsBlockedIP(ip net.IP) bool {
	return IsBlockedIPWithAllowlistAndHost(ip, "", nil, false)
}

// IsAlwaysBlockedIP checks whether an IP is an absolute forbidden address (cloud metadata, link-local, loopback, multicast, or unspecified 0.0.0.0/8).
// Platform allowlists may NEVER bypass these addresses under any circumstances (D69).
func IsAlwaysBlockedIP(ip net.IP, allowLoopback bool) bool {
	if ip == nil {
		return true
	}
	if !allowLoopback && (ip.IsLoopback() || ip.Equal(net.IPv4(127, 0, 0, 1)) || ip.Equal(net.IPv6loopback)) {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// Alibaba Cloud metadata IP (100.100.100.200) inside RFC 6598
	if ip.Equal(net.ParseIP("100.100.100.200")) {
		return true
	}
	// 0.0.0.0/8 (broadcast/this host)
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 0 {
		return true
	}
	return false
}

// IsBlockedIPWithAllowlistAndHost evaluates whether an IP is blocked for a specific destination host,
// respecting platform allowlists for private RFC 1918 / CGNAT networks while unconditionally blocking metadata/link-local (D69).
func IsBlockedIPWithAllowlistAndHost(ip net.IP, hostname string, allowlist *PlatformSSRFAllowlist, allowLoopback bool) bool {
	if ip == nil {
		return true
	}
	// 1. Critical dangerous destinations (metadata, link-local, loopback, multicast, broadcast) are ALWAYS blocked.
	if IsAlwaysBlockedIP(ip, allowLoopback) {
		return true
	}
	// 2. Explicit CIDR match in administrator allowlist (allows private / CGNAT range)
	if allowlist != nil && allowlist.IsIPAllowed(ip) {
		return false
	}
	// 3. Host match in administrator allowlist (allows private / CGNAT range for this specific host)
	if allowlist != nil && hostname != "" && allowlist.IsHostAllowed(hostname) {
		return false
	}
	// 4. Private RFC 1918 ranges
	if ip.IsPrivate() {
		return true
	}
	// 5. Blocked CIDRs (CGNAT, benchmarking, documentation)
	for _, block := range blockedCIDRs {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// IsBlockedIPWithAllowlist checks whether an IP is blocked, respecting platform allowlists for in-cluster/on-prem hosts (D69).
func IsBlockedIPWithAllowlist(ip net.IP, allowlist *PlatformSSRFAllowlist) bool {
	allowLoopback := allowlist != nil && allowlist.AllowLoopback
	return IsBlockedIPWithAllowlistAndHost(ip, "", allowlist, allowLoopback)
}

// PlatformSSRFAllowlist defines administrator-configured network ranges and hosts
// permitted for in-cluster (e.g. Dependency-Track on .svc:8080) or on-premise integrations (D69).
type PlatformSSRFAllowlist struct {
	AllowedCIDRs      []*net.IPNet
	AllowedHosts      []string
	AllowInternalHTTP bool
	AllowLoopback     bool // Only for testing with local mock servers
}

// IsIPAllowed returns true if the IP matches any allowed CIDR in the platform allowlist.
func (p *PlatformSSRFAllowlist) IsIPAllowed(ip net.IP) bool {
	if p == nil || ip == nil {
		return false
	}
	for _, cidr := range p.AllowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// IsHostAllowed returns true if hostname matches any allowed host or domain suffix.
func (p *PlatformSSRFAllowlist) IsHostAllowed(hostname string) bool {
	if p == nil || hostname == "" {
		return false
	}
	h := strings.ToLower(hostname)
	for _, allowed := range p.AllowedHosts {
		allowedLower := strings.ToLower(allowed)
		if allowedLower == "*" {
			continue // Universal wildcard '*' is disallowed
		}
		if h == allowedLower {
			return true
		}
		if strings.HasPrefix(allowedLower, "*.") && strings.HasSuffix(h, allowedLower[1:]) {
			return true
		}
		if strings.HasPrefix(allowedLower, ".") && strings.HasSuffix(h, allowedLower) {
			return true
		}
	}
	return false
}

// ValidateConnectorURL checks destination URL scheme and validates that the resolved host
// does not target loopback, private RFC 1918, CGNAT, or cloud metadata endpoints (SSRF guard D69).
func ValidateConnectorURL(rawURL string) error {
	return ValidateConnectorURLWithAllowlist(rawURL, nil)
}

// ValidateConnectorURLWithPolicy validates connector URL, with optional allowance for insecure HTTP (testing only).
func ValidateConnectorURLWithPolicy(rawURL string, allowInsecureHTTP bool) error {
	var allowlist *PlatformSSRFAllowlist
	if allowInsecureHTTP {
		allowlist = &PlatformSSRFAllowlist{
			AllowInternalHTTP: true,
			AllowedHosts:      []string{"*"},
		}
	}
	return ValidateConnectorURLWithAllowlist(rawURL, allowlist)
}

// ValidateConnectorURLWithAllowlist validates connector URL using a platform administrator allowlist.
func ValidateConnectorURLWithAllowlist(rawURL string, allowlist *PlatformSSRFAllowlist) error {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return fmt.Errorf("%w: url cannot be empty", ErrSSRFBlocked)
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("%w: malformed url: %v", ErrSSRFBlocked, err)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return fmt.Errorf("%w: empty host in url", ErrSSRFBlocked)
	}

	isAllowedHost := allowlist != nil && allowlist.IsHostAllowed(hostname)

	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" {
		allowedHTTP := isAllowedHost && allowlist != nil && allowlist.AllowInternalHTTP
		if !allowedHTTP {
			return fmt.Errorf("%w: unsupported scheme %q (must be https)", ErrSSRFBlocked, scheme)
		}
	}

	hostnameLower := strings.ToLower(hostname)
	if !isAllowedHost {
		if hostnameLower == "localhost" || strings.HasSuffix(hostnameLower, ".localhost") ||
			strings.HasSuffix(hostnameLower, ".local") || strings.HasSuffix(hostnameLower, ".internal") {
			return fmt.Errorf("%w: local or internal destination %q is forbidden (D69)", ErrSSRFBlocked, hostname)
		}
	}

	allowLoopback := allowlist != nil && allowlist.AllowLoopback

	// Check if hostname is an explicit IP literal
	if ip := net.ParseIP(hostname); ip != nil {
		if IsBlockedIPWithAllowlistAndHost(ip, hostname, allowlist, allowLoopback) {
			return fmt.Errorf("%w: destination IP %s is a private, link-local, or metadata address (D69)", ErrSSRFBlocked, ip.String())
		}
		return nil
	}

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		// If DNS resolution fails, allow it only if it is a plausible external domain name or an allowed internal host
		return nil
	}

	for _, ip := range ips {
		if IsBlockedIPWithAllowlistAndHost(ip, hostname, allowlist, allowLoopback) {
			return fmt.Errorf("%w: host %q resolves to blocked IP %s (D69)", ErrSSRFBlocked, hostname, ip.String())
		}
	}

	return nil
}
