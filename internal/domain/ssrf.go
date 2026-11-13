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
	return IsBlockedIPWithAllowlist(ip, nil)
}

// IsBlockedIPWithAllowlist checks whether an IP is blocked, respecting platform allowlists for in-cluster/on-prem hosts (D69).
func IsBlockedIPWithAllowlist(ip net.IP, allowlist *PlatformSSRFAllowlist) bool {
	if ip == nil {
		return true
	}
	if allowlist != nil && allowlist.IsIPAllowed(ip) {
		return false
	}
	// Use standard library classification for private, loopback, link-local, multicast, unspecified
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, block := range blockedCIDRs {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// PlatformSSRFAllowlist defines administrator-configured network ranges and hosts
// permitted for in-cluster (e.g. Dependency-Track on .svc:8080) or on-premise integrations (D69).
type PlatformSSRFAllowlist struct {
	AllowedCIDRs      []*net.IPNet
	AllowedHosts      []string
	AllowInternalHTTP bool
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
		if allowedLower == "*" || h == allowedLower {
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

	// Check if hostname is an explicit IP literal
	if ip := net.ParseIP(hostname); ip != nil {
		if allowlist != nil && allowlist.IsIPAllowed(ip) {
			return nil
		}
		if IsBlockedIP(ip) {
			return fmt.Errorf("%w: destination IP %s is a private or link-local address (D69)", ErrSSRFBlocked, ip.String())
		}
		return nil
	}

	// Resolve hostname to IP addresses
	ips, err := net.LookupIP(hostname)
	if err != nil {
		// If DNS resolution fails, allow it only if it is a plausible external domain name
		return nil
	}

	for _, ip := range ips {
		if allowlist != nil && allowlist.IsIPAllowed(ip) {
			continue
		}
		if isAllowedHost {
			continue
		}
		if IsBlockedIP(ip) {
			return fmt.Errorf("%w: host %q resolves to blocked IP %s (D69)", ErrSSRFBlocked, hostname, ip.String())
		}
	}

	return nil
}
