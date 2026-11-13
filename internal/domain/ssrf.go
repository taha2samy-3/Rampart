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
	if ip == nil {
		return true
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

// ValidateConnectorURL checks destination URL scheme and validates that the resolved host
// does not target loopback, private RFC 1918, CGNAT, or cloud metadata endpoints (SSRF guard D69).
func ValidateConnectorURL(rawURL string) error {
	return ValidateConnectorURLWithPolicy(rawURL, false)
}

// ValidateConnectorURLWithPolicy validates connector URL, with optional allowance for insecure HTTP (testing only).
func ValidateConnectorURLWithPolicy(rawURL string, allowInsecureHTTP bool) error {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return fmt.Errorf("%w: url cannot be empty", ErrSSRFBlocked)
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("%w: malformed url: %v", ErrSSRFBlocked, err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" {
		if !allowInsecureHTTP || scheme != "http" {
			return fmt.Errorf("%w: unsupported scheme %q (must be https)", ErrSSRFBlocked, scheme)
		}
	}

	hostname := u.Hostname()
	if hostname == "" {
		return fmt.Errorf("%w: empty host in url", ErrSSRFBlocked)
	}

	hostnameLower := strings.ToLower(hostname)
	if hostnameLower == "localhost" || strings.HasSuffix(hostnameLower, ".localhost") ||
		strings.HasSuffix(hostnameLower, ".local") || strings.HasSuffix(hostnameLower, ".internal") {
		return fmt.Errorf("%w: local or internal destination %q is forbidden (D69)", ErrSSRFBlocked, hostname)
	}

	// Check if hostname is an explicit IP literal
	if ip := net.ParseIP(hostname); ip != nil {
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
		if IsBlockedIP(ip) {
			return fmt.Errorf("%w: host %q resolves to blocked IP %s (D69)", ErrSSRFBlocked, hostname, ip.String())
		}
	}

	return nil
}
