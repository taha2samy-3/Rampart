package enrich

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"rampart/internal/domain"
)

// NewFeedHTTPClient returns the HTTP client every feed uses (docs/33 section 7).
//
// A feed URL is written by an administrator, and a mirror inside the cluster or the company is a normal value for it, so
// private addresses are allowed. What is never allowed is what D69 never allows for any caller: cloud metadata, link-local,
// loopback, multicast and the unspecified address. The check runs when the connection is made, on the address that was
// resolved, so a name that resolves there (DNS rebinding) is refused as well as an address written in the URL.
//
// A redirect is followed at most five times, never from https to http, and the credentials of the request
// (Authorization, apiKey) are not sent to another host.
//
// allowLoopback is for tests that serve a feed from 127.0.0.1.
func NewFeedHTTPClient(timeout time.Duration, allowLoopback bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("feeds: cannot read the address %q", address)
			}
			if domain.IsAlwaysBlockedIP(ip, allowLoopback) {
				return fmt.Errorf("feeds: %w: %s", domain.ErrSSRFBlocked, ip)
			}
			return nil
		},
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = dialer.DialContext
	return &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: feedRedirectPolicy}
}

// feedHeaders are the headers that carry a credential. They go only to the host the request was first made to.
var feedHeaders = []string{"Authorization", "apiKey", "Cookie"}

// feedRedirectPolicy is the redirect rule of every feed client.
func feedRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("stopped after 5 redirects")
	}
	first := via[0]
	if first.URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("a redirect from https to http is refused")
	}
	if req.URL.Host != first.URL.Host {
		for _, h := range feedHeaders {
			req.Header.Del(h)
		}
	}
	return nil
}

// withFeedRedirects returns c with the feed redirect rule added to the rule it has. A client given by a test or an
// embedder keeps its transport and its own rule; the credentials still do not follow a redirect to another host.
func withFeedRedirects(c *http.Client) *http.Client {
	cp := *c
	prev := c.CheckRedirect
	cp.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := feedRedirectPolicy(req, via); err != nil {
			return err
		}
		if prev != nil {
			return prev(req, via)
		}
		return nil
	}
	return &cp
}
