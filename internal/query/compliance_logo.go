package query

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"rampart/internal/compliance"
	"rampart/internal/domain"
)

// logoMaxBytes is the largest mark the server keeps. A mark is a small picture; anything larger is a mistake or an attack.
const logoMaxBytes = 256 << 10

// LogoFetcher reads the mark of a framework from the address the resource names. The default is safe against
// requests into the cluster (SSRF); tests replace it.
type LogoFetcher func(ctx context.Context, rawURL string) (body []byte, contentType string, err error)

// SetLogoFetcher replaces how a framework's mark is read.
func (a *API) SetLogoFetcher(f LogoFetcher) { a.logos.fetch = f }

type logoEntry struct {
	body  []byte
	ctype string
	err   error
	until time.Time
}

// logoCache keeps a mark for a day and a failure for ten minutes, so a dead address is not asked at every page view.
type logoCache struct {
	mu    sync.Mutex
	m     map[string]logoEntry
	fetch LogoFetcher
	now   func() time.Time
}

func (c *logoCache) get(ctx context.Context, rawURL string) ([]byte, string, error) {
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	c.mu.Lock()
	if e, ok := c.m[rawURL]; ok && now().Before(e.until) {
		c.mu.Unlock()
		return e.body, e.ctype, e.err
	}
	c.mu.Unlock()
	fetch := c.fetch
	if fetch == nil {
		fetch = fetchLogoSafely
	}
	body, ctype, err := fetch(ctx, rawURL)
	e := logoEntry{body: body, ctype: ctype, err: err, until: now().Add(24 * time.Hour)}
	if err != nil {
		e.until = now().Add(10 * time.Minute)
	}
	c.mu.Lock()
	if c.m == nil {
		c.m = map[string]logoEntry{}
	}
	if len(c.m) >= 128 { // a tenant cannot grow the cache without bound
		for k := range c.m {
			delete(c.m, k)
			break
		}
	}
	c.m[rawURL] = e
	c.mu.Unlock()
	return body, ctype, err
}

// fetchLogoSafely reads an https address that the framework resource names. The address is data from a tenant, so
// it is refused when it points into the cluster, the host or the metadata service: checked on each connection
// (so a name that changes its answer is caught), on each redirect, with a short time limit and a size limit.
func fetchLogoSafely(ctx context.Context, rawURL string) ([]byte, string, error) {
	if err := compliance.ValidateLogoURL(rawURL); err != nil || rawURL == "" {
		return nil, "", fmt.Errorf("logoUrl: %v", err)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip == nil || domain.IsBlockedIP(ip) {
			return errors.New("the address is private, local or a metadata address")
		}
		return nil
	}}
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true}, // no Proxy: a proxy would dial for us
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return compliance.ValidateLogoURL(req.URL.String())
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "image/svg+xml,image/png,image/jpeg,image/webp")
	req.Header.Set("User-Agent", "rampart-logo")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("could not be read: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("the address answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, logoMaxBytes+1))
	if err != nil {
		return nil, "", err
	}
	ctype, err := checkLogo(body)
	return body, ctype, err
}

// checkLogo says what a body is, from its bytes and not from what the server claimed, and refuses anything that is
// not a small PNG, JPEG, WebP or SVG. An SVG with a script, an event handler, a foreign object, an entity or a
// reference to another file is refused, so the mark is safe even if it were opened on its own.
func checkLogo(body []byte) (string, error) {
	if len(body) == 0 {
		return "", errors.New("the address returned nothing")
	}
	if len(body) > logoMaxBytes {
		return "", fmt.Errorf("larger than %d KiB", logoMaxBytes>>10)
	}
	head := body
	if len(head) > 512 {
		head = head[:512]
	}
	switch ct := http.DetectContentType(head); ct {
	case "image/png", "image/jpeg", "image/webp":
		return ct, nil
	}
	low := strings.ToLower(string(body))
	if bytes.Contains(body, []byte("<svg")) || strings.Contains(low, "<svg") {
		for _, bad := range []string{"<script", "javascript:", "<foreignobject", "<!entity", "<iframe", "<embed", "<object", "<use", "<image", "href=\"http", "href='http", "xlink:href=\"http", "url(http", "@import"} {
			if strings.Contains(low, bad) {
				return "", fmt.Errorf("an SVG with %q is not accepted", strings.TrimPrefix(bad, "<"))
			}
		}
		if onAttr(low) {
			return "", errors.New("an SVG with an event handler is not accepted")
		}
		return "image/svg+xml", nil
	}
	return "", errors.New("not a PNG, JPEG, WebP or SVG picture")
}

// onAttr finds an event-handler attribute such as onload= or onclick=.
func onAttr(low string) bool {
	for i := 0; i+3 < len(low); i++ {
		if (low[i] == ' ' || low[i] == '"' || low[i] == '\'' || low[i] == '\n' || low[i] == '\t') && low[i+1] == 'o' && low[i+2] == 'n' {
			j := i + 3
			for j < len(low) && low[j] >= 'a' && low[j] <= 'z' {
				j++
			}
			for j < len(low) && (low[j] == ' ') {
				j++
			}
			if j < len(low) && low[j] == '=' && j > i+3 {
				return true
			}
		}
	}
	return false
}

// logoPath is where the browser reads a framework's mark. The short hash of the address changes the path when the
// resource names another picture, so a browser that kept the old one asks again.
func logoPath(id, rawURL string) string {
	if rawURL == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(rawURL))
	return "/api/v1/taxonomies/" + id + "/logo?v=" + hex.EncodeToString(sum[:4])
}
