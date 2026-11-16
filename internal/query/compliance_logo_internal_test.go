package query

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCheckLogo(t *testing.T) {
	png := "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
	jpg := "\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
	okSVG := `<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="#4353d6"/></svg>`
	cases := []struct {
		name, body, want string // want is the content type, or "" when it must be refused
	}{
		{"png", png, "image/png"},
		{"jpeg", jpg, "image/jpeg"},
		{"a plain svg", okSVG, "image/svg+xml"},
		{"an svg with a doctype only", `<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg xmlns="http://www.w3.org/2000/svg"/>`, "image/svg+xml"},
		{"a script in an svg", `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`, ""},
		{"a javascript: link", `<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><rect/></a></svg>`, ""},
		{"an event handler", `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`, ""},
		{"an event handler after a newline", "<svg xmlns=\"http://www.w3.org/2000/svg\"\nonclick = \"x()\"/>", ""},
		{"a foreignObject", `<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div/></foreignObject></svg>`, ""},
		{"an external entity", `<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg>&x;</svg>`, ""},
		{"a link to another file", `<svg xmlns="http://www.w3.org/2000/svg"><image href="http://evil.example/x.png"/></svg>`, ""},
		{"html", `<html><body>not a picture</body></html>`, ""},
		{"text", `hello`, ""},
		{"empty", ``, ""},
		{"too large", png + strings.Repeat("x", logoMaxBytes), ""},
	}
	for _, c := range cases {
		got, err := checkLogo([]byte(c.body))
		if (c.want == "") != (err != nil) || got != c.want {
			t.Errorf("%s: got %q err=%v, want %q", c.name, got, err, c.want)
		}
	}
}

// The address in a resource is data from a tenant. It must not be a way to make the server call something inside
// the cluster, on the host, or the cloud metadata service.
func TestFetchLogoSafely_RefusesWhatIsNotAPublicHTTPSAddress(t *testing.T) {
	var hit bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true; _, _ = w.Write([]byte("x")) }))
	defer srv.Close() // a real server, on 127.0.0.1

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for name, u := range map[string]string{
		"loopback server":      srv.URL + "/m.png",
		"plain http":           "http://logos.example.com/m.png",
		"metadata service":     "https://169.254.169.254/latest/meta-data/",
		"private address":      "https://10.0.0.5/m.png",
		"ipv6 loopback":        "https://[::1]/m.png",
		"credentials in a url": "https://user:pw@logos.example.com/m.png",
		"no host":              "https:///m.png",
		"not a url":            "::::",
		"empty":                "",
	} {
		if _, _, err := fetchLogoSafely(ctx, u); err == nil {
			t.Errorf("%s: %q must be refused", name, u)
		}
	}
	if hit {
		t.Fatal("the loopback server was reached: the dial check did not stop it")
	}
}
