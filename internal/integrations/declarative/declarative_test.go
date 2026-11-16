package declarative

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

const googleChat = `{"kind":"notifier","runtime":"declarative","version":"1.0.0",
 "secrets":[{"name":"webhookUrl"}],"egress":["chat.googleapis.com"],
 "send":{"request":{"method":"POST","url":"{{ secrets.webhookUrl }}","json":{"text":"*{{ message.title }}*\n{{ message.summary }}\n<{{ message.url }}|Open in Rampart>"}},"expect":"status == 200"}}`

type rec struct {
	req    *http.Request
	body   string
	status int
}

func (r *rec) Do(req *http.Request) ([]byte, int, http.Header, error) {
	r.req = req
	b, _ := io.ReadAll(req.Body)
	r.body = string(b)
	return nil, r.status, nil, nil
}

// D94: doc 19's Google Chat example installs and sends; the message is escaped into the JSON, not spliced into it.
func TestDeclarativeNotifier(t *testing.T) {
	spec, err := Parse([]byte(googleChat))
	if err != nil {
		t.Fatal(err)
	}
	d := &rec{status: 200}
	n, err := NewNotifier(spec, nil, map[string]string{"webhookUrl": "https://chat.googleapis.com/v1/spaces/x/messages?key=k"}, d)
	if err != nil {
		t.Fatal(err)
	}
	err = n.Send(context.Background(), map[string]string{"title": `SQL "injection"` + "\n}", "summary": "2 critical", "url": "https://rampart.example/f/1"})
	if err != nil {
		t.Fatal(err)
	}
	if d.req.Header.Get("Content-Type") != "application/json" || !strings.Contains(d.body, `*SQL \"injection\"\n}*`) || !strings.Contains(d.body, "Open in Rampart") {
		t.Fatalf("body: %s", d.body)
	}

	d.status = 500
	if err := n.Send(context.Background(), map[string]string{"title": "x"}); err == nil || !strings.Contains(err.Error(), "send.expect") {
		t.Fatalf("a 500 fails the delivery: %v", err)
	}

	// A secret that points at another host than the declared egress is refused before any request.
	n2, _ := NewNotifier(spec, nil, map[string]string{"webhookUrl": "https://evil.example/collect"}, d)
	d.req = nil
	if err := n2.Send(context.Background(), map[string]string{"title": "x"}); !errors.Is(err, ErrEgress) || d.req != nil {
		t.Fatalf("egress: %v", err)
	}
	if _, err := NewNotifier(spec, nil, map[string]string{}, d); err == nil {
		t.Fatal("a declared secret must be supplied")
	}
}

func TestParseRefusals(t *testing.T) {
	refused := map[string]string{
		"tracker":            `{"kind":"tracker","runtime":"declarative","version":"1.0.0","egress":["a.example"]}`,
		"code runtime":       `{"kind":"notifier","runtime":"wasm","version":"1.0.0","egress":["a.example"]}`,
		"no egress":          `{"kind":"notifier","runtime":"declarative","version":"1.0.0","send":{"request":{"url":"https://a.example"}}}`,
		"ip egress":          `{"kind":"notifier","runtime":"declarative","version":"1.0.0","egress":["10.0.0.1"],"send":{"request":{"url":"https://a.example"}}}`,
		"unknown template":   `{"kind":"notifier","runtime":"declarative","version":"1.0.0","egress":["a.example"],"send":{"request":{"url":"https://a.example","body":"{{ tenant.id }}"}}}`,
		"undeclared secret":  `{"kind":"notifier","runtime":"declarative","version":"1.0.0","egress":["a.example"],"send":{"request":{"url":"{{ secrets.key }}"}}}`,
		"misspelt message":   `{"kind":"notifier","runtime":"declarative","version":"1.0.0","egress":["a.example"],"send":{"request":{"url":"https://a.example","body":"{{ message.titel }}"}}}`,
		"filter":             `{"kind":"notifier","runtime":"declarative","version":"1.0.0","egress":["a.example"],"send":{"request":{"url":"https://a.example","body":"{{ message.title | upper }}"}}}`,
		"message in header":  `{"kind":"notifier","runtime":"declarative","version":"1.0.0","egress":["a.example"],"send":{"request":{"url":"https://a.example","headers":{"X-T":"{{ message.title }}"}}}}`,
		"expect not boolean": `{"kind":"notifier","runtime":"declarative","version":"1.0.0","egress":["a.example"],"send":{"request":{"url":"https://a.example"},"expect":"status"}}`,
		"unknown field":      `{"kind":"notifier","runtime":"declarative","version":"1.0.0","egress":["a.example"],"exec":"rm -rf /"}`,
		"bad version":        `{"kind":"notifier","runtime":"declarative","version":"latest","egress":["a.example"],"send":{"request":{"url":"https://a.example"}}}`,
	}
	for why, raw := range refused {
		if _, err := Parse([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", why, err)
		}
	}
	spec, err := Parse([]byte(`{"kind":"notifier","runtime":"declarative","version":"1.0.0","egress":["*.example.com"],
		"configSchema":{"type":"object","required":["room"],"properties":{"room":{"type":"string"},"level":{"type":"integer"}}},
		"send":{"request":{"url":"https://hooks.example.com/{{ config.room }}"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	for raw, ok := range map[string]bool{`{"room":"sec"}`: true, `{}`: false, `{"room":1}`: false, `{"room":"a","level":1.5}`: false, `{"room":"a","x":1}`: false} {
		if _, err := spec.ValidateConfig([]byte(raw)); (err == nil) != ok {
			t.Errorf("config %s: %v", raw, err)
		}
	}
}
