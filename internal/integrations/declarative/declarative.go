// Package declarative runs tier-1 integrations: an IntegrationPackage that describes an outbound tool as data, an
// HTTP request with templates, so a new tool is installed without a release (docs/19 §6, docs/23 §6.6, docs/16
// D94). This version runs declarative notifiers; trackers, sources and code runtimes are refused by name.
package declarative

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"
)

// ErrInvalid wraps every refusal of a package or of a connector's use of it.
var ErrInvalid = errors.New("integration package")

// Spec is IntegrationPackage.spec for a declarative notifier.
type Spec struct {
	Kind         string          `json:"kind"`    // notifier
	Runtime      string          `json:"runtime"` // declarative
	Version      string          `json:"version"`
	Description  string          `json:"description,omitempty"`
	ConfigSchema *ConfigSchema   `json:"configSchema,omitempty"`
	Secrets      []SecretDecl    `json:"secrets,omitempty"`
	Egress       []string        `json:"egress"`
	Send         *SendSpec       `json:"send,omitempty"`
	Raw          json.RawMessage `json:"-"`
}

// SecretDecl names a secret the connector supplies. Templates read it as {{ secrets.<name> }}.
type SecretDecl struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// ConfigSchema is the JSON Schema subset a package may declare for its connector's config: an object with typed
// properties. It is enough for forms and for refusing a wrong config; anything richer is refused, not ignored.
type ConfigSchema struct {
	Type       string                    `json:"type"`
	Required   []string                  `json:"required,omitempty"`
	Properties map[string]PropertySchema `json:"properties,omitempty"`
}

// PropertySchema is one config property.
type PropertySchema struct {
	Type        string   `json:"type"` // string | integer | number | boolean
	Description string   `json:"description,omitempty"`
	Enum        []string `json:"enum,omitempty"`
}

// SendSpec is the one request a notifier makes per message, and the condition its answer must meet.
type SendSpec struct {
	Request RequestSpec `json:"request"`
	// Expect is a CEL condition over `status` (int) that the answer must meet, e.g. 'status == 200'. Default 2xx.
	Expect string `json:"expect,omitempty"`
}

// RequestSpec is a templated HTTP request.
type RequestSpec struct {
	Method  string            `json:"method,omitempty"` // POST (default) | PUT | PATCH
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	JSON    json.RawMessage   `json:"json,omitempty"`
	Body    string            `json:"body,omitempty"` // plain text, when there is no json
}

var (
	nameRe   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,40}$`)
	hostRe   = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	verRe    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)
	placeRe  = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)
	anyBrace = regexp.MustCompile(`\{\{[^}]*\}\}`)
)

// MessageFields are what a notifier template may read as {{ message.<field> }}: the canonical message every
// built-in notifier receives (docs/19 message.v1).
var MessageFields = []string{"title", "summary", "severity", "url", "appName", "findingId", "timestamp", "id"}

// notBuilt names what doc 19 describes and this version refuses, with what to do instead.
var notBuilt = map[string]string{
	"tracker":     "declarative trackers are not built yet; use a built-in tracker (Jira, GitHub)",
	"source":      "declarative sources are not built yet; Dependency-Track is the built-in source",
	"parser":      "parser mappings are not built yet; use a built-in parser",
	"wasm":        "code runtimes (wasm) are tier 2 and need a ClusterIntegrationPackage, which is not built",
	"grpc":        "code runtimes (grpc) are tier 2 and need a ClusterIntegrationPackage, which is not built",
	"mapping":     "runtime mapping is for parsers, which are not built yet",
	"declarative": "",
}

// Parse decodes and validates IntegrationPackage.spec strictly.
func Parse(raw []byte) (*Spec, error) {
	var s Spec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	s.Raw = append(json.RawMessage(nil), raw...)
	return &s, s.validate()
}

func (s *Spec) validate() error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: "+f, append([]any{ErrInvalid}, a...)...) }
	if why := notBuilt[s.Kind]; why != "" {
		return bad("kind %q: %s", s.Kind, why)
	}
	if s.Kind != "notifier" {
		return bad("kind %q: use notifier", s.Kind)
	}
	if why, known := notBuilt[s.Runtime]; known && why != "" {
		return bad("runtime %q: %s", s.Runtime, why)
	}
	if s.Runtime != "declarative" {
		return bad("runtime %q: use declarative", s.Runtime)
	}
	if !verRe.MatchString(s.Version) {
		return bad("version %q: use a semantic version such as 1.0.0", s.Version)
	}
	secrets := map[string]bool{}
	for _, d := range s.Secrets {
		if !nameRe.MatchString(d.Name) || secrets[d.Name] {
			return bad("secret name %q: letters, digits and _, unique", d.Name)
		}
		secrets[d.Name] = true
	}
	config := map[string]bool{}
	if s.ConfigSchema != nil {
		if s.ConfigSchema.Type != "object" {
			return bad("configSchema.type must be object")
		}
		for name, p := range s.ConfigSchema.Properties {
			if !nameRe.MatchString(name) {
				return bad("configSchema property %q: letters, digits and _", name)
			}
			switch p.Type {
			case "string", "integer", "number", "boolean":
			default:
				return bad("configSchema property %q: type %q is not supported (string, integer, number, boolean)", name, p.Type)
			}
			config[name] = true
		}
		for _, r := range s.ConfigSchema.Required {
			if !config[r] {
				return bad("configSchema.required names %q, which is not a property", r)
			}
		}
	}
	if len(s.Egress) == 0 {
		return bad("egress: list the hosts this package may reach")
	}
	for _, h := range s.Egress {
		// localhost is accepted as a name; reaching it still needs the platform's loopback allowance (D77).
		if net.ParseIP(h) != nil || (h != "localhost" && !hostRe.MatchString(h)) {
			return bad("egress %q: a host name, or *.domain; no addresses, ports or templates", h)
		}
	}
	if s.Send == nil || strings.TrimSpace(s.Send.Request.URL) == "" {
		return bad("send.request.url is required")
	}
	switch strings.ToUpper(s.Send.Request.Method) {
	case "", "POST", "PUT", "PATCH":
	default:
		return bad("send.request.method %q: POST, PUT or PATCH", s.Send.Request.Method)
	}
	if len(s.Send.Request.JSON) > 0 && s.Send.Request.Body != "" {
		return bad("send.request: json or body, not both")
	}
	// Every placeholder must name something that exists: a typo is refused at install, not found at 3 a.m.
	check := func(where, text string) error {
		if text == "" {
			return nil
		}
		matched := placeRe.FindAllStringSubmatchIndex(text, -1)
		if len(anyBrace.FindAllStringIndex(text, -1)) != len(matched) {
			return bad("%s: a template is {{ message.x }}, {{ config.x }} or {{ secrets.x }}, with no filters or logic", where)
		}
		for _, m := range placeRe.FindAllStringSubmatch(text, -1) {
			root, field := m[1], m[2]
			switch root {
			case "message":
				if !contains(MessageFields, field) {
					return bad("%s: message.%s does not exist (%s)", where, field, strings.Join(MessageFields, ", "))
				}
			case "config":
				if !config[field] {
					return bad("%s: config.%s is not in configSchema", where, field)
				}
			case "secrets":
				if !secrets[field] {
					return bad("%s: secrets.%s is not declared in secrets", where, field)
				}
			default:
				return bad("%s: %q is not readable; templates read message, config and secrets", where, root)
			}
		}
		return nil
	}
	if err := check("send.request.url", s.Send.Request.URL); err != nil {
		return err
	}
	for k, v := range s.Send.Request.Headers {
		if err := check("send.request.headers."+k, v); err != nil {
			return err
		}
		if strings.Contains(v, "{{") && strings.Contains(v, "message.") {
			return bad("send.request.headers.%s: a header cannot carry message text", k)
		}
	}
	if err := check("send.request.body", s.Send.Request.Body); err != nil {
		return err
	}
	if len(s.Send.Request.JSON) > 0 {
		var v any
		if err := json.Unmarshal(s.Send.Request.JSON, &v); err != nil {
			return bad("send.request.json: %v", err)
		}
		var walkErr error
		walkStrings(v, func(str string) string {
			if walkErr == nil {
				walkErr = check("send.request.json", str)
			}
			return str
		})
		if walkErr != nil {
			return walkErr
		}
	}
	if _, err := compileExpect(s.Send.Expect); err != nil {
		return bad("send.expect: %v", err)
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func compileExpect(expr string) (cel.Program, error) {
	if strings.TrimSpace(expr) == "" {
		expr = "status >= 200 && status < 300"
	}
	env, err := cel.NewEnv(cel.Variable("status", cel.IntType))
	if err != nil {
		return nil, err
	}
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("%q is not a condition", expr)
	}
	return env.Program(ast, cel.CostLimit(1000))
}

// ValidateConfig checks a connector's config against the package's schema.
func (s *Spec) ValidateConfig(raw json.RawMessage) (map[string]any, error) {
	cfg := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("%w: config is not an object: %v", ErrInvalid, err)
		}
	}
	props := map[string]PropertySchema{}
	var required []string
	if s.ConfigSchema != nil {
		props, required = s.ConfigSchema.Properties, s.ConfigSchema.Required
	}
	for k, v := range cfg {
		p, ok := props[k]
		if !ok {
			return nil, fmt.Errorf("%w: config.%s is not in the package's configSchema", ErrInvalid, k)
		}
		okType := false
		switch p.Type {
		case "string":
			_, okType = v.(string)
		case "boolean":
			_, okType = v.(bool)
		case "number":
			_, okType = v.(float64)
		case "integer":
			f, isNum := v.(float64)
			okType = isNum && f == float64(int64(f))
		}
		if !okType {
			return nil, fmt.Errorf("%w: config.%s must be a %s", ErrInvalid, k, p.Type)
		}
		if len(p.Enum) > 0 && !contains(p.Enum, fmt.Sprint(v)) {
			return nil, fmt.Errorf("%w: config.%s must be one of %s", ErrInvalid, k, strings.Join(p.Enum, ", "))
		}
	}
	for _, r := range required {
		if _, ok := cfg[r]; !ok {
			return nil, fmt.Errorf("%w: config.%s is required", ErrInvalid, r)
		}
	}
	return cfg, nil
}

// SecretNames lists the declared secrets, sorted.
func (s *Spec) SecretNames() []string {
	out := make([]string, 0, len(s.Secrets))
	for _, d := range s.Secrets {
		out = append(out, d.Name)
	}
	sort.Strings(out)
	return out
}

// Values are what a template reads.
type Values struct {
	Message map[string]string
	Config  map[string]any
	Secrets map[string]string
}

func (v Values) lookup(root, field string) string {
	switch root {
	case "message":
		return v.Message[field]
	case "config":
		if x, ok := v.Config[field]; ok {
			if f, isNum := x.(float64); isNum && f == float64(int64(f)) {
				return fmt.Sprint(int64(f))
			}
			return fmt.Sprint(x)
		}
	case "secrets":
		return v.Secrets[field]
	}
	return ""
}

func (v Values) render(s string) string {
	return placeRe.ReplaceAllStringFunc(s, func(m string) string {
		p := placeRe.FindStringSubmatch(m)
		return v.lookup(p[1], p[2])
	})
}

// walkStrings rewrites every string in a decoded JSON value. Keys are left as written.
func walkStrings(v any, f func(string) string) any {
	switch x := v.(type) {
	case string:
		return f(x)
	case map[string]any:
		for k, e := range x {
			x[k] = walkStrings(e, f)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = walkStrings(e, f)
		}
		return x
	}
	return v
}

// Doer sends a request; the SSRF-safe client of internal/connectors implements it.
type Doer interface {
	Do(req *http.Request) ([]byte, int, http.Header, error)
}

// Notifier sends messages for one connector of a package.
type Notifier struct {
	spec   *Spec
	vals   Values
	doer   Doer
	expect cel.Program
}

// NewNotifier binds a package to a connector's config and secrets. Every declared secret must be supplied.
func NewNotifier(spec *Spec, config map[string]any, secrets map[string]string, doer Doer) (*Notifier, error) {
	for _, n := range spec.SecretNames() {
		if strings.TrimSpace(secrets[n]) == "" {
			return nil, fmt.Errorf("%w: secret %q is declared by the package and not supplied by the connector", ErrInvalid, n)
		}
	}
	prg, err := compileExpect(spec.Send.Expect)
	if err != nil {
		return nil, err
	}
	return &Notifier{spec: spec, vals: Values{Config: config, Secrets: secrets}, doer: doer, expect: prg}, nil
}

// ErrEgress refuses a request whose rendered host is not one the package declared.
var ErrEgress = errors.New("integration package: host not in egress")

func hostAllowed(host string, egress []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, e := range egress {
		if strings.HasPrefix(e, "*.") {
			if strings.HasSuffix(host, e[1:]) && len(host) > len(e)-1 {
				return true
			}
		} else if host == e {
			return true
		}
	}
	return false
}

// Send renders the request for one message and sends it. The rendered URL must be https and reach a declared
// host; the client then refuses private addresses and cross-host redirects (docs/19 §11).
func (n *Notifier) Send(ctx context.Context, message map[string]string) error {
	v := n.vals
	v.Message = message
	r := n.spec.Send.Request
	raw := v.render(r.URL)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: the rendered url is not a url", ErrInvalid)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && allowHTTP(n.doer)) {
		return fmt.Errorf("%w: the url must be https", ErrInvalid)
	}
	if !hostAllowed(u.Hostname(), n.spec.Egress) {
		return fmt.Errorf("%w: %s (declared: %s)", ErrEgress, u.Hostname(), strings.Join(n.spec.Egress, ", "))
	}
	var body []byte
	contentType := "text/plain; charset=utf-8"
	if len(r.JSON) > 0 {
		var doc any
		_ = json.Unmarshal(r.JSON, &doc) // validated at Parse
		doc = walkStrings(doc, v.render)
		// json.Marshal escapes whatever the message holds: a title cannot break out of its string.
		if body, err = json.Marshal(doc); err != nil {
			return err
		}
		contentType = "application/json"
	} else {
		body = []byte(v.render(r.Body))
	}
	method := strings.ToUpper(r.Method)
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "rampart-notifier")
	for k, h := range r.Headers {
		req.Header.Set(k, v.render(h))
	}
	_, status, _, err := n.doer.Do(req)
	if err != nil {
		return err
	}
	out, _, err := n.expect.Eval(map[string]any{"status": int64(status)})
	if err != nil {
		return err
	}
	if ok, _ := out.Value().(bool); !ok {
		return fmt.Errorf("integration package: the answer did not meet send.expect (status %d)", status)
	}
	return nil
}

// allowHTTP lets the test harness, whose client allows loopback, use a plain-http receiver.
func allowHTTP(d Doer) bool {
	if l, ok := d.(interface{ AllowLoopback() bool }); ok {
		return l.AllowLoopback()
	}
	return false
}
