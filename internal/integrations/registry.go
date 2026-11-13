package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"sync"

	"rampart/internal/domain"
)

var (
	ErrIntegrationNotFound  = errors.New("integrations: integration not found")
	ErrDuplicateIntegration = errors.New("integrations: duplicate integration registration")
)

// IntegrationKind categorizes the integration extension point (docs/19 §1).
type IntegrationKind string

const (
	KindParser   IntegrationKind = "parser"
	KindSource   IntegrationKind = "source"
	KindTracker  IntegrationKind = "tracker"
	KindNotifier IntegrationKind = "notifier"
)

// SupportLevel indicates official tier (built-in, certified, community).
type SupportLevel string

const (
	SupportBuiltin   SupportLevel = "builtin"
	SupportCertified SupportLevel = "certified"
	SupportCommunity SupportLevel = "community"
)

// Descriptor provides metadata about an integration component.
type Descriptor struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Kind         IntegrationKind `json:"kind"`
	Version      string          `json:"version"`
	SupportLevel SupportLevel    `json:"support_level"`
	Description  string          `json:"description"`
	ConfigSchema json.RawMessage `json:"config_schema,omitempty"`
	Secrets      []string        `json:"secrets,omitempty"`
	Egress       []string        `json:"egress,omitempty"`
	Capabilities []string        `json:"capabilities,omitempty"`
}

// ParserContract defines the ingestion parsing interface (docs/19 §2).
type ParserContract interface {
	Descriptor() Descriptor
	Detect(head []byte, filename string, contentType string) (confidence int)
	Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error]
}

// UpstreamProject represents an asset/project discovered in an upstream source (docs/19 §3).
type UpstreamProject struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Version    string            `json:"version,omitempty"`
	Purl       string            `json:"purl,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

// SourceContract defines API pull integrations (docs/19 §3).
type SourceContract interface {
	Descriptor() Descriptor
	Check(ctx context.Context, cfg any) error
	Discover(ctx context.Context, cfg any) iter.Seq2[UpstreamProject, error]
	Pull(ctx context.Context, cfg any, project UpstreamProject, cursor string) (iter.Seq2[domain.RawFinding, error], string, error)
}

// IssueDraft represents canonical ticket parameters to create or update (docs/19 §3).
type IssueDraft struct {
	Title      string   `json:"title"`
	Body       string   `json:"body"`
	Severity   string   `json:"severity"`
	Labels     []string `json:"labels,omitempty"`
	ProjectKey string   `json:"project_key,omitempty"`
	ExternalID string   `json:"external_id,omitempty"`
}

// IssueRef uniquely identifies a tracker issue.
type IssueRef struct {
	Key string `json:"key"`
	URL string `json:"url"`
}

// IssueState reflects remote ticket resolution.
type IssueState struct {
	Key        string `json:"key"`
	Status     string `json:"status"`
	Resolution string `json:"resolution,omitempty"`
	Closed     bool   `json:"closed"`
}

// TrackerContract defines outbound ticketing integrations (docs/19 §3).
type TrackerContract interface {
	Descriptor() Descriptor
	Check(ctx context.Context, cfg any) error
	Create(ctx context.Context, cfg any, draft IssueDraft) (IssueRef, error)
	Update(ctx context.Context, cfg any, ref IssueRef, draft IssueDraft) error
	Get(ctx context.Context, cfg any, refs []IssueRef) ([]IssueState, error)
}

// Message represents canonical outbound notification content (docs/19 §3).
type Message struct {
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Body    string `json:"body"`
	URL     string `json:"url,omitempty"`
	Level   string `json:"level,omitempty"`
}

// NotifierContract defines outbound notification integrations (docs/19 §3).
type NotifierContract interface {
	Descriptor() Descriptor
	Check(ctx context.Context, cfg any) error
	Send(ctx context.Context, cfg any, m Message) error
}

// Registry maintains the catalogue of all available integrations across all tiers.
type Registry struct {
	mu        sync.RWMutex
	parsers   map[string]ParserContract
	sources   map[string]SourceContract
	trackers  map[string]TrackerContract
	notifiers map[string]NotifierContract
}

// NewRegistry initializes an empty integration registry.
func NewRegistry() *Registry {
	return &Registry{
		parsers:   make(map[string]ParserContract),
		sources:   make(map[string]SourceContract),
		trackers:  make(map[string]TrackerContract),
		notifiers: make(map[string]NotifierContract),
	}
}

// RegisterParser registers a parser contract in the registry.
func (r *Registry) RegisterParser(p ParserContract) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := p.Descriptor().ID
	if _, exists := r.parsers[id]; exists {
		return fmt.Errorf("%w: parser %q already registered", ErrDuplicateIntegration, id)
	}

	r.parsers[id] = p
	return nil
}

// GetParser retrieves a parser by ID.
func (r *Registry) GetParser(id string) (ParserContract, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, exists := r.parsers[id]
	if !exists {
		return nil, fmt.Errorf("%w: parser %q", ErrIntegrationNotFound, id)
	}
	return p, nil
}

// ListParsers returns all registered parsers.
func (r *Registry) ListParsers() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var list []Descriptor
	for _, p := range r.parsers {
		list = append(list, p.Descriptor())
	}
	return list
}

// DetectParser finds the best matching parser for an incoming report.
func (r *Registry) DetectParser(head []byte, filename string, contentType string) (ParserContract, int) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var best ParserContract
	bestScore := 0

	for _, p := range r.parsers {
		score := p.Detect(head, filename, contentType)
		if score > bestScore {
			bestScore = score
			best = p
		}
	}

	return best, bestScore
}

// RegisterSource registers a source contract in the registry.
func (r *Registry) RegisterSource(s SourceContract) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := s.Descriptor().ID
	if _, exists := r.sources[id]; exists {
		return fmt.Errorf("%w: source %q already registered", ErrDuplicateIntegration, id)
	}

	r.sources[id] = s
	return nil
}

// GetSource retrieves a source by ID.
func (r *Registry) GetSource(id string) (SourceContract, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	s, exists := r.sources[id]
	if !exists {
		return nil, fmt.Errorf("%w: source %q", ErrIntegrationNotFound, id)
	}
	return s, nil
}

// ListSources returns all registered sources.
func (r *Registry) ListSources() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var list []Descriptor
	for _, s := range r.sources {
		list = append(list, s.Descriptor())
	}
	return list
}

// RegisterTracker registers a tracker contract in the registry.
func (r *Registry) RegisterTracker(t TrackerContract) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := t.Descriptor().ID
	if _, exists := r.trackers[id]; exists {
		return fmt.Errorf("%w: tracker %q already registered", ErrDuplicateIntegration, id)
	}

	r.trackers[id] = t
	return nil
}

// GetTracker retrieves a tracker by ID.
func (r *Registry) GetTracker(id string) (TrackerContract, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, exists := r.trackers[id]
	if !exists {
		return nil, fmt.Errorf("%w: tracker %q", ErrIntegrationNotFound, id)
	}
	return t, nil
}

// ListTrackers returns all registered trackers.
func (r *Registry) ListTrackers() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var list []Descriptor
	for _, t := range r.trackers {
		list = append(list, t.Descriptor())
	}
	return list
}

// RegisterNotifier registers a notifier contract in the registry.
func (r *Registry) RegisterNotifier(n NotifierContract) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := n.Descriptor().ID
	if _, exists := r.notifiers[id]; exists {
		return fmt.Errorf("%w: notifier %q already registered", ErrDuplicateIntegration, id)
	}

	r.notifiers[id] = n
	return nil
}

// GetNotifier retrieves a notifier by ID.
func (r *Registry) GetNotifier(id string) (NotifierContract, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	n, exists := r.notifiers[id]
	if !exists {
		return nil, fmt.Errorf("%w: notifier %q", ErrIntegrationNotFound, id)
	}
	return n, nil
}

// ListNotifiers returns all registered notifiers.
func (r *Registry) ListNotifiers() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var list []Descriptor
	for _, n := range r.notifiers {
		list = append(list, n.Descriptor())
	}
	return list
}

// ListAll returns descriptors of all registered integrations across all kinds.
func (r *Registry) ListAll() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var list []Descriptor
	for _, p := range r.parsers {
		list = append(list, p.Descriptor())
	}
	for _, s := range r.sources {
		list = append(list, s.Descriptor())
	}
	for _, t := range r.trackers {
		list = append(list, t.Descriptor())
	}
	for _, n := range r.notifiers {
		list = append(list, n.Descriptor())
	}
	return list
}
