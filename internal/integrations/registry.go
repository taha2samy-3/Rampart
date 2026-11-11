package integrations

import (
	"context"
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
}

// ParserContract defines the ingestion parsing interface (docs/19 §2).
type ParserContract interface {
	Descriptor() Descriptor
	Detect(head []byte, filename string, contentType string) (confidence int)
	Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error]
}

// Registry maintains the catalogue of all available integrations across all tiers.
type Registry struct {
	mu      sync.RWMutex
	parsers map[string]ParserContract
}

// NewRegistry initializes an empty integration registry.
func NewRegistry() *Registry {
	return &Registry{
		parsers: make(map[string]ParserContract),
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
