package parsers

import (
	"context"
	"errors"
	"io"
	"iter"
	"sync"

	"rampart/internal/domain"
)

var (
	ErrUnknownFormat = errors.New("parsers: unknown report format")
	ErrAborted       = errors.New("parsers: parsing aborted by context")
)

// Parser defines the streaming extraction contract (docs/05 §2).
type Parser interface {
	// Name identifies the parser implementation.
	Name() string

	// Detect inspects the initial byte header and filename/MIME hints to score confidence (0–100).
	Detect(head []byte, filename string, contentType string) (confidence int)

	// Parse streams findings one by one using Go 1.23+ iterators without unbounded allocations (D15).
	Parse(ctx context.Context, r io.Reader, pc domain.ParseContext) iter.Seq2[domain.RawFinding, error]
}

// Registry maintains the set of active format parsers.
type Registry struct {
	mu      sync.RWMutex
	parsers []Parser
}

// NewRegistry creates a new parser registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a parser to the registry.
func (r *Registry) Register(p Parser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.parsers = append(r.parsers, p)
}

// Detect matches the best parser for the given input.
func (r *Registry) Detect(head []byte, filename string, contentType string) (Parser, int) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var bestParser Parser
	bestScore := 0

	for _, p := range r.parsers {
		score := p.Detect(head, filename, contentType)
		if score > bestScore {
			bestScore = score
			bestParser = p
		}
	}

	return bestParser, bestScore
}
