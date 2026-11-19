package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"rampart/internal/domain"
)

func main() {
	p := NewParser()
	w := bufio.NewWriter(os.Stdout)
	defer func() { _ = w.Flush() }()

	enc := json.NewEncoder(w)
	ctx := context.Background()
	pc := domain.ParseContext{
		TenantID:      domain.NewID(),
		ScanSourceID:  domain.NewID(),
		ScannerFamily: "trufflehog",
		Track:         "main",
	}
	if os.Getenv("RAMPART_RECORD_ERRORS") == "1" {
		// The host wants a bad record reported, not the whole report stopped (docs/16 D13).
		pc.RecordError = func(re domain.RecordError) { _ = enc.Encode(map[string]domain.RecordError{"__record_error": re}) }
	}

	for f, err := range p.Parse(ctx, os.Stdin, pc) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "trufflehog wasm parse error: %v\n", err)
			os.Exit(1)
		}
		if err := enc.Encode(f); err != nil {
			fmt.Fprintf(os.Stderr, "trufflehog wasm encode error: %v\n", err)
			os.Exit(1)
		}
	}
}
