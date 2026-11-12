package sarif_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"rampart/internal/domain"
	"rampart/internal/parsers/sarif"
)

// Fuzz: whatever the bytes are, the parser must not panic or hang, and every error is an error value
// (a hostile report must never take the worker down; doc 05, D15).
func FuzzSarifParse(f *testing.F) {
	seeds, _ := filepath.Glob("testdata/*")
	for _, p := range seeds {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte("[]"))
	f.Add([]byte(`{"version":"2.1.0","runs":[{"results":[{}]}]}`))
	p := sarif.NewParser()
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = p.Detect(data[:min(len(data), 4096)], "report.json", "application/json")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		n := 0
		for _, err := range p.Parse(ctx, bytes.NewReader(data), domain.ParseContext{}) {
			_ = err
			if n++; n > 1_000_000 {
				t.Fatal("parser produced an unbounded number of records")
			}
		}
		if ctx.Err() != nil {
			t.Fatal("parser did not finish within 5 s on a small input")
		}
	})
}
