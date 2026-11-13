package integrations

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/cel-go/cel"
)

// TestSpike6_StreamingPathSelectionWithCEL measures the speed and memory profile
// of streaming path selection and CEL expression evaluation across records (Spike 6).
// Limitations: Synthetic records and simple title expression; see docs/16 D69.
func TestSpike6_StreamingPathSelectionWithCEL(t *testing.T) {
	totalRecords := 100_000
	if testing.Short() {
		totalRecords = 1_000
	}

	// 1. Set up CEL environment with record variables and custom helpers
	env, err := cel.NewEnv(
		cel.Variable("rec", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("dep", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		t.Fatalf("failed to initialize CEL environment: %v", err)
	}

	// Expression corresponding to docs/19 §4 (ParserMapping spec)
	titleExpr := `rec.id + " in " + dep.name`
	ast, issues := env.Compile(titleExpr)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("failed to compile CEL title expression: %v", issues.Err())
	}
	titleProg, err := env.Program(ast, cel.CostLimit(1000))
	if err != nil {
		t.Fatalf("failed to build CEL program: %v", err)
	}

	// 2. Build a streaming reader that emits a realistic nested JSON report without buffering in memory
	pr, pw := io.Pipe()
	go func() {
		defer func() { _ = pw.Close() }()
		_, _ = fmt.Fprint(pw, `{"dependencies":[`)
		for i := 0; i < totalRecords; i++ {
			if i > 0 {
				_, _ = fmt.Fprint(pw, `,`)
			}
			_, _ = fmt.Fprintf(pw, `{"name":"pkg-%d","version":"1.0.%d","vulns":[{"id":"GHSA-%05d","desc":"test vulnerability %d","sev":"HIGH"}]}`,
				i%1000, i%10, i, i)
		}
		_, _ = fmt.Fprint(pw, `]}`)
	}()

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()
	var processedRecords int
	dec := json.NewDecoder(pr)

	// Stream through JSON using token walk
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("expected '{', got %v (err: %v)", tok, err)
	}

	for dec.More() {
		tKey, err := dec.Token()
		if err != nil {
			t.Fatalf("error reading token: %v", err)
		}
		if tKey != "dependencies" {
			var skip any
			_ = dec.Decode(&skip)
			continue
		}

		tok, err := dec.Token()
		if err != nil || tok != json.Delim('[') {
			t.Fatalf("expected '[', got %v (err: %v)", tok, err)
		}

		for dec.More() {
			var depWrapper struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Vulns   []struct {
					ID   string `json:"id"`
					Desc string `json:"desc"`
					Sev  string `json:"sev"`
				} `json:"vulns"`
			}
			if err := dec.Decode(&depWrapper); err != nil {
				t.Fatalf("failed decoding dependency record: %v", err)
			}

			depMap := map[string]any{
				"name":    depWrapper.Name,
				"version": depWrapper.Version,
			}

			for _, v := range depWrapper.Vulns {
				recMap := map[string]any{
					"id":   v.ID,
					"desc": v.Desc,
					"sev":  v.Sev,
				}

				out, _, evalErr := titleProg.Eval(map[string]any{
					"rec": recMap,
					"dep": depMap,
				})
				if evalErr != nil {
					t.Fatalf("CEL evaluation failed on record %d: %v", processedRecords, evalErr)
				}

				resStr, ok := out.Value().(string)
				if !ok || !strings.Contains(resStr, " in ") {
					t.Fatalf("unexpected CEL eval result: %v", out.Value())
				}

				processedRecords++
			}
		}

		_, _ = dec.Token()
	}

	elapsed := time.Since(start)

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	heapAllocDiff := int64(memAfter.HeapAlloc) - int64(memBefore.HeapAlloc)
	if heapAllocDiff < 0 {
		heapAllocDiff = 0
	}
	heapAllocMB := float64(heapAllocDiff) / (1024 * 1024)
	recordsPerSec := float64(processedRecords) / elapsed.Seconds()

	t.Logf("=== Spike 6 Informational Results ===")
	t.Logf("Processed records: %d", processedRecords)
	t.Logf("Elapsed time: %v (%.0f records/sec)", elapsed, recordsPerSec)
	t.Logf("HeapAlloc delta: %.2f MB", heapAllocMB)
	t.Logf("Sys memory: %.2f MB", float64(memAfter.Sys)/(1024*1024))

	if processedRecords != totalRecords {
		t.Fatalf("expected %d records, processed %d", totalRecords, processedRecords)
	}

	// Memory sanity check: should not balloon wildly even without hard timing failure
	if heapAllocMB > 150.0 {
		t.Errorf("heap memory allocation delta %.2f MB exceeded 150 MB safety margin", heapAllocMB)
	}
}
