package telemetry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"rampart/internal/telemetry"
)

// Metric labels use the matched route pattern, never the raw path, so ids in URLs cannot blow up
// the number of series.
func TestHTTPMetricsUseTheRoutePatternNotTheRawPath(t *testing.T) {
	p, err := telemetry.Setup(context.Background(), telemetry.Config{Version: "test", Target: "all"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	rec := tracetest.NewSpanRecorder()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/items/{id}", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := telemetry.RequestIDMiddleware(telemetry.HTTPMiddleware(mux))
	for _, id := range []string{"1", "2", "3"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/items/"+id, nil))
		if w.Code != 200 || w.Header().Get("X-Request-ID") == "" {
			t.Fatalf("request %s: %d, request id %q", id, w.Code, w.Header().Get("X-Request-ID"))
		}
	}

	w := httptest.NewRecorder()
	p.MetricsHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	body := w.Body.String()
	if !strings.Contains(body, `http_route="/api/v1/items/{id}"`) {
		t.Errorf("the route pattern must label the metrics:\n%s", grep(body, "http_server_request_duration_seconds_count"))
	}
	for _, id := range []string{"/items/1", "/items/2", "/items/3"} {
		if strings.Contains(body, id) {
			t.Errorf("a raw path (%s) leaked into metric labels", id)
		}
	}
	if !strings.Contains(body, "go_goroutines") || !strings.Contains(body, "target_info") {
		t.Error("runtime metrics and the resource info must be exported")
	}

	spans := rec.Ended()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}
	if name := spans[0].Name(); strings.Contains(name, "/items/1") {
		t.Errorf("span names must not contain raw ids, got %q", name)
	}
}

func grep(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
