package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
)

// Config configures OpenTelemetry (D6: telemetry.otlpEndpoint).
type Config struct {
	ServiceName  string // default "rampart"
	Version      string
	Target       string // the -target value, reported as a resource attribute
	OTLPEndpoint string // e.g. http://otel-collector:4318; empty disables OTLP export
}

// Provider owns the metric and trace pipelines. Metrics are always available on /metrics in the
// Prometheus text format; traces and OTLP metrics are exported only when an endpoint is set.
type Provider struct {
	registry *prometheus.Registry
	shutdown []func(context.Context) error
	otlp     bool
}

// Setup installs the global tracer and meter providers and the W3C propagators.
func Setup(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "rampart"
	}
	host, _ := os.Hostname()
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName(cfg.ServiceName),
		semconv.ServiceVersion(cfg.Version),
		semconv.ServiceInstanceID(host),
		attribute.String("rampart.target", cfg.Target),
	))
	if err != nil {
		return nil, err
	}

	p := &Provider{registry: prometheus.NewRegistry()}
	p.registry.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	promReader, err := otelprom.New(otelprom.WithRegisterer(p.registry), otelprom.WithoutScopeInfo())
	if err != nil {
		return nil, fmt.Errorf("telemetry: prometheus exporter: %w", err)
	}
	mopts := []sdkmetric.Option{sdkmetric.WithResource(res), sdkmetric.WithReader(promReader)}
	topts := []sdktrace.TracerProviderOption{sdktrace.WithResource(res)}

	if cfg.OTLPEndpoint != "" {
		p.otlp = true
		me, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(cfg.OTLPEndpoint))
		if err != nil {
			return nil, fmt.Errorf("telemetry: otlp metrics: %w", err)
		}
		mopts = append(mopts, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(me, sdkmetric.WithInterval(15*time.Second))))
		te, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(cfg.OTLPEndpoint))
		if err != nil {
			return nil, fmt.Errorf("telemetry: otlp traces: %w", err)
		}
		topts = append(topts, sdktrace.WithBatcher(te))
	}

	mp := sdkmetric.NewMeterProvider(mopts...)
	tp := sdktrace.NewTracerProvider(topts...)
	otel.SetMeterProvider(mp)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	p.shutdown = []func(context.Context) error{tp.Shutdown, mp.Shutdown}
	return p, nil
}

// OTLPEnabled reports whether telemetry is being exported.
func (p *Provider) OTLPEnabled() bool { return p.otlp }

// MetricsHandler serves /metrics (Prometheus text format).
func (p *Provider) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{})
}

// Shutdown flushes and stops the pipelines.
func (p *Provider) Shutdown(ctx context.Context) error {
	var errs []error
	for _, f := range p.shutdown {
		errs = append(errs, f(ctx))
	}
	return errors.Join(errs...)
}

// HTTPMiddleware traces and measures every request. The route label is the matched ServeMux
// pattern (never the raw path), so metric cardinality stays bounded even with ids in URLs.
func HTTPMiddleware(next http.Handler) http.Handler {
	return otelhttp.NewHandler(next, "http.server",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string { return r.Method + " " + routeOf(r) }),
		otelhttp.WithFilter(func(r *http.Request) bool { return r.URL.Path != "/healthz" && r.URL.Path != "/readyz" }),
	)
}

func routeOf(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return "unmatched"
}

// TraceID returns the trace id of the span in ctx, or "".
func TraceID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

// CorrelatingHandler adds trace_id, span_id and request_id to every log record written with a
// context that carries them (logger.InfoContext), so logs, traces and a support ticket line up.
type CorrelatingHandler struct{ slog.Handler }

// Handle implements slog.Handler.
func (h CorrelatingHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	if id := RequestID(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

// WithAttrs implements slog.Handler.
func (h CorrelatingHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return CorrelatingHandler{h.Handler.WithAttrs(a)}
}

// WithGroup implements slog.Handler.
func (h CorrelatingHandler) WithGroup(n string) slog.Handler {
	return CorrelatingHandler{h.Handler.WithGroup(n)}
}
