package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"

	otelslog "go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/version"
)

// multiHandler broadcasts log records to multiple handlers.
type multiHandler struct {
	handlers []slog.Handler
}

// newMultiHandler creates a handler that writes to multiple handlers.
// Returns nil if no handlers provided, the single handler if only one, or a multiHandler for multiple.
func newMultiHandler(handlers ...slog.Handler) slog.Handler {
	var nonNil []slog.Handler
	for _, h := range handlers {
		if h != nil {
			nonNil = append(nonNil, h)
		}
	}

	switch len(nonNil) {
	case 0:
		return nil
	case 1:
		return nonNil[0]
	default:
		return multiHandler{handlers: nonNil}
	}
}

func (m multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m multiHandler) Handle(ctx context.Context, record slog.Record) error {
	var enabled []slog.Handler
	for _, h := range m.handlers {
		if h.Enabled(ctx, record.Level) {
			enabled = append(enabled, h)
		}
	}

	lastIdx := len(enabled) - 1
	for i, h := range enabled {
		r := record
		if i < lastIdx {
			r = record.Clone()
		}
		if err := h.Handle(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

func (m multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		handlers[i] = h.WithAttrs(attrs)
	}
	return multiHandler{handlers: handlers}
}

func (m multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		handlers[i] = h.WithGroup(name)
	}
	return multiHandler{handlers: handlers}
}

// BuildOTLPLogExporter creates an OTLP-backed slog logger that exports logs via gRPC.
func BuildOTLPLogExporter(ctx context.Context, logger *slog.Logger, commons config.BackendCommons) (*slog.Logger, func(context.Context) error, error) {
	endpoint := strings.TrimSpace(commons.Otlp.Grpc)
	if endpoint == "" {
		return logger, nil, nil
	}

	exporter, err := newLogExporter(ctx, endpoint)
	if err != nil {
		return logger, nil, err
	}
	exporter = newResilientLogExporter(exporter, logger, endpoint)

	res, err := buildResource(commons.Otlp.AgentLabels)
	if err != nil {
		return logger, nil, err
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)

	handler := otelslog.NewHandler(
		"orb-agent",
		otelslog.WithLoggerProvider(provider),
	)

	var resultingLogger *slog.Logger
	if logger != nil {
		if combined := newMultiHandler(logger.Handler(), handler); combined != nil {
			*logger = *slog.New(combined)
		}
		resultingLogger = logger
	} else {
		resultingLogger = slog.New(handler)
	}

	return resultingLogger, provider.Shutdown, nil
}

// buildResource creates an OTLP resource with service information and custom labels.
func buildResource(labels map[string]string) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String("orb-agent"),
		semconv.ServiceVersionKey.String(version.GetBuildVersion()),
	}

	for k, v := range labels {
		if strings.TrimSpace(k) != "" {
			attrs = append(attrs, attribute.String(k, v))
		}
	}

	defaultRes := resource.Default()
	customRes := resource.NewWithAttributes(defaultRes.SchemaURL(), attrs...)

	return resource.Merge(defaultRes, customRes)
}

// newLogExporter constructs a gRPC log exporter after normalizing the endpoint.
func newLogExporter(ctx context.Context, endpoint string) (sdklog.Exporter, error) {
	addr, insecure, err := normalizeEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	opts := []otlploggrpc.Option{otlploggrpc.WithEndpoint(addr)}

	if insecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	}

	return otlploggrpc.New(ctx, opts...)
}

// normalizeEndpoint converts URLs such as https://host:port into host:port and infers TLS usage.
func normalizeEndpoint(raw string) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, fmt.Errorf("empty OTLP endpoint")
	}

	// Assume insecure for bare host:port input
	if !strings.Contains(raw, "://") {
		return raw, true, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", false, fmt.Errorf("parse OTLP endpoint %q: %w", raw, err)
	}

	host := u.Host
	if host == "" {
		host = u.Path
	}
	if host == "" {
		return "", false, fmt.Errorf("invalid OTLP endpoint %q: missing host", raw)
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "grpc":
		return host, true, nil
	case "https", "grpcs":
		return host, false, nil
	default:
		return "", false, fmt.Errorf("unsupported OTLP endpoint scheme %q", u.Scheme)
	}
}

// resilientLogExporter wraps an exporter to provide resilience and error logging.
type resilientLogExporter struct {
	endpoint string
	logger   *slog.Logger
	warnOnce sync.Once

	mu       sync.RWMutex
	exporter sdklog.Exporter
}

// newResilientLogExporter wraps an exporter to log errors on first failure.
func newResilientLogExporter(exp sdklog.Exporter, logger *slog.Logger, endpoint string) sdklog.Exporter {
	if exp == nil {
		return nil
	}
	return &resilientLogExporter{
		endpoint: endpoint,
		logger:   logger,
		exporter: exp,
	}
}

func (r *resilientLogExporter) Export(ctx context.Context, records []sdklog.Record) error {
	r.mu.RLock()
	exp := r.exporter
	r.mu.RUnlock()

	if exp == nil {
		return nil
	}

	if err := exp.Export(ctx, records); err != nil {
		r.warnOnce.Do(func() {
			if r.logger != nil {
				r.logger.Error("OTLP gRPC log export failed",
					"endpoint", r.endpoint,
					"error", err)
			}
		})
		return err
	}

	return nil
}

func (r *resilientLogExporter) ForceFlush(ctx context.Context) error {
	r.mu.RLock()
	exp := r.exporter
	r.mu.RUnlock()

	if exp == nil {
		return nil
	}
	return exp.ForceFlush(ctx)
}

func (r *resilientLogExporter) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	exp := r.exporter
	r.exporter = nil
	r.mu.Unlock()

	if exp == nil {
		return nil
	}
	return exp.Shutdown(ctx)
}
