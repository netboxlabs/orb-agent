package telemetry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/version"
)

func TestBuildOTLPLogExporterEmptyEndpoint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	commons := config.BackendCommons{}

	resultLogger, shutdown, err := BuildOTLPLogExporter(context.Background(), logger, commons)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resultLogger != logger {
		t.Fatalf("expected same logger pointer when endpoint empty")
	}
	if shutdown != nil {
		t.Fatalf("expected shutdown to be nil when endpoint empty")
	}
}

func TestBuildOTLPExporterInvalidEndpoint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	commons := config.BackendCommons{}
	commons.Otlp.Grpc = "ftp://not-supported"

	resultLogger, shutdown, err := BuildOTLPLogExporter(context.Background(), logger, commons)
	if err == nil {
		t.Fatalf("expected error for unsupported scheme")
	}
	if resultLogger != logger {
		t.Fatalf("expected original logger to be returned on error")
	}
	if shutdown != nil {
		t.Fatalf("expected shutdown to be nil on error")
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		raw          string
		wantAddr     string
		wantInsecure bool
		wantErr      string
	}{
		{
			name:    "empty",
			raw:     "",
			wantErr: "empty OTLP endpoint",
		},
		{
			name:         "plain host",
			raw:          "collector:4317",
			wantAddr:     "collector:4317",
			wantInsecure: true,
		},
		{
			name:         "trimmed host",
			raw:          "  collector:4317 ",
			wantAddr:     "collector:4317",
			wantInsecure: true,
		},
		{
			name:         "http scheme",
			raw:          "http://collector:4317",
			wantAddr:     "collector:4317",
			wantInsecure: true,
		},
		{
			name:         "grpc scheme",
			raw:          "grpc://collector:4317",
			wantAddr:     "collector:4317",
			wantInsecure: true,
		},
		{
			name:         "https scheme",
			raw:          "https://collector:4317",
			wantAddr:     "collector:4317",
			wantInsecure: false,
		},
		{
			name:         "grpcs scheme",
			raw:          "grpcs://collector:4317",
			wantAddr:     "collector:4317",
			wantInsecure: false,
		},
		{
			name:         "path host",
			raw:          "https://collector:4317/path",
			wantAddr:     "collector:4317",
			wantInsecure: false,
		},
		{
			name:    "unsupported scheme",
			raw:     "ftp://collector",
			wantErr: "unsupported OTLP endpoint scheme",
		},
		{
			name:    "missing host",
			raw:     "http://",
			wantErr: "missing host",
		},
		{
			name:    "invalid URL",
			raw:     "http://[::1",
			wantErr: "parse OTLP endpoint",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotAddr, gotInsecure, err := normalizeEndpoint(tt.raw)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error to contain %q, got %q", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotAddr != tt.wantAddr {
				t.Fatalf("unexpected addr: got %q want %q", gotAddr, tt.wantAddr)
			}
			if gotInsecure != tt.wantInsecure {
				t.Fatalf("unexpected insecure flag: got %v want %v", gotInsecure, tt.wantInsecure)
			}
		})
	}
}

func TestNewMultiHandlerCases(t *testing.T) {
	t.Parallel()

	if handler := newMultiHandler(); handler != nil {
		t.Fatalf("expected nil handler when no handlers provided")
	}

	h := &captureHandler{enabled: true}
	if handler := newMultiHandler(h); handler != h {
		t.Fatalf("expected single handler to be returned as-is")
	}
}

func TestMultiHandlerBehaviour(t *testing.T) {
	t.Parallel()

	mutator := &captureHandler{enabled: true, mutate: true}
	collector := &captureHandler{enabled: true}

	handler := newMultiHandler(mutator, collector)
	if handler == nil {
		t.Fatalf("expected non-nil handler for multiple handlers")
	}

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "test", 0)
	if err := handler.Handle(context.Background(), record); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mutator.records) != 1 || len(collector.records) != 1 {
		t.Fatalf("expected both handlers to receive the record")
	}

	if !attrExists(mutator.records[0], "mutated") {
		t.Fatalf("expected mutator to see mutated attribute")
	}
	if attrExists(collector.records[0], "mutated") {
		t.Fatalf("expected collector to receive original record without mutation")
	}

	if !handler.Enabled(context.Background(), slog.LevelError) {
		t.Fatalf("expected Enabled to propagate")
	}

	disabled := &captureHandler{}
	if newMultiHandler(disabled, disabled).Enabled(context.Background(), slog.LevelInfo) {
		t.Fatalf("expected Enabled to be false when all handlers disabled")
	}

	withAttrs := handler.WithAttrs([]slog.Attr{slog.String("key", "value")})
	mh, ok := withAttrs.(multiHandler)
	if !ok {
		t.Fatalf("expected WithAttrs to return multiHandler")
	}
	for i, item := range []struct {
		name    string
		handler *captureHandler
	}{
		{"mutator", mutator},
		{"collector", collector},
	} {
		if item.handler.withAttrsCount != 1 {
			t.Fatalf("expected WithAttrs to be called on %s", item.name)
		}
		if len(item.handler.lastAttrs) != 1 || item.handler.lastAttrs[0].Key != "key" {
			t.Fatalf("unexpected attrs passed to %s: %+v", item.name, item.handler.lastAttrs)
		}
		if _, ok := mh.handlers[i].(*captureHandler); !ok {
			t.Fatalf("expected handler %d to remain captureHandler", i)
		}
	}

	withGroup := handler.WithGroup("grp")
	mhg, ok := withGroup.(multiHandler)
	if !ok {
		t.Fatalf("expected WithGroup to return multiHandler")
	}
	if mutator.withGroupCount != 1 || collector.withGroupCount != 1 {
		t.Fatalf("expected WithGroup to be called on both handlers")
	}
	if mutator.lastGroup != "grp" || collector.lastGroup != "grp" {
		t.Fatalf("unexpected group name recorded")
	}
	for i, h := range mhg.handlers {
		if _, ok := h.(*captureHandler); !ok {
			t.Fatalf("expected handler %d to remain captureHandler", i)
		}
	}
}

func TestBuildResource(t *testing.T) {
	t.Parallel()

	labels := map[string]string{
		"env":    "prod",
		"region": "eu",
		"":       "ignored",
		"  ":     "ignored",
	}

	res, err := buildResource(labels)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	attrs := res.Attributes()

	assertAttr := func(key attribute.Key, val string) {
		for _, attr := range attrs {
			if attr.Key == key && attr.Value.AsString() == val {
				return
			}
		}
		t.Fatalf("attribute %q with value %q not found", key, val)
	}

	assertAttr(semconv.ServiceNameKey, "orb-agent")
	assertAttr(semconv.ServiceVersionKey, version.GetBuildVersion())
	assertAttr("env", "prod")
	assertAttr("region", "eu")

	for _, attr := range attrs {
		if attr.Key == "" {
			t.Fatalf("expected empty keys to be filtered out")
		}
	}
}

func TestResilientLogExporterLogsOnce(t *testing.T) {
	t.Parallel()

	exp := &mockExporter{exportErr: errors.New("boom")}
	handler := &levelRecordingHandler{}
	logger := slog.New(handler)
	resilient := newResilientLogExporter(exp, logger, "localhost:4317")
	if resilient == nil {
		t.Fatalf("expected non-nil exporter wrapper")
	}

	ctx := context.Background()
	if err := resilient.Export(ctx, nil); err == nil {
		t.Fatalf("expected export error to propagate")
	}
	if err := resilient.Export(ctx, nil); err == nil {
		t.Fatalf("expected export error to propagate on subsequent call")
	}

	if exp.exportCount != 2 {
		t.Fatalf("expected export to be called twice, got %d", exp.exportCount)
	}
	if handler.logCount != 1 {
		t.Fatalf("expected failure log only once, got %d", handler.logCount)
	}
	if handler.lastLevel != slog.LevelError {
		t.Fatalf("expected non-transient failure at ERROR, got %v", handler.lastLevel)
	}
}

func TestResilientLogExporterTransientStartupLogsDebug(t *testing.T) {
	t.Parallel()

	exp := &mockExporter{exportErr: errors.New("connection refused")}
	handler := &levelRecordingHandler{}
	logger := slog.New(handler)
	resilient := newResilientLogExporter(exp, logger, "localhost:4317")

	ctx := context.Background()
	if err := resilient.Export(ctx, nil); err == nil {
		t.Fatalf("expected export error to propagate")
	}
	if handler.logCount != 1 {
		t.Fatalf("expected failure log only once, got %d", handler.logCount)
	}
	if handler.lastLevel != slog.LevelDebug {
		t.Fatalf("expected transient startup failure at DEBUG, got %v", handler.lastLevel)
	}
}

func TestResilientLogExporterTransientAfterGraceLogsWarn(t *testing.T) {
	t.Parallel()

	exp := &mockExporter{exportErr: status.Error(codes.Unavailable, "transport closing")}
	handler := &levelRecordingHandler{}
	logger := slog.New(handler)
	resilient := newResilientLogExporter(exp, logger, "localhost:4317")
	r, ok := resilient.(*resilientLogExporter)
	if !ok {
		t.Fatalf("expected resilientLogExporter type")
	}
	r.createdAt = time.Now().Add(-otlpExportStartupGrace - time.Second)

	ctx := context.Background()
	if err := resilient.Export(ctx, nil); err == nil {
		t.Fatalf("expected export error to propagate")
	}
	if handler.logCount != 1 {
		t.Fatalf("expected failure log only once, got %d", handler.logCount)
	}
	if handler.lastLevel != slog.LevelWarn {
		t.Fatalf("expected transient failure after grace at WARN, got %v", handler.lastLevel)
	}
}

func TestIsTransientOTLPErr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "connection refused", err: errors.New("dial tcp 127.0.0.1:4337: connect: connection refused"), want: true},
		{name: "export timeout", err: errors.New("exporter export timeout: unavailable"), want: true},
		{name: "unavailable", err: status.Error(codes.Unavailable, "server down"), want: true},
		{name: "other", err: errors.New("permission denied"), want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isTransientOTLPErr(tt.err); got != tt.want {
				t.Fatalf("isTransientOTLPErr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResilientLogExporterFlushAndShutdown(t *testing.T) {
	t.Parallel()

	exp := &mockExporter{}
	res := newResilientLogExporter(exp, nil, "localhost:4317")
	r, ok := res.(*resilientLogExporter)
	if !ok {
		t.Fatalf("expected resilientLogExporter type")
	}

	ctx := context.Background()
	if err := res.ForceFlush(ctx); err != nil {
		t.Fatalf("unexpected flush error: %v", err)
	}
	if exp.flushCount != 1 {
		t.Fatalf("expected ForceFlush to be delegated")
	}

	if err := res.Shutdown(ctx); err != nil {
		t.Fatalf("unexpected shutdown error: %v", err)
	}
	if exp.shutdownCount != 1 {
		t.Fatalf("expected Shutdown to be delegated")
	}

	if r.exporter != nil {
		t.Fatalf("expected exporter to be cleared after shutdown")
	}

	if err := res.Export(ctx, nil); err != nil {
		t.Fatalf("expected no error after shutdown, got %v", err)
	}
	if err := res.ForceFlush(ctx); err != nil {
		t.Fatalf("expected no flush error after shutdown, got %v", err)
	}
	if err := res.Shutdown(ctx); err != nil {
		t.Fatalf("expected no shutdown error after shutdown, got %v", err)
	}
}

type captureHandler struct {
	mu             sync.Mutex
	records        []slog.Record
	enabled        bool
	mutate         bool
	withAttrsCount int
	lastAttrs      []slog.Attr
	withGroupCount int
	lastGroup      string
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool {
	return h.enabled
}

func (h *captureHandler) Handle(_ context.Context, record slog.Record) error {
	if h.mutate {
		record.AddAttrs(slog.String("mutated", "true"))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, record.Clone())
	return nil
}

func (h *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.withAttrsCount++
	h.lastAttrs = attrs
	return h
}

func (h *captureHandler) WithGroup(name string) slog.Handler {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.withGroupCount++
	h.lastGroup = name
	return h
}

func attrExists(record slog.Record, key string) bool {
	found := false
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == key {
			found = true
			return false
		}
		return true
	})
	return found
}

type mockExporter struct {
	exportErr     error
	exportCount   int
	flushCount    int
	shutdownCount int
}

func (m *mockExporter) Export(context.Context, []sdklog.Record) error {
	m.exportCount++
	return m.exportErr
}

func (m *mockExporter) ForceFlush(context.Context) error {
	m.flushCount++
	return nil
}

func (m *mockExporter) Shutdown(context.Context) error {
	m.shutdownCount++
	return nil
}

type levelRecordingHandler struct {
	mu        sync.Mutex
	logCount  int
	lastLevel slog.Level
}

func (h *levelRecordingHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *levelRecordingHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logCount++
	h.lastLevel = record.Level
	return nil
}

func (h *levelRecordingHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *levelRecordingHandler) WithGroup(string) slog.Handler {
	return h
}
