package telemetry

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func TestNormalizeEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		wantAddr string
		insecure bool
		wantErr  bool
	}{
		{name: "bare host", input: "localhost:4317", wantAddr: "localhost:4317", insecure: true},
		{name: "http scheme", input: "http://collector:4317", wantAddr: "collector:4317", insecure: true},
		{name: "trim whitespace", input: "  http://example:55681  ", wantAddr: "example:55681", insecure: true},
		{name: "https scheme", input: "https://secure-host:443", wantAddr: "secure-host:443", insecure: false},
		{name: "grpc scheme", input: "grpc://collector", wantAddr: "collector", insecure: true},
		{name: "grpcs scheme", input: "grpcs://collector:4317", wantAddr: "collector:4317", insecure: false},
		{name: "missing host", input: "https://", wantErr: true},
		{name: "unsupported scheme", input: "ftp://invalid", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			addr, insecure, err := normalizeEndpoint(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if addr != tt.wantAddr {
				t.Fatalf("expected addr %q, got %q", tt.wantAddr, addr)
			}
			if insecure != tt.insecure {
				t.Fatalf("expected insecure=%t, got %t", tt.insecure, insecure)
			}
		})
	}
}

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
