package telemetry

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// A password holding an @ is percent-encoded in a URL. Written without a
// scheme, the login reaches grpc-go as part of the address, which it decodes
// and writes, decoded, in the error of every export: the log line and the
// error returned to the SDK write neither form. The error is a real one,
// from the exporter dialling that address.
func TestResilientLogExporterMasksALoginPercentDecodedInARealGRPCError(t *testing.T) {
	endpoint := "canary-user:canary%40pass@127.0.0.1:1"
	exp, err := newLogExporter(context.Background(), endpoint)
	if err != nil {
		t.Fatalf("newLogExporter: %v", err)
	}
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })

	var logs strings.Builder
	var mu sync.Mutex
	logger := slog.New(slog.NewTextHandler(&lockedWriter{w: &logs, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	resilient := newResilientLogExporter(exp, logger, endpoint)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err = resilient.Export(ctx, []sdklog.Record{{}})
	if err == nil {
		t.Fatal("expected the export to fail")
	}
	if !strings.Contains(err.Error(), "invalid target address") {
		t.Fatalf("the export failed for another reason than the address: %v", err)
	}
	if strings.Contains(err.Error(), "canary") {
		t.Errorf("the error returned writes the login: %v", err)
	}
	if !strings.Contains(err.Error(), "********@127.0.0.1:1") {
		t.Errorf("the error returned does not write the address masked: %v", err)
	}

	mu.Lock()
	out := logs.String()
	mu.Unlock()
	if strings.Contains(out, "canary") {
		t.Errorf("the log writes the login:\n%s", out)
	}
}
