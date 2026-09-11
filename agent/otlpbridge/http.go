package otlpbridge

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	// maxHTTPBodyBytes bounds a single OTLP/HTTP request body (after
	// decompression). pktvisor and the OTel collector send far smaller exports;
	// anything bigger is refused with 413 instead of being buffered.
	maxHTTPBodyBytes int64 = 16 << 20

	contentTypeProtobuf = "application/x-protobuf"
	contentTypeJSON     = "application/json"

	httpReadHeaderTimeout = 10 * time.Second
	httpReadTimeout       = 30 * time.Second // headers + body; a stalled body must not pin a handler
	httpIdleTimeout       = 60 * time.Second
	httpShutdownTimeout   = 5 * time.Second
)

// otlpHTTPHandler exposes the OTLP/HTTP export endpoints on top of the same
// Export handlers the gRPC server uses, so both transports share one queue,
// one topic-routing rule and one encoder. Backends that only speak OTLP/HTTP
// (pktvisor) reach the bridge through it.
func (s *BridgeServer) otlpHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	// Method-scoped patterns: the mux answers 405 with an Allow header for other methods.
	mux.HandleFunc("POST /v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		s.serveExport(w, r, &collectormetrics.ExportMetricsServiceRequest{}, func(ctx context.Context, m proto.Message) (proto.Message, error) {
			return (&metricsServer{bridge: s}).Export(ctx, m.(*collectormetrics.ExportMetricsServiceRequest))
		})
	})
	mux.HandleFunc("POST /v1/logs", func(w http.ResponseWriter, r *http.Request) {
		s.serveExport(w, r, &collectorlogs.ExportLogsServiceRequest{}, func(ctx context.Context, m proto.Message) (proto.Message, error) {
			return (&logsServer{bridge: s}).Export(ctx, m.(*collectorlogs.ExportLogsServiceRequest))
		})
	})
	mux.HandleFunc("POST /v1/traces", func(w http.ResponseWriter, r *http.Request) {
		s.serveExport(w, r, &collectortrace.ExportTraceServiceRequest{}, func(ctx context.Context, m proto.Message) (proto.Message, error) {
			return (&traceServer{bridge: s}).Export(ctx, m.(*collectortrace.ExportTraceServiceRequest))
		})
	})
	return mux
}

// serveExport decodes one OTLP/HTTP request into req, runs export, and writes
// the response in the same encoding the client used, following the OTLP/HTTP
// status conventions: 429 (with Retry-After) when the bridge queue is full so
// the client backs off, 400 for undecodable bodies, 415 for other encodings.
// Failure bodies are plain text rather than the spec's google.rpc.Status:
// pktvisor ignores response bodies and the collector's otlphttp exporter
// tolerates non-Status bodies, so the status code is what matters here.
func (s *BridgeServer) serveExport(w http.ResponseWriter, r *http.Request, req proto.Message, export func(context.Context, proto.Message) (proto.Message, error)) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != contentTypeProtobuf && mediaType != contentTypeJSON) {
		http.Error(w, "unsupported content type: use application/x-protobuf or application/json", http.StatusUnsupportedMediaType)
		return
	}
	if enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc != "" && enc != "identity" && enc != "gzip" {
		http.Error(w, "unsupported content encoding: use gzip or none", http.StatusUnsupportedMediaType)
		return
	}

	body, err := readOTLPBody(w, r)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, fmt.Sprintf("request body exceeds %d bytes", maxHTTPBodyBytes), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "unable to read request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if mediaType == contentTypeJSON {
		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(body, req)
	} else {
		err = proto.Unmarshal(body, req)
	}
	if err != nil {
		http.Error(w, "unable to decode OTLP request: "+err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := export(r.Context(), req)
	if err != nil {
		if status.Code(err) == codes.ResourceExhausted {
			w.Header().Set("Retry-After", "5")
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		}
		s.logger.Warn("OTLP HTTP export failed", "path", r.URL.Path, "error", err)
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}

	var out []byte
	if mediaType == contentTypeJSON {
		out, err = protojson.Marshal(resp)
	} else {
		out, err = proto.Marshal(resp)
	}
	if err != nil {
		s.logger.Warn("OTLP HTTP response encoding failed", "path", r.URL.Path, "error", err)
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// readOTLPBody reads the request body, transparently gunzipping when the
// client set Content-Encoding: gzip, and enforces maxHTTPBodyBytes on the
// decoded bytes so a compressed body cannot bypass the limit. MaxBytesReader
// is given the ResponseWriter so, for raw bodies, net/http stops reading and
// closes the connection after an oversized body instead of draining it. A
// gzip bomb (small on the wire, over the cap decoded) is caught by the
// LimitReader check below; net/http then drains at most 256 KiB of the
// remaining compressed bytes before reusing the connection.
func readOTLPBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxHTTPBodyBytes)
	var reader io.Reader = r.Body
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Encoding")), "gzip") {
		zr, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("invalid gzip body: %w", err)
		}
		defer func() { _ = zr.Close() }()
		// +1 so a decoded stream that is exactly one byte over the cap is detected.
		limited := io.LimitReader(zr, maxHTTPBodyBytes+1)
		body, err := io.ReadAll(limited)
		if err != nil {
			return nil, fmt.Errorf("invalid gzip body: %w", err)
		}
		if int64(len(body)) > maxHTTPBodyBytes {
			return nil, &http.MaxBytesError{Limit: maxHTTPBodyBytes}
		}
		return body, nil
	}
	return io.ReadAll(reader)
}
