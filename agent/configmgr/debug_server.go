//go:build !nodebug

package configmgr

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// debugServer runs a lightweight HTTP server exposing debug/test endpoints.
// It is compiled in by default; build with "-tags nodebug" to exclude it.
type debugServer struct {
	logger   *slog.Logger
	listener net.Listener
	server   *http.Server
}

// tokenStatusInfo is returned by the token-status endpoint.
type tokenStatusInfo struct {
	ExpiresAt      time.Time `json:"expires_at"`
	TimeUntilExpiry string   `json:"time_until_expiry"`
	Expired        bool      `json:"expired"`
	ExpiringSoon   bool      `json:"expiring_soon"`
}

// debugServerOpts holds the callbacks the debug server needs, keeping it decoupled
// from concrete types like AuthTokenManager.
type debugServerOpts struct {
	reconnectChan chan<- struct{}
	tokenStatus   func() tokenStatusInfo // nil-safe: endpoint returns 501 when absent
}

// startDebugServer starts the debug HTTP server on the given port.
// Pass 0 to let the OS pick a free port (useful in tests).
func startDebugServer(logger *slog.Logger, port int, opts debugServerOpts) (*debugServer, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /debug/force-reconnect", func(w http.ResponseWriter, _ *http.Request) {
		select {
		case opts.reconnectChan <- struct{}{}:
			logger.Warn("debug: forced MQTT reconnect triggered via HTTP")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "reconnect_triggered"})
		default:
			logger.Warn("debug: forced reconnect requested but reconnect already in progress")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "reconnect_already_in_progress"})
		}
	})

	mux.HandleFunc("POST /debug/force-token-rotation", func(w http.ResponseWriter, _ *http.Request) {
		// Signals a reconnect which will refresh the JWT via ConnectPacketBuilder.
		// Unlike force-reconnect, this is explicitly about exercising the token rotation path.
		select {
		case opts.reconnectChan <- struct{}{}:
			logger.Warn("debug: forced token rotation triggered via HTTP")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "token_rotation_triggered"})
		default:
			logger.Warn("debug: forced token rotation requested but reconnect already in progress")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "reconnect_already_in_progress"})
		}
	})

	mux.HandleFunc("GET /debug/token-status", func(w http.ResponseWriter, _ *http.Request) {
		if opts.tokenStatus == nil {
			w.WriteHeader(http.StatusNotImplemented)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "token status not available"})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(opts.tokenStatus())
	})

	mux.HandleFunc("GET /debug/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("debug server listen: %w", err)
	}

	srv := &http.Server{Handler: mux}
	ds := &debugServer{
		logger:   logger,
		listener: ln,
		server:   srv,
	}

	go func() {
		logger.Info("debug server started", "addr", ln.Addr().String())
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Error("debug server error", "error", err)
		}
	}()

	return ds, nil
}

func (ds *debugServer) stop() {
	if ds == nil || ds.server == nil {
		return
	}
	ds.logger.Info("stopping debug server")
	_ = ds.server.Close()
}

func (ds *debugServer) addr() string {
	if ds == nil || ds.listener == nil {
		return ""
	}
	return ds.listener.Addr().String()
}
