//go:build debug

package configmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
)

// debugServer runs a lightweight HTTP server exposing debug/test endpoints.
// Only compiled when built with "-tags debug".
type debugServer struct {
	logger   *slog.Logger
	listener net.Listener
	server   *http.Server
}

// debugServerOpts holds the callbacks the debug server needs, keeping it
// decoupled from concrete types like AuthTokenManager.
type debugServerOpts struct {
	reconnectChan chan<- struct{}
	tokenStatus   func() tokenStatusInfo                   // nil-safe: endpoint returns 501 when absent
	tokenRotate   func() (old, fresh time.Time, err error) // nil-safe: refreshes token without reconnecting
}

// tokenStatusInfo is returned by the token-status debug endpoint.
type tokenStatusInfo struct {
	ExpiresAt       time.Time `json:"expires_at"`
	TimeUntilExpiry string    `json:"time_until_expiry"`
	Expired         bool      `json:"expired"`
	ExpiringSoon    bool      `json:"expiring_soon"`
}

// tokenRotationResult is returned by the force-token-rotation debug endpoint.
type tokenRotationResult struct {
	Status          string    `json:"status"`
	TimeUntilExpiry string    `json:"time_until_expiry,omitempty"`
	PreviousExpiry  time.Time `json:"previous_expiry,omitempty"`
	NewExpiry       time.Time `json:"new_expiry,omitempty"`
}

// startFleetDebugServer starts a debug HTTP server wired to the fleet manager's
// auth token manager and reconnect channel. Port is read from ORB_DEBUG_PORT
// env (default 6166).
func startFleetDebugServer(logger *slog.Logger, atm *fleet.AuthTokenManager, reconnectChan chan<- struct{}) *debugServer {
	ds, err := startDebugServer(logger, debugServerOpts{
		reconnectChan: reconnectChan,
		tokenStatus: func() tokenStatusInfo {
			expiry := atm.GetTokenExpiryTime()
			return tokenStatusInfo{
				ExpiresAt:       expiry,
				TimeUntilExpiry: time.Until(expiry).Truncate(time.Second).String(),
				Expired:         atm.IsTokenExpired(),
				ExpiringSoon:    atm.IsTokenExpiringSoon(2 * time.Minute),
			}
		},
		tokenRotate: func() (old, fresh time.Time, err error) {
			old = atm.GetTokenExpiryTime()
			_, err = atm.RefreshToken(context.Background())
			if err != nil {
				return old, time.Time{}, err
			}
			fresh = atm.GetTokenExpiryTime()
			return old, fresh, nil
		},
	})
	if err != nil {
		logger.Error("failed to start debug server", "error", err)
		return nil
	}
	logger.Info("debug server available", "addr", ds.addr())
	return ds
}

func startDebugServer(logger *slog.Logger, opts debugServerOpts) (*debugServer, error) {
	port := 6166
	if v := os.Getenv("ORB_DEBUG_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p >= 0 {
			port = p
		}
	}

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
		if opts.tokenRotate == nil {
			w.WriteHeader(http.StatusNotImplemented)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "token rotation not available"})
			return
		}
		oldExpiry, newExpiry, err := opts.tokenRotate()
		if err != nil {
			logger.Error("debug: token rotation failed", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "token_rotation_failed", "error": err.Error()})
			return
		}
		logger.Warn("debug: token rotated (connection unchanged)", "old_expiry", oldExpiry, "new_expiry", newExpiry)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenRotationResult{
			Status:          "token_rotated",
			PreviousExpiry:  oldExpiry,
			NewExpiry:       newExpiry,
			TimeUntilExpiry: time.Until(newExpiry).Truncate(time.Second).String(),
		})
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

	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
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
