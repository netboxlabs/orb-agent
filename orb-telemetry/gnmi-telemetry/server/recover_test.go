package server_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/policy"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/server"
)

// A handler that panics gets a 500 and a logged error, and the server keeps
// answering. Without recovery net/http drops the connection unanswered.
func TestHandlerPanicIsAnsweredWith500(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	ctx := context.Background()
	dialer := &gnmi.FakeDialer{Session: &gnmi.FakeSession{Caps: &gnmi.CapabilitiesResult{}}}
	srv := server.NewServer("localhost", 0, logger, policy.NewManager(ctx, logger, policy.Options{ProfilesRoot: testProfilesRoot(t), Dialer: dialer}), "1.0.0")
	srv.Router().GET("/panic-probe/:id", func(*gin.Context) { panic("probe failure") })

	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/panic-probe/7", nil))
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.JSONEq(t, `{"detail":"internal error"}`, w.Body.String())
	require.Contains(t, logs.String(), "panic serving request")
	require.Contains(t, logs.String(), "probe failure")
	require.Contains(t, logs.String(), "/panic-probe/:id", "the route pattern, not the request path")

	w = httptest.NewRecorder()
	srv.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	require.Equal(t, http.StatusOK, w.Code, "the server keeps serving")
}
