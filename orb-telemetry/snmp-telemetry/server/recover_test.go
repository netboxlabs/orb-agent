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

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/policy"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/server"
)

// A handler that panics gets a 500 and a logged error, and the server keeps
// answering. Without recovery net/http drops the connection unanswered.
func TestHandlerPanicIsAnsweredWith500(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	ctx := context.Background()
	srv := server.NewServer("localhost", 0, logger, policy.NewManager(ctx, logger, policy.Options{ProfilesRoot: testProfilesRoot(t)}), "1.0.0")
	srv.Router().Handle("PROBE", "/panic-probe/:id", panicProbe)

	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, httptest.NewRequest("PROBE", "/panic-probe/7", nil))
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.JSONEq(t, `{"detail":"internal error"}`, w.Body.String())
	require.Contains(t, logs.String(), "panic serving request")
	require.Contains(t, logs.String(), "probe failure")
	require.Regexp(t, `"handler":"[^"]*\.panicProbe"`, logs.String())
	require.NotContains(t, logs.String(), "PROBE", "nothing the client sent")
	require.NotContains(t, logs.String(), "/panic-probe/7", "nothing the client sent")

	w = httptest.NewRecorder()
	srv.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	require.Equal(t, http.StatusOK, w.Code, "the server keeps serving")
}

func panicProbe(*gin.Context) { panic("probe failure") }
