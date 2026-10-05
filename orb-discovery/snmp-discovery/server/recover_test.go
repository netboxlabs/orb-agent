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

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/policy"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/server"
)

// A handler that panics gets a 500 and a logged error, and the server keeps
// answering. Without recovery net/http drops the connection unanswered.
func TestHandlerPanicIsAnsweredWith500(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	ctx := context.Background()
	policyManager, err := policy.NewManager(ctx, logger, nil, nil)
	require.NoError(t, err)
	srv := server.NewServer("localhost", 0, logger, policyManager, "1.0.0")
	srv.Router().GET("/panic-probe", func(*gin.Context) { panic("probe failure") })

	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/panic-probe", nil))
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.JSONEq(t, `{"detail":"internal error"}`, w.Body.String())
	require.Contains(t, logs.String(), "panic serving request")
	require.Contains(t, logs.String(), "probe failure")
	require.Contains(t, logs.String(), "/panic-probe")

	w = httptest.NewRecorder()
	srv.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	require.Equal(t, http.StatusOK, w.Code, "the server keeps serving")
}
