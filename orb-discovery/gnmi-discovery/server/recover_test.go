package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/policy"
)

// A handler that panics gets a 500 and a logged error, and the server keeps
// answering. Without recovery net/http drops the connection unanswered.
func TestHandlerPanicIsAnsweredWith500(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	ctx := context.Background()
	mgr, err := policy.NewManager(ctx, logger, nil, &gnmi.FakeDialer{Session: &gnmi.FakeSession{}}, "")
	require.NoError(t, err)
	srv := NewServer("127.0.0.1", 0, logger, mgr, "test")
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
