package server_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/policy"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/server"
)

type MockClient struct {
	mock.Mock
}

func (m *MockClient) Ingest(ctx context.Context, entities []diode.Entity) (*diodepb.IngestResponse, error) {
	args := m.Called(ctx, entities)
	return args.Get(0).(*diodepb.IngestResponse), args.Error(1)
}

func (m *MockClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestServerConfigureAndStart(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	client := new(MockClient)
	policyManager := policy.NewManager(ctx, logger, client)

	srv := server.NewServer("localhost", 8081, logger, policyManager, "1.0.0")
	srv.Start()

	// Check /status endpoint
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1/status", nil)
	srv.Router().ServeHTTP(w, c.Request)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"version": "1.0.0"`)
	assert.Contains(t, w.Body.String(), `"start_time":`)
	assert.Contains(t, w.Body.String(), `"up_time_seconds": 0`)

	srv.Stop()
}

func TestServerGetCapabilities(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	client := new(MockClient)
	policyManager := policy.NewManager(ctx, logger, client)

	srv := server.NewServer("localhost", 8081, logger, policyManager, "1.0.0")

	// Check /capabilities endpoint
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	srv.Router().ServeHTTP(w, c.Request)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `targets`)
}

func TestServerCreateDeletePolicy(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	client := new(MockClient)
	policyManager := policy.NewManager(ctx, logger, client)

	srv := server.NewServer("localhost", 8081, logger, policyManager, "1.0.0")

	body := []byte(`
    policies:
      test-policy:
        config:
          defaults:
            site: New York NY
        scope:
          targets: 
            - host: 192.168.31.1
          authentication:
            protocol_version: SNMPv2c
            community: public
    `)

	w := httptest.NewRecorder()
	request, _ := http.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/x-yaml")

	// Create policy
	srv.Router().ServeHTTP(w, request)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), `policies [test-policy] were started`)

	// Delete policy
	w = httptest.NewRecorder()
	request, _ = http.NewRequest(http.MethodDelete, "/api/v1/policies/test-policy", nil)
	srv.Router().ServeHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `policy 'test-policy' was deleted`)
}
