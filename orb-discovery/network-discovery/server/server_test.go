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

	"github.com/netboxlabs/orb-discovery/network-discovery/policy"
	"github.com/netboxlabs/orb-discovery/network-discovery/server"
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

	srv := server.NewServer("localhost", 8080, logger, policyManager, "1.0.0")
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

	srv := server.NewServer("localhost", 8073, logger, policyManager, "1.0.0")

	// Check /capabilities endpoint
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	srv.Router().ServeHTTP(w, c.Request)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `targets`)
	assert.Contains(t, w.Body.String(), `ports`)
}

func TestServerCreateDeletePolicy(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	client := new(MockClient)
	policyManager := policy.NewManager(ctx, logger, client)

	srv := server.NewServer("localhost", 8073, logger, policyManager, "1.0.0")

	body := []byte(`
    policies:
      test-policy:
        config:
          defaults:
            site: New York NY
        scope:
          targets: 
            - 192.168.31.1/24
    `)

	w := httptest.NewRecorder()
	request, _ := http.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/x-yaml")

	// Create policy
	srv.Router().ServeHTTP(w, request)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), `policies [test-policy] were started`)

	// Try to create the same policy again
	body = []byte(`
    policies:
      test-pol:
        scope:
          targets: 
            - 192.168.31.1/24
      test-policy:
        scope:
          targets: 
            - 192.168.31.1/24
    `)
	w = httptest.NewRecorder()
	request, _ = http.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/x-yaml")

	srv.Router().ServeHTTP(w, request)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), `policy 'test-policy' already exists`)

	// Delete policy
	w = httptest.NewRecorder()
	request, _ = http.NewRequest(http.MethodDelete, "/api/v1/policies/test-policy", nil)
	srv.Router().ServeHTTP(w, request)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `policy 'test-policy' was deleted`)

	// Try to delete the same policy again
	w = httptest.NewRecorder()
	request, _ = http.NewRequest(http.MethodDelete, "/api/v1/policies/test-policy", nil)
	srv.Router().ServeHTTP(w, request)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), `policy not found`)
}

func TestServerCreateInvalidPolicy(t *testing.T) {
	tests := []struct {
		desc          string
		contentType   string
		body          []byte
		returnCode    int
		returnMessage string
	}{
		{
			desc:          "invalid content type",
			contentType:   "application/json",
			body:          []byte(``),
			returnCode:    http.StatusBadRequest,
			returnMessage: `invalid Content-Type. Only 'application/x-yaml' is supported`,
		},
		{
			desc:          "invalid YAML",
			contentType:   "application/x-yaml",
			body:          []byte(`invalid`),
			returnCode:    http.StatusBadRequest,
			returnMessage: `yaml: unmarshal errors:`,
		},
		{
			desc:        "no policies found",
			contentType: "application/x-yaml",
			body: []byte(`
            policies: {}
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `no policies found in the request`,
		},
		{
			desc:        "no targets found",
			contentType: "application/x-yaml",
			body: []byte(`
            policies:
              test-policy:
                scope:
                  targets: 
                    - 192.168.31.1/24
              test-policy-invalid:
                config:
                  defaults:
                    site: New York NY
                scope:
                  ports: [80, 443]
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy-invalid : no targets found in the policy`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			ctx := context.Background()
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
			client := new(MockClient)
			policyManager := policy.NewManager(ctx, logger, client)

			srv := server.NewServer("localhost", 8073, logger, policyManager, "1.0.0")

			// Create invalid policy request
			w := httptest.NewRecorder()
			request, _ := http.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(tt.body))
			request.Header.Set("Content-Type", tt.contentType)

			srv.Router().ServeHTTP(w, request)

			assert.Equal(t, tt.returnCode, w.Code)
			assert.Contains(t, w.Body.String(), tt.returnMessage)
		})
	}
}
