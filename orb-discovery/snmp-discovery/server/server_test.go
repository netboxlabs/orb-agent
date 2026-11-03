package server_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/metrics"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/policy"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/server"
)

type MockClient struct {
	mock.Mock
}

func (m *MockClient) Ingest(ctx context.Context, entities []diode.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	args := m.Called(ctx, entities)
	return args.Get(0).(*diodepb.IngestResponse), args.Error(1)
}

func (m *MockClient) IngestProto(ctx context.Context, entities []*diodepb.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
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
	policyManager, err := policy.NewManager(ctx, logger, client, nil)
	require.NoError(t, err)

	err = setupTestMeter(t)
	require.NoError(t, err)

	srv := server.NewServer("localhost", 8081, logger, policyManager, "1.0.0")
	serverErrCh := srv.Start()
	t.Cleanup(func() {
		srv.Stop()
		<-serverErrCh
	})

	// Check /status endpoint
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1/status", nil)
	srv.Router().ServeHTTP(w, c.Request)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"version": "1.0.0"`)
	assert.Contains(t, w.Body.String(), `"start_time":`)
	assert.Contains(t, w.Body.String(), `"up_time_seconds": 0`)
	assert.Contains(t, w.Body.String(), `"policies":`)
}

func TestServerGetStatusWithPolicies(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	client := new(MockClient)
	policyManager, err := policy.NewManager(ctx, logger, client, nil)
	require.NoError(t, err)

	err = setupTestMeter(t)
	require.NoError(t, err)

	srv := server.NewServer("localhost", 8082, logger, policyManager, "1.0.0")

	// Create a policy first
	body := []byte(`
    policies:
      test-policy:
        config:
          lookup_extensions_dir: /tmp/lookup_extensions
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
	srv.Router().ServeHTTP(w, request)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Check /status endpoint
	w = httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1/status", nil)
	srv.Router().ServeHTTP(w, c.Request)

	assert.Equal(t, http.StatusOK, w.Code)
	bodyStr := w.Body.String()

	// Verify status fields
	assert.Contains(t, bodyStr, `"version": "1.0.0"`)
	assert.Contains(t, bodyStr, `"start_time":`)
	assert.Contains(t, bodyStr, `"up_time_seconds":`)
	assert.Contains(t, bodyStr, `"policies":`)

	// Verify policy structure
	assert.Contains(t, bodyStr, `"test-policy"`)
	assert.Contains(t, bodyStr, `"name":`)
	assert.Contains(t, bodyStr, `"status":`)
	assert.Contains(t, bodyStr, `"runs":`)

	// Clean up
	srv.Stop()
}

func TestServerGetCapabilities(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
	client := new(MockClient)
	policyManager, err := policy.NewManager(ctx, logger, client, nil)
	require.NoError(t, err)

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
	policyManager, err := policy.NewManager(ctx, logger, client, nil)
	require.NoError(t, err)

	srv := server.NewServer("localhost", 8081, logger, policyManager, "1.0.0")

	body := []byte(`
    policies:
      test-policy:
        config:
          lookup_extensions_dir: /tmp/lookup_extensions
          defaults:
            site: New York NY
        scope:
          targets: 
            - host: 192.168.31.1
          authentication:
            protocol_version: SNMPv2c
            community: public
    `)

	err = setupTestMeter(t)
	require.NoError(t, err)

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
      test-policy:
        config:
          lookup_extensions_dir: /tmp/lookup_extensions
        scope:
          targets: 
            - host: 192.168.31.1
          authentication:
            protocol_version: SNMPv2c
            community: public
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

// TestServerCreatePolicyLogsNoCredentials pins that a policy's SNMP
// credentials, at the scope and on a target, stay out of the log at DEBUG,
// from the policy's start through a poll of the target. The agent relays this
// process's log into its own, so a credential logged here reaches the agent's
// console and, when the agent sends its log to Fleet, the platform (MON-777).
func TestServerCreatePolicyLogsNoCredentials(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	policyManager, err := policy.NewManager(context.Background(), logger, new(MockClient), nil)
	require.NoError(t, err)
	srv := server.NewServer("localhost", 8081, logger, policyManager, "1.0.0")
	require.NoError(t, setupTestMeter(t))

	body := []byte(fmt.Sprintf(`
    policies:
      secret-policy:
        config:
          lookup_extensions_dir: /tmp/lookup_extensions
        scope:
          targets:
            - host: 192.0.2.10
            - host: 127.0.0.1
              port: %d
              authentication:
                protocol_version: SNMPv2c
                community: c0mmunity-7f3a
          authentication:
            protocol_version: SNMPv3
            security_level: authPriv
            username: orb
            auth_protocol: SHA
            auth_passphrase: 4uth-pass-7f3a
            priv_protocol: AES
            priv_passphrase: pr1v-pass-7f3a
    `, snmpResponder(t)))
	w := httptest.NewRecorder()
	request, _ := http.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/x-yaml")
	srv.Router().ServeHTTP(w, request)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	// gosnmp logs every packet of a poll at DEBUG, the community's most
	// frequent way into the log, so the check waits for a reply to be parsed.
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "Parsed community") },
		10*time.Second, 20*time.Millisecond, "the target has to have been polled for the log to hold its packets")

	w = httptest.NewRecorder()
	request, _ = http.NewRequest(http.MethodDelete, "/api/v1/policies/secret-policy", nil)
	srv.Router().ServeHTTP(w, request)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	out := logs.String()
	require.Contains(t, out, `"msg":"starting policy"`, "the start is logged at DEBUG")
	for _, credential := range []string{"c0mmunity-7f3a", "4uth-pass-7f3a", "pr1v-pass-7f3a"} {
		assert.NotContains(t, out, credential)
	}
}

// snmpResponder answers every SNMP request on a local port with endOfMibView,
// enough for a poll to send packets and parse the replies, and returns the
// port.
func snmpResponder(t *testing.T) uint16 {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		codec := &gosnmp.GoSNMP{Version: gosnmp.Version2c, MaxOids: gosnmp.MaxOids}
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			req, err := codec.SnmpDecodePacket(buf[:n])
			if err != nil || len(req.Variables) == 0 {
				continue
			}
			codec.Version = req.Version
			codec.Community = req.Community
			// The encoder stamps the next value of its own counter, so seeding
			// it one below the request's ID makes the reply carry that ID.
			codec.SetRequestID(req.RequestID - 1)
			out, err := codec.SnmpEncodePacket(gosnmp.GetResponse,
				[]gosnmp.SnmpPDU{{Name: req.Variables[0].Name, Type: gosnmp.EndOfMibView}}, 0, 0)
			if err == nil {
				_, _ = conn.WriteTo(out, addr)
			}
		}
	}()
	port, err := strconv.ParseUint(strings.TrimPrefix(conn.LocalAddr().String(), "127.0.0.1:"), 10, 16)
	require.NoError(t, err)
	return uint16(port)
}

// syncBuffer lets the test read what the server and the policy's goroutines
// logged.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// setupTestMeter creates a no-op meter provider for testing
func setupTestMeter(_ *testing.T) error {
	ctx := context.Background()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// Use the no-op meter provider for testing to avoid actual metrics export
	return metrics.SetupMetricsExport(ctx, logger, "localhost:4317", 10)
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
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                scope:
                  targets:
                    - host: 192.168.31.1
                  authentication:
                    protocol_version: SNMPv2c
                    community: public
              test-policy-invalid:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                  defaults:
                    site: New York NY
                scope:
                  ports: [80, 443]
                  authentication:
                    protocol_version: SNMPv2c
                    community: public
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy-invalid : no targets found in the policy`,
		},
		{
			desc:        "missing authentication",
			contentType: "application/x-yaml",
			body: []byte(`
            policies:
              test-policy:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                scope:
                  targets:
                    - host: 192.168.31.1
                  authentication:
                    protocol_version: SNMPv2c
                    community: public
              test-policy-invalid:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                  defaults:
                    site: New York NY
                scope:
                  targets:
                    - host: 192.168.31.1
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy-invalid : invalid policy : target 192.168.31.1: no authentication configured and no policy-level fallback available`,
		},
		{
			desc:        "unsupported protocol version",
			contentType: "application/x-yaml",
			body: []byte(`
            policies:
              test-policy:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                scope:
                  targets:
                    - host: 192.168.31.1
                  authentication:
                    protocol_version: SNMPv4
                    community: public
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy : invalid policy : policy-level: unsupported protocol version`,
		},
		{
			desc:        "missing community",
			contentType: "application/x-yaml",
			body: []byte(`
            policies:
              test-policy:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                scope:
                  targets:
                    - host: 192.168.31.1
                  authentication:
                    protocol_version: SNMPv2c
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy : invalid policy : policy-level: missing community`,
		},
		{
			desc:        "invalid security level",
			contentType: "application/x-yaml",
			body: []byte(`
            policies:
              test-policy:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                scope:
                  targets:
                    - host: 192.168.31.1
                  authentication:
                    protocol_version: SNMPv3
                    security_level: invalid
                    username: user
                    auth_passphrase: pass
                    auth_protocol: MD5
                    priv_passphrase: pass
                    priv_protocol: DES
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy : invalid policy : policy-level: invalid security level`,
		},
		{
			desc:        "missing security level for SNMPv3",
			contentType: "application/x-yaml",
			body: []byte(`
            policies:
              test-policy:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                scope:
                  targets:
                    - host: 192.168.31.1
                  authentication:
                    protocol_version: SNMPv3
                    username: user
                    auth_passphrase: pass
                    auth_protocol: MD5
                    priv_passphrase: pass
                    priv_protocol: DES
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy : invalid policy : policy-level: invalid security level`,
		},
		{
			desc:        "missing username for SNMPv3 with authNoPriv",
			contentType: "application/x-yaml",
			body: []byte(`
            policies:
              test-policy:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                scope:
                  targets:
                    - host: 192.168.31.1
                  authentication:
                    protocol_version: SNMPv3
                    security_level: authNoPriv
                    auth_passphrase: pass
                    auth_protocol: MD5
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy : invalid policy : policy-level: missing username`,
		},
		{
			desc:        "missing auth passphrase for SNMPv3 with authNoPriv",
			contentType: "application/x-yaml",
			body: []byte(`
            policies:
              test-policy:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                scope:
                  targets:
                    - host: 192.168.31.1
                  authentication:
                    protocol_version: SNMPv3
                    security_level: authNoPriv
                    username: user
                    auth_protocol: MD5
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy : invalid policy : policy-level: missing auth passphrase`,
		},
		{
			desc:        "missing auth protocol for SNMPv3 with authNoPriv",
			contentType: "application/x-yaml",
			body: []byte(`
            policies:
              test-policy:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                scope:
                  targets:
                    - host: 192.168.31.1
                  authentication:
                    protocol_version: SNMPv3
                    security_level: authNoPriv
                    username: user
                    auth_passphrase: pass
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy : invalid policy : policy-level: missing auth protocol`,
		},
		{
			desc:        "missing priv passphrase for SNMPv3 with authPriv",
			contentType: "application/x-yaml",
			body: []byte(`
            policies:
              test-policy:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                scope:
                  targets:
                    - host: 192.168.31.1
                  authentication:
                    protocol_version: SNMPv3
                    security_level: authPriv
                    username: user
                    auth_passphrase: pass
                    auth_protocol: MD5
                    priv_protocol: DES
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy : invalid policy : policy-level: missing priv passphrase`,
		},
		{
			desc:        "missing priv protocol for SNMPv3 with authPriv",
			contentType: "application/x-yaml",
			body: []byte(`
            policies:
              test-policy:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                scope:
                  targets:
                    - host: 192.168.31.1
                  authentication:
                    protocol_version: SNMPv3
                    security_level: authPriv
                    username: user
                    auth_passphrase: pass
                    priv_passphrase: pass
                    priv_protocol: DES
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy : invalid policy : policy-level: missing auth protocol`,
		},
		{
			desc:        "missing priv protocol for SNMPv3",
			contentType: "application/x-yaml",
			body: []byte(`
            policies:
              test-policy:
                config:
                  lookup_extensions_dir: /tmp/lookup_extensions
                scope:
                  targets:
                    - host: 192.168.31.1
                  authentication:
                    protocol_version: SNMPv3
                    security_level: authPriv
                    username: user
                    auth_passphrase: pass
                    priv_passphrase: pass
                    auth_protocol: MD5
            `),
			returnCode:    http.StatusBadRequest,
			returnMessage: `test-policy : invalid policy : policy-level: missing priv protocol`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			ctx := context.Background()
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: false}))
			client := new(MockClient)

			policyManager, err := policy.NewManager(ctx, logger, client, nil)
			require.NoError(t, err)

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
