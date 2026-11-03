package policymgr_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/devicediscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/gnmidiscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/gnmitelemetry"
	"github.com/netboxlabs/orb-agent/agent/backend/mocks"
	"github.com/netboxlabs/orb-agent/agent/backend/networkdiscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/opentelemetryinfinity"
	"github.com/netboxlabs/orb-agent/agent/backend/pktvisor"
	"github.com/netboxlabs/orb-agent/agent/backend/snmpdiscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/snmptelemetry"
	"github.com/netboxlabs/orb-agent/agent/backend/worker"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policies"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
	"github.com/netboxlabs/orb-agent/agent/secretsmgr"
)

// resolvedSecret is what the policy's secret reference resolves to. It is
// distinctive, so a match in the log can only be the secret.
const resolvedSecret = "Pl41n-r3solved-credential-7f3a"

// TestManagedPolicySecretsNeverReachTheLog applies, to every backend the agent
// sends a policy's body to, a policy whose credential comes from a secret
// reference, through the policy manager and a real secrets manager. The
// backend's API must be sent the resolved value, so there was something to
// leak, and no log record, at any level, may carry it (MON-777: six backends
// logged the resolved policy at DEBUG).
//
// The records are rendered at DEBUG through a text and a JSON handler, the
// console's two formats. Those see every record any handler sees, the OTLP
// one included: a handler can only drop a record or format it.
func TestManagedPolicySecretsNeverReachTheLog(t *testing.T) {
	logs := &renderedLogs{}
	logger := logs.logger()

	mgr, err := policymgr.New(logger, startDoppler(t, logger, "SNMP_COMMUNITY", resolvedSecret), config.Config{})
	require.NoError(t, err)

	for _, tc := range []struct {
		backend    string
		executable string
		register   func() bool
	}{
		{"device_discovery", "device-discovery", devicediscovery.Register},
		{"network_discovery", "network-discovery", networkdiscovery.Register},
		{"snmp_discovery", "snmp-discovery", snmpdiscovery.Register},
		{"gnmi_discovery", "gnmi-discovery", gnmidiscovery.Register},
		{"snmp_telemetry", "snmp-telemetry", snmptelemetry.Register},
		{"gnmi_telemetry", "gnmi-telemetry", gnmitelemetry.Register},
		{"worker", "orb-worker", worker.Register},
		{"pktvisor", "pktvisord", pktvisor.Register},
		{"opentelemetry_infinity", "otlpinf", opentelemetryinfinity.Register},
	} {
		t.Run(tc.backend, func(t *testing.T) {
			posted := startBackend(t, logger, mgr, tc.backend, tc.executable, tc.register)
			from := logs.len()

			policyID := "policy-" + tc.backend
			mgr.ManagePolicy(config.PolicyPayload{
				Action:    "manage",
				ID:        policyID,
				DatasetID: "dataset-1",
				Name:      "secret_ref_policy",
				Backend:   tc.backend,
				Version:   1,
				Data: map[string]any{
					// pktvisor refuses a policy that names no tap; the others pass it on.
					"input": map[string]any{"tap": "default_pcap"},
					// An SNMP community, a credential under a name that masking by
					// field name (redact.SensitiveData) does not know.
					"scope": map[string]any{
						"targets": []any{map[string]any{"host": "192.0.2.10"}},
						"authentication": map[string]any{
							"protocol_version": "SNMPv2c",
							"community":        "${doppler://SNMP_COMMUNITY}",
						},
					},
				},
			})

			state, err := mgr.GetPolicyState()
			require.NoError(t, err)
			var applied *policies.PolicyData
			for i := range state {
				if state[i].ID == policyID {
					applied = &state[i]
				}
			}
			require.NotNil(t, applied, "the policy is stored")
			require.Equal(t, policies.Running, applied.State, "the policy is applied: %s", applied.BackendErr)
			require.Contains(t, posted(), resolvedSecret, "the backend's API is sent the resolved value")
			require.True(t, logs.debugRecordFor(policyID),
				"the backend logged the apply at DEBUG, so a body in it would be in the log")

			assert.Empty(t, logs.linesWith(from, resolvedSecret), "no log record carries the resolved secret")
		})
	}
}

// startDoppler starts a Doppler secrets manager against a server standing in
// for Doppler's API, holding one secret under the manager's default project
// and config.
func startDoppler(t *testing.T, logger *slog.Logger, name, value string) secretsmgr.Manager {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/v3/configs/config/secret" || r.Header.Get("Authorization") != "Bearer dp.st.test" ||
			q.Get("project") != "orb" || q.Get("config") != "prd" || q.Get("name") != name {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":  name,
			"value": map[string]any{"raw": value, "computed": value},
		})
	}))
	t.Cleanup(server.Close)

	secrets, err := secretsmgr.New(logger, config.ManagerSecrets{
		Active: "doppler",
		Sources: config.SecretsSources{Doppler: config.DopplerManager{
			Token:   "dp.st.test",
			APIHost: server.URL,
			Project: "orb",
			Config:  "prd",
		}},
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	require.NoError(t, secrets.Start(ctx))
	return secrets
}

// startBackend registers and starts the named backend, its process mocked
// and a server standing in for the process's API, and returns what that
// server was sent as policies. Like mocks.APIStandIn, the server answers
// every path with the version in each shape the backends read it in, so any
// backend's readiness check and Version pass.
func startBackend(t *testing.T, logger *slog.Logger, mgr policymgr.PolicyManager, name, executable string,
	register func() bool,
) func() string {
	t.Helper()
	var mu sync.Mutex
	var posted bytes.Buffer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/policies" {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			posted.Write(body)
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": "1.0.0",
			"app":     map[string]any{"version": "1.0.0"},
		})
	}))
	t.Cleanup(server.Close)
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, executable), nil, 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	cmd := &mocks.MockCmd{}
	mocks.SetupSuccessfulProcess(cmd, 12345)
	mocks.AllowHeldListenAddr(t)
	original := backend.NewCmdOptions
	backend.NewCmdOptions = func(backend.CmdOptions, string, ...string) backend.Commander { return cmd }
	t.Cleanup(func() { backend.NewCmdOptions = original })

	require.True(t, register())
	be := backend.GetBackend(name)
	var commons config.BackendCommons
	commons.Otlp.Grpc = "127.0.0.1:4317" // the telemetry backends require one
	require.NoError(t, be.Configure(logger, mgr.GetRepo(), map[string]any{"host": host, "port": port}, commons, nil))
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), config.ContextKey("agent_id"), "agent-1"))
	t.Cleanup(cancel)
	require.NoError(t, be.Start(ctx, cancel))

	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return posted.String()
	}
}

// renderedLogs renders every record, at every level, in the console's text
// and JSON formats.
type renderedLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *renderedLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *renderedLogs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *renderedLogs) logger() *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	return slog.New(slog.NewMultiHandler(slog.NewTextHandler(l, opts), slog.NewJSONHandler(l, opts)))
}

// len returns how much has been rendered so far, to pass to linesWith.
func (l *renderedLogs) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Len()
}

// linesWith returns the records rendered after the first from bytes that
// contain s, so a subtest sees only what was logged while it ran.
func (l *renderedLogs) linesWith(from int, s string) []string {
	var lines []string
	for line := range strings.SplitSeq(l.String()[from:], "\n") {
		if strings.Contains(line, s) {
			lines = append(lines, line)
		}
	}
	return lines
}

// debugRecordFor reports whether a DEBUG record carrying the policy's id was
// rendered. The policy manager logs nothing at DEBUG, so it is the backend's
// apply line.
func (l *renderedLogs) debugRecordFor(policyID string) bool {
	for line := range strings.SplitSeq(l.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["level"] == "DEBUG" && rec["policy_id"] == policyID {
			return true
		}
	}
	return false
}
