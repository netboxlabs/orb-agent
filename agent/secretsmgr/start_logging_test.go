package secretsmgr

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// newCapturingLogger returns a JSON slog logger writing into the returned buffer.
func newCapturingLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})), buf
}

func TestVaultStart_LogsStartingAndConnectionEstablished(t *testing.T) {
	cluster, _ := createTestVault(t)
	client := getTestVaultClient(t)
	addr := "http://" + cluster.ClusterNodes[0].HostPort

	logger, buf := newCapturingLogger()
	vm := &vaultManager{
		preLogger: logger,
		config: config.VaultManager{
			Address:  addr,
			Auth:     "token",
			AuthArgs: map[string]any{"token": client.Token()},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, vm.Start(ctx))

	logs := buf.String()
	assert.Contains(t, logs, "starting secrets manager")
	assert.Contains(t, logs, `"active":"vault"`)
	assert.Contains(t, logs, addr)
	assert.Contains(t, logs, "secrets manager connection established")
}

func TestVaultStart_LogsStartingBeforeFailure(t *testing.T) {
	logger, buf := newCapturingLogger()
	vm := &vaultManager{
		preLogger: logger,
		config:    config.VaultManager{Address: "http://127.0.0.1:1"},
	}

	require.Error(t, vm.Start(context.Background()))

	logs := buf.String()
	assert.Contains(t, logs, "starting secrets manager")
	assert.Contains(t, logs, `"active":"vault"`)
	assert.NotContains(t, logs, "secrets manager connection established")
}

func TestDopplerStart_LogsStartingAndStarted(t *testing.T) {
	logger, buf := newCapturingLogger()
	d := &dopplerManager{preLogger: logger, config: config.DopplerManager{Token: "tok"}}

	require.NoError(t, d.Start(context.Background()))

	logs := buf.String()
	assert.Contains(t, logs, "starting secrets manager")
	assert.Contains(t, logs, `"active":"doppler"`)
	assert.Contains(t, logs, defaultDopplerAPIHost)
	assert.Contains(t, logs, "secrets manager started")
	assert.NotContains(t, logs, "tok", "token must never be logged")
}

func TestDopplerStart_LogsStartingBeforeFailure(t *testing.T) {
	logger, buf := newCapturingLogger()
	d := &dopplerManager{preLogger: logger, config: config.DopplerManager{}}

	require.Error(t, d.Start(context.Background()))

	logs := buf.String()
	assert.Contains(t, logs, "starting secrets manager")
	assert.Contains(t, logs, `"active":"doppler"`)
	assert.NotContains(t, logs, "secrets manager started")
}

func TestDelineaStart_LogsStartingAndStarted(t *testing.T) {
	logger, buf := newCapturingLogger()
	m := &delineaManager{
		preLogger: logger,
		config: config.DelineaManager{
			ServerURL: "https://secrets.example.invalid",
			Username:  "svc_orb",
			Password:  "hunter2",
		},
	}

	require.NoError(t, m.Start(context.Background()))

	logs := buf.String()
	assert.Contains(t, logs, "starting secrets manager")
	assert.Contains(t, logs, `"active":"delinea"`)
	assert.Contains(t, logs, "https://secrets.example.invalid")
	assert.Contains(t, logs, "secrets manager started")
	assert.NotContains(t, logs, "hunter2", "password must never be logged")
}

func TestCyberArkStart_LogsStartingAndStarted(t *testing.T) {
	logger, buf := newCapturingLogger()
	c := &cyberarkManager{
		preLogger: logger,
		config:    config.CyberArkManager{URL: "https://ccp.example.invalid", AppID: "orb"},
	}

	require.NoError(t, c.Start(context.Background()))

	logs := buf.String()
	assert.Contains(t, logs, "starting secrets manager")
	assert.Contains(t, logs, `"active":"cyberark"`)
	assert.Contains(t, logs, "https://ccp.example.invalid")
	assert.Contains(t, logs, "secrets manager started")
}

func TestFleetStart_LogsStartingAndStarted(t *testing.T) {
	logger, buf := newCapturingLogger()
	f := NewFleetSecretsManager(logger, config.FleetSecretsManager{})

	require.NoError(t, f.Start(context.Background()))

	logs := buf.String()
	assert.Contains(t, logs, "starting secrets manager")
	assert.Contains(t, logs, `"active":"fleet"`)
	assert.Contains(t, logs, "secrets manager started")
}
