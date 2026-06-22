package configmgr

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
)

// When the files manager is the fleet type, BindFilesManager registers the
// catch-up OnReadyHook (which sends bundle_list_req on connect).
func TestBindFilesManager_FleetTypeRegistersCatchUpHook(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockConn := &fleet.MockMQTTConnection{}
	mgr := newFleetConfigManagerWithConnection(logger, nil, nil, mockConn)

	fm := filesmgr.New(logger, config.FilesManagerConfig{Active: "fleet"})
	require.NoError(t, mgr.BindFilesManager(fm))
	assert.Equal(t, 1, mockConn.HookCount(),
		"fleet files manager should register one catch-up OnReadyHook")
}

// When the files manager is not the fleet type (dummy / delivery inactive),
// BindFilesManager warns and registers no hook.
func TestBindFilesManager_NonFleetRegistersNoHook(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockConn := &fleet.MockMQTTConnection{}
	mgr := newFleetConfigManagerWithConnection(logger, nil, nil, mockConn)

	fm := filesmgr.New(logger, config.FilesManagerConfig{}) // dummy
	require.NoError(t, mgr.BindFilesManager(fm))
	assert.Equal(t, 0, mockConn.HookCount(),
		"non-fleet files manager should register no catch-up hook")
}
