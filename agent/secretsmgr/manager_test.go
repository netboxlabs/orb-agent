package secretsmgr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// TestDummyManager_SolvePolicySecrets_GenericSchemeErrors verifies that the
// dummy manager (active when no secrets manager is configured) fails fast on a
// ${secret://…} reference instead of passing it through as a literal.
func TestDummyManager_SolvePolicySecrets_GenericSchemeErrors(t *testing.T) {
	dm := &dummyManager{}

	payload := config.PolicyPayload{
		ID: "policy1",
		Data: map[string]any{
			"key": "${secret://x}",
		},
	}

	_, err := dm.SolvePolicySecrets(payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no secrets manager is configured")
}

// TestDummyManager_SolvePolicySecrets_ProviderSchemePassesThrough verifies
// pre-existing behavior is unchanged: provider-specific placeholders and plain
// values pass through untouched when no secrets manager is configured.
func TestDummyManager_SolvePolicySecrets_ProviderSchemePassesThrough(t *testing.T) {
	dm := &dummyManager{}

	payload := config.PolicyPayload{
		ID: "policy1",
		Data: map[string]any{
			"provider": "${vault://x}",
			"plain":    "plain value",
		},
	}

	out, err := dm.SolvePolicySecrets(payload)
	require.NoError(t, err)
	data := out.Data.(map[string]any)
	assert.Equal(t, "${vault://x}", data["provider"])
	assert.Equal(t, "plain value", data["plain"])
}

// TestDummyManager_SolveConfigSecrets_GenericSchemeErrors verifies the
// config-secrets path also rejects a ${secret://…} reference found in the
// backends map.
func TestDummyManager_SolveConfigSecrets_GenericSchemeErrors(t *testing.T) {
	dm := &dummyManager{}

	backends := map[string]any{
		"otel": map[string]any{"token": "${secret://y}"},
	}

	_, _, err := dm.SolveConfigSecrets(backends, config.ManagerConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no secrets manager is configured")
}

// TestDummyManager_SolveConfigSecrets_ConfigManagerGenericSchemeErrors verifies
// the ManagerConfig branch (structToMap round-trip) also rejects a ${secret://…}
// reference — it is a distinct code path from the backends walk.
func TestDummyManager_SolveConfigSecrets_ConfigManagerGenericSchemeErrors(t *testing.T) {
	dm := &dummyManager{}

	cm := config.ManagerConfig{}
	cm.Sources.Fleet.ClientSecret = "${secret://x}"

	_, _, err := dm.SolveConfigSecrets(map[string]any{}, cm)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no secrets manager is configured")
}

// TestDummyManager_SolveConfigSecrets_Passthrough verifies provider-specific
// schemes, ${VAR} placeholders, and plain values pass through the config path
// untouched with no error.
func TestDummyManager_SolveConfigSecrets_Passthrough(t *testing.T) {
	dm := &dummyManager{}

	backends := map[string]any{
		"otel": map[string]any{
			"token": "${vault://kv/app/token}",
			"plain": "just a value",
		},
	}
	cm := config.ManagerConfig{}
	cm.Sources.Fleet.ClientSecret = "${FLEET_CLIENT_SECRET}"

	gotBackends, gotCM, err := dm.SolveConfigSecrets(backends, cm)
	require.NoError(t, err)
	assert.Equal(t, backends, gotBackends)
	assert.Equal(t, cm, gotCM)
}
