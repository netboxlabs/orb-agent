package secretsmgr

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func TestDopplerStart_EmptyTokenFails(t *testing.T) {
	d := &dopplerManager{
		logger: newTestLogger(),
		config: config.DopplerManager{},
	}
	err := d.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "token is required")
}

func TestDopplerStart_DefaultsAPIHostAndTimeout(t *testing.T) {
	d := &dopplerManager{
		logger: newTestLogger(),
		config: config.DopplerManager{Token: "dp.st.faketoken"},
	}
	err := d.Start(context.Background())
	require.NoError(t, err)
	require.Equal(t, "https://api.doppler.com", d.apiHost)
	require.NotNil(t, d.httpClient)
}

func TestDopplerStart_TokenFromEnv(t *testing.T) {
	t.Setenv("DOPPLER_TOKEN_TEST_TASK2", "dp.st.fromenv")
	d := &dopplerManager{
		logger: newTestLogger(),
		config: config.DopplerManager{Token: "${DOPPLER_TOKEN_TEST_TASK2}"},
	}
	err := d.Start(context.Background())
	require.NoError(t, err)
	require.Equal(t, "dp.st.fromenv", d.config.Token)
}

func TestDopplerStart_UnsetEnvTokenFails(t *testing.T) {
	d := &dopplerManager{
		logger: newTestLogger(),
		config: config.DopplerManager{Token: "${ORB_UNSET_VAR_TASK2}"},
	}
	err := d.Start(context.Background())
	require.Error(t, err)
}
