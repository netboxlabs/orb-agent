package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
)

func TestSplitEffectivePortTakesAnInlineSuffix(t *testing.T) {
	bare, port, inline := splitEffectivePort("10.0.0.1:6030", 0)
	assert.Equal(t, "10.0.0.1", bare)
	assert.Equal(t, uint16(6030), port)
	assert.True(t, inline)
}

func TestSplitEffectivePortLeavesACIDRAlone(t *testing.T) {
	bare, port, inline := splitEffectivePort("10.0.0.0/24", 0)
	assert.Equal(t, "10.0.0.0/24", bare)
	assert.Equal(t, uint16(config.DefaultGNMIPort), port)
	assert.False(t, inline)
}

func TestCheckInlinePortRejectsAServiceName(t *testing.T) {
	err := checkInlinePort("10.0.0.1:http")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be a number")

	assert.NoError(t, checkInlinePort("10.0.0.1:6030"))
	assert.NoError(t, checkInlinePort("2001:db8::1"), "an unbracketed IPv6 literal is not an inline port")
}

// Port 0 parses as a number and is not one. splitEffectivePort would store it
// and resolvedPort would then redirect the target to the default port, so
// "10.0.0.1:0" reached a device on 9339 while the operator read it as a pin.
func TestCheckInlinePortRejectsZero(t *testing.T) {
	err := checkInlinePort("10.0.0.1:0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "between 1 and 65535")

	assert.NoError(t, checkInlinePort("10.0.0.1:1"))
}
