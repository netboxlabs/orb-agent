package snmp

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

var clientTestLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

func newTestClient(t *testing.T, auth *config.Authentication) *Client {
	t.Helper()
	w, err := NewClient("10.0.0.1", 161, 1, time.Second, auth, clientTestLogger)
	require.NoError(t, err)
	c, ok := w.(*Client)
	require.True(t, ok, "NewClient must return *Client")
	return c
}

// The context name has to reach the gosnmp handle, not merely pass validation.
// It belongs on the GoSNMP root, not inside SecurityParameters.
func TestNewClient_V3CarriesContextName(t *testing.T) {
	c := newTestClient(t, &config.Authentication{
		ProtocolVersion: ProtocolVersion3,
		SecurityLevel:   "authPriv",
		Username:        "admin",
		AuthProtocol:    "SHA",
		AuthPassphrase:  "authpass",
		PrivProtocol:    "AES",
		PrivPassphrase:  "privpass",
		ContextName:     "vrf-mgmt",
	})
	assert.Equal(t, "vrf-mgmt", c.ContextName)
	assert.Equal(t, gosnmp.Version3, c.Version)
	assert.Equal(t, gosnmp.AuthPriv, c.MsgFlags)
}

// An absent context name must leave the field empty rather than defaulting.
func TestNewClient_V3WithoutContextNameLeavesItEmpty(t *testing.T) {
	c := newTestClient(t, &config.Authentication{
		ProtocolVersion: ProtocolVersion3,
		SecurityLevel:   "noAuthNoPriv",
		Username:        "admin",
	})
	assert.Empty(t, c.ContextName)
	assert.Equal(t, gosnmp.NoAuthNoPriv, c.MsgFlags)
}

// v2c is the common path and must keep working across the gosnmp bump.
func TestNewClient_V2cUsesCommunity(t *testing.T) {
	c := newTestClient(t, &config.Authentication{
		ProtocolVersion: "SNMPv2c",
		Community:       "public",
	})
	assert.Equal(t, gosnmp.Version2c, c.Version)
	assert.Equal(t, "public", c.Community)
}

// Security level drives MsgFlags; getting this wrong authenticates with the
// wrong mode and the device simply refuses.
func TestNewClient_V3SecurityLevelMapsToMsgFlags(t *testing.T) {
	for level, want := range map[string]gosnmp.SnmpV3MsgFlags{
		"noAuthNoPriv": gosnmp.NoAuthNoPriv,
		"authNoPriv":   gosnmp.AuthNoPriv,
		"authPriv":     gosnmp.AuthPriv,
	} {
		c := newTestClient(t, &config.Authentication{
			ProtocolVersion: ProtocolVersion3,
			SecurityLevel:   level,
			Username:        "admin",
			AuthProtocol:    "SHA",
			AuthPassphrase:  "authpass",
			PrivProtocol:    "AES",
			PrivPassphrase:  "privpass",
		})
		assert.Equal(t, want, c.MsgFlags, "security level %q", level)
	}
}
