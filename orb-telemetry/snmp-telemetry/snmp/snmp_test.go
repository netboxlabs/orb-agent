package snmp

import (
	"context"
	"log/slog"
	"net"
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
	w, err := NewClient(t.Context(), "10.0.0.1", 161, 1, time.Second, auth, clientTestLogger)
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

// The fake has to answer the way gosnmp does: parseObjectIdentifier prefixes
// every PDU name with a dot, and a double that omits it hides every prefix
// comparison a caller makes against a profile OID.
func TestFakeSNMPWalker_NamesCarryLeadingDot(t *testing.T) {
	w, err := NewFakeSNMPWalker(t.Context(), "10.0.0.1", 161, 1, time.Second, nil, clientTestLogger)
	require.NoError(t, err)

	pdus, err := w.Walk("1.3.6.1.2.1.2.2.1.2", 1)
	require.NoError(t, err)
	require.Len(t, pdus, 1)
	for name, pdu := range pdus {
		assert.Equal(t, ".1.3.6.1.2.1.2.2.1.2.999", name)
		assert.Equal(t, name, pdu.Name, "the map key and the PDU name must agree")
	}
}

// ---------------------------------------------------------------------------
// Collection context reaching the SNMP client
// ---------------------------------------------------------------------------

// TestNewClient_CarriesCollectionContext pins the context onto the gosnmp
// handle for every protocol version. gosnmp consults it when it dials and again
// before each request attempt, so a client built without it can stay in its
// retry sequence long after the collection was cancelled.
func TestNewClient_CarriesCollectionContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, auth := range []*config.Authentication{
		{ProtocolVersion: ProtocolVersion1, Community: "public"},
		{ProtocolVersion: ProtocolVersion2c, Community: "public"},
		{ProtocolVersion: ProtocolVersion3, SecurityLevel: "noAuthNoPriv", Username: "admin"},
	} {
		t.Run(auth.ProtocolVersion, func(t *testing.T) {
			w, err := NewClient(ctx, "10.0.0.1", 161, 1, time.Second, auth, clientTestLogger)
			require.NoError(t, err)
			c, ok := w.(*Client)
			require.True(t, ok)
			assert.Same(t, ctx, c.Context)
		})
	}
}

// TestClient_ConnectStopsOnCancelledContext checks the dial honours the
// context. The address is a loopback literal so no resolver is involved.
func TestClient_ConnectStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	w, err := NewClient(ctx, "127.0.0.1", 161, 1, time.Second,
		&config.Authentication{ProtocolVersion: ProtocolVersion2c, Community: "public"}, clientTestLogger)
	require.NoError(t, err)
	require.ErrorIs(t, w.Connect(), context.Canceled)
}

// TestClient_WalkStopsWhenContextIsCancelled is the point of the change: a walk
// against a socket that never answers must abandon its retry sequence when the
// collection is cancelled, rather than running every retry to completion.
func TestClient_WalkStopsWhenContextIsCancelled(t *testing.T) {
	// A bound UDP socket that reads nothing, so every request times out.
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = silent.Close() }()
	addr, ok := silent.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		perRequest = 50 * time.Millisecond
		retries    = 100
	)
	w, err := NewClient(ctx, "127.0.0.1", uint16(addr.Port), retries, perRequest, //nolint:gosec
		&config.Authentication{ProtocolVersion: ProtocolVersion2c, Community: "public"}, clientTestLogger)
	require.NoError(t, err)
	require.NoError(t, w.Connect())
	defer func() { _ = w.Close() }()

	go func() {
		time.Sleep(3 * perRequest)
		cancel()
	}()

	start := time.Now()
	_, err = w.Walk("1.3.6.1.2.1.1.1", 0)
	elapsed := time.Since(start)

	require.Error(t, err)
	// The full retry sequence is retries*perRequest, five seconds here. The
	// bound is far below that and far above the cancellation, so the assertion
	// does not turn on how fast the host is.
	assert.Less(t, elapsed, retries*perRequest/4,
		"the walk ran on past the cancelled collection")
}
