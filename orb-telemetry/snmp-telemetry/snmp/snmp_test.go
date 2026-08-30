package snmp

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
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

// The fake also has to answer honestly about which request type it was asked
// for. A double that reported the same walk however it was set up would let a
// regression from GETBULK back to GETNEXT pass the suite.
func TestFakeSNMPWalker_RecordsTheWalkModeItWasGiven(t *testing.T) {
	w, err := NewFakeSNMPWalker(t.Context(), "10.0.0.1", 161, 1, time.Second, nil, clientTestLogger)
	require.NoError(t, err)

	_, err = w.Walk("1.3.6.1.2.1.2.2.1.2", 1)
	require.NoError(t, err)
	w.SetBulkWalk(true)
	_, err = w.Walk("1.3.6.1.2.1.2.2.1.5", 1)
	require.NoError(t, err)

	fake, ok := w.(*FakeSNMPWalker)
	require.True(t, ok)
	assert.Equal(t, []FakeWalk{
		{OID: "1.3.6.1.2.1.2.2.1.2", BulkWalk: false},
		{OID: "1.3.6.1.2.1.2.2.1.5", BulkWalk: true},
	}, fake.Walks)
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
	port := udpPort(t, silent.LocalAddr())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		perRequest = 50 * time.Millisecond
		retries    = 100
	)
	w, err := NewClient(ctx, "127.0.0.1", port, retries, perRequest,
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

// ---------------------------------------------------------------------------
// GETBULK
// ---------------------------------------------------------------------------

// oidLess orders two dotted OIDs by numeric component, the way an agent orders
// its MIB. String order would put .10 before .2 and the walk would look like it
// went backwards.
func oidLess(a, b string) bool {
	as := strings.Split(strings.TrimPrefix(a, "."), ".")
	bs := strings.Split(strings.TrimPrefix(b, "."), ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, _ := strconv.Atoi(as[i])
		bi, _ := strconv.Atoi(bs[i])
		if ai != bi {
			return ai < bi
		}
	}
	return len(as) < len(bs)
}

// fakeAgent is a UDP SNMP agent serving one ordered table. It answers GETNEXT
// and GETBULK out of the same data, so the two walks can be compared value for
// value, and it counts requests by type so the round trips of each are visible.
// Counting in the client would only report what the client meant to send.
// udpPort returns a listener's port, checking the address type and the range
// rather than asserting them. A port is always inside uint16, but the compiler
// cannot know that from net.UDPAddr's int field.
func udpPort(t *testing.T, addr net.Addr) uint16 {
	t.Helper()
	udp, ok := addr.(*net.UDPAddr)
	require.True(t, ok, "expected a UDP address, got %T", addr)
	require.GreaterOrEqual(t, udp.Port, 0)
	require.LessOrEqual(t, udp.Port, math.MaxUint16)
	return uint16(udp.Port)
}

type fakeAgent struct {
	conn net.PacketConn
	port uint16
	vars []gosnmp.SnmpPDU

	mu       sync.Mutex
	requests map[gosnmp.PDUType]int
	maxReps  []uint32
}

func newFakeAgent(t *testing.T, vars []gosnmp.SnmpPDU) *fakeAgent {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	a := &fakeAgent{conn: conn, port: udpPort(t, conn.LocalAddr()), vars: vars, requests: make(map[gosnmp.PDUType]int)}
	go a.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return a
}

func (a *fakeAgent) counts() (map[gosnmp.PDUType]int, []uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[gosnmp.PDUType]int, len(a.requests))
	for k, v := range a.requests {
		out[k] = v
	}
	return out, append([]uint32(nil), a.maxReps...)
}

func (a *fakeAgent) serve() {
	codec := &gosnmp.GoSNMP{Version: gosnmp.Version2c, MaxOids: gosnmp.MaxOids}
	buf := make([]byte, 4096)
	for {
		n, addr, err := a.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := codec.SnmpDecodePacket(buf[:n])
		if err != nil {
			continue
		}
		a.mu.Lock()
		a.requests[req.PDUType]++
		if req.PDUType == gosnmp.GetBulkRequest {
			a.maxReps = append(a.maxReps, req.MaxRepetitions)
		}
		a.mu.Unlock()

		codec.Version = req.Version
		codec.Community = req.Community
		// The encoder stamps the next value of its own counter, so seeding it
		// one below the request's ID makes the reply carry that ID.
		codec.SetRequestID(req.RequestID - 1)
		out, err := codec.SnmpEncodePacket(gosnmp.GetResponse, a.answer(req), 0, 0)
		if err != nil {
			continue
		}
		_, _ = a.conn.WriteTo(out, addr)
	}
}

// answer builds the varbinds for one request. An exhausted walk gets
// endOfMibView rather than an empty varbind list, which a client treats as a
// malformed reply and retries.
func (a *fakeAgent) answer(req *gosnmp.SnmpPacket) []gosnmp.SnmpPDU {
	if len(req.Variables) == 0 {
		return nil
	}
	name := req.Variables[0].Name
	endOfMib := []gosnmp.SnmpPDU{{Name: name, Type: gosnmp.EndOfMibView}}

	if req.PDUType == gosnmp.GetRequest {
		for _, v := range a.vars {
			if strings.TrimPrefix(v.Name, ".") == strings.TrimPrefix(name, ".") {
				return []gosnmp.SnmpPDU{v}
			}
		}
		return []gosnmp.SnmpPDU{{Name: name, Type: gosnmp.NoSuchObject}}
	}

	next := len(a.vars)
	for i, v := range a.vars {
		if oidLess(name, v.Name) {
			next = i
			break
		}
	}
	if next == len(a.vars) {
		return endOfMib
	}
	count := 1
	if req.PDUType == gosnmp.GetBulkRequest {
		count = int(req.MaxRepetitions)
	}
	if next+count > len(a.vars) {
		count = len(a.vars) - next
	}
	return a.vars[next : next+count]
}

// interfaceTable builds a table of the shape a bundled profile walks: several
// columns of the same width, plus one value past the subtree so the walk has
// somewhere to stop.
func interfaceTable(root string, columns, rows int) []gosnmp.SnmpPDU {
	vars := make([]gosnmp.SnmpPDU, 0, columns*rows+1)
	for col := 1; col <= columns; col++ {
		for row := 1; row <= rows; row++ {
			vars = append(vars, gosnmp.SnmpPDU{
				Name:  fmt.Sprintf("%s.%d.%d", root, col, row),
				Type:  gosnmp.OctetString,
				Value: []byte(fmt.Sprintf("c%dr%d", col, row)),
			})
		}
	}
	// Outside root, so the walk leaves the subtree instead of running to the
	// end of the agent's MIB.
	return append(vars, gosnmp.SnmpPDU{Name: "1.3.6.1.2.1.3.1.1.0", Type: gosnmp.OctetString, Value: []byte("beyond")})
}

func agentClient(t *testing.T, a *fakeAgent, version string) *Client {
	t.Helper()
	w, err := NewClient(t.Context(), "127.0.0.1", a.port, 1, 3*time.Second,
		&config.Authentication{ProtocolVersion: version, Community: "public"}, clientTestLogger)
	require.NoError(t, err)
	require.NoError(t, w.Connect())
	t.Cleanup(func() { _ = w.Close() })
	c, ok := w.(*Client)
	require.True(t, ok)
	return c
}

// TestClient_BulkWalkReturnsTheSameValuesInFewerRoundTrips is the point of the
// change. The values collected must not move; only the number of requests that
// fetched them.
func TestClient_BulkWalkReturnsTheSameValuesInFewerRoundTrips(t *testing.T) {
	const (
		root    = "1.3.6.1.2.1.2.2.1"
		columns = 5
		rows    = 200
		values  = columns * rows
	)
	table := interfaceTable(root, columns, rows)

	getNextAgent := newFakeAgent(t, table)
	getNext := agentClient(t, getNextAgent, ProtocolVersion2c)
	getNext.SetBulkWalk(false)
	byGetNext, err := getNext.Walk(root, 0)
	require.NoError(t, err)

	bulkAgent := newFakeAgent(t, table)
	bulk := agentClient(t, bulkAgent, ProtocolVersion2c)
	bulk.SetBulkWalk(true)
	byBulk, err := bulk.Walk(root, 0)
	require.NoError(t, err)

	require.Len(t, byGetNext, values)
	assert.Equal(t, byGetNext, byBulk, "GETBULK must collect exactly what GETNEXT collected")

	nextCounts, nextReps := getNextAgent.counts()
	bulkCounts, bulkReps := bulkAgent.counts()

	// One GETNEXT per value, plus the one that leaves the subtree.
	assert.Equal(t, map[gosnmp.PDUType]int{gosnmp.GetNextRequest: values + 1}, nextCounts)
	assert.Empty(t, nextReps)

	// GETBULK carries back maxRepetitions values at a time, and the walk stops
	// on the first batch holding the value past the subtree.
	wantBulk := (values + int(maxRepetitions)) / int(maxRepetitions)
	assert.Equal(t, map[gosnmp.PDUType]int{gosnmp.GetBulkRequest: wantBulk}, bulkCounts)
	require.NotEmpty(t, bulkReps)
	for _, r := range bulkReps {
		assert.Equal(t, maxRepetitions, r, "every GETBULK must ask for the chosen batch size")
	}
	// gosnmp falls back to 50 when the field is unset, which its own
	// documentation warns is more than some agents can fit in one reply.
	assert.Less(t, maxRepetitions, uint32(50), "the batch size must be a choice, not gosnmp's fallback")
	assert.Less(t, wantBulk, values/10, "GETBULK must cut the round trips by an order of magnitude")
}

// TestClient_SNMPv1NeverBulkWalks pins the one case where GETBULK is not an
// option: it was introduced in SNMPv2, and gosnmp fails a GETBULK on a v1
// connection outright rather than falling back. A v1 client that honoured
// SetBulkWalk(true) would collect nothing at all.
func TestClient_SNMPv1NeverBulkWalks(t *testing.T) {
	const root = "1.3.6.1.2.1.2.2.1"
	agent := newFakeAgent(t, interfaceTable(root, 2, 3))

	c := agentClient(t, agent, ProtocolVersion1)
	c.SetBulkWalk(true)
	pdus, err := c.Walk(root, 0)
	require.NoError(t, err)
	assert.Len(t, pdus, 6)

	counts, _ := agent.counts()
	assert.Equal(t, map[gosnmp.PDUType]int{gosnmp.GetNextRequest: 7}, counts)
}

// TestClient_BulkWalkHonoursTheCollectionContext repeats the cancellation
// guarantee for the bulk path. gosnmp routes GETBULK and GETNEXT through the
// same send, so this holds by construction, and it is pinned because a walk
// that ignored the context would keep a cancelled collection alive.
func TestClient_BulkWalkHonoursTheCollectionContext(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = silent.Close() }()
	port := udpPort(t, silent.LocalAddr())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const (
		perRequest = 50 * time.Millisecond
		retries    = 100
	)
	w, err := NewClient(ctx, "127.0.0.1", port, retries, perRequest,
		&config.Authentication{ProtocolVersion: ProtocolVersion2c, Community: "public"}, clientTestLogger)
	require.NoError(t, err)
	require.NoError(t, w.Connect())
	defer func() { _ = w.Close() }()
	w.SetBulkWalk(true)

	go func() {
		time.Sleep(3 * perRequest)
		cancel()
	}()

	start := time.Now()
	_, err = w.Walk("1.3.6.1.2.1.2.2.1", 0)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Less(t, elapsed, retries*perRequest/4,
		"the bulk walk ran on past the cancelled collection")
}

// TestNewClient_BulkWalkIsOffUntilTheProfileAllowsIt covers the walks that come
// before a profile is known. Those read sysObjectID and sysDescr, which is how
// the profile is chosen, so they cannot yet know whether the device tolerates
// GETBULK.
func TestNewClient_BulkWalkIsOffUntilTheProfileAllowsIt(t *testing.T) {
	for _, version := range []string{ProtocolVersion1, ProtocolVersion2c, ProtocolVersion3} {
		t.Run(version, func(t *testing.T) {
			c := newTestClient(t, &config.Authentication{
				ProtocolVersion: version,
				Community:       "public",
				SecurityLevel:   "noAuthNoPriv",
				Username:        "admin",
			})
			assert.False(t, c.bulkWalk)
		})
	}
}

// SNMPv1 has no GETBULK, so the switch must refuse to arm rather than leave a
// v1 client to fail every walk.
func TestClient_SetBulkWalkIsIgnoredOnV1(t *testing.T) {
	v1 := newTestClient(t, &config.Authentication{ProtocolVersion: ProtocolVersion1, Community: "public"})
	v1.SetBulkWalk(true)
	assert.False(t, v1.bulkWalk)

	v2c := newTestClient(t, &config.Authentication{ProtocolVersion: ProtocolVersion2c, Community: "public"})
	v2c.SetBulkWalk(true)
	assert.True(t, v2c.bulkWalk)
	v2c.SetBulkWalk(false)
	assert.False(t, v2c.bulkWalk)
}
