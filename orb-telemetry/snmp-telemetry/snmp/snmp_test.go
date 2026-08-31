package snmp

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
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
	// corrupt, when set, rewrites each encoded reply before it goes on the
	// wire, so a test can drive the client's parse errors with a real packet
	// rather than a hand-written one.
	corrupt func([]byte) []byte

	mu       sync.Mutex
	requests map[gosnmp.PDUType]int
	maxReps  []uint32
}

func newFakeAgent(t *testing.T, vars []gosnmp.SnmpPDU) *fakeAgent {
	t.Helper()
	return newCorruptingAgent(t, vars, nil)
}

// newCorruptingAgent serves the same table through a rewrite applied to every
// reply, so a test can drive the client with a packet a device would not send.
// The hook is set before the agent serves: setting it afterwards would race the
// serving goroutine.
func newCorruptingAgent(t *testing.T, vars []gosnmp.SnmpPDU, corrupt func([]byte) []byte) *fakeAgent {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	a := &fakeAgent{
		conn:     conn,
		port:     udpPort(t, conn.LocalAddr()),
		vars:     vars,
		corrupt:  corrupt,
		requests: make(map[gosnmp.PDUType]int),
	}
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
		if a.corrupt != nil {
			out = a.corrupt(out)
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

// ---------------------------------------------------------------------------
// The community must not reach the log
// ---------------------------------------------------------------------------

// debugLogger returns a debug-level logger and the buffer it writes to. Debug
// is the level that installs gosnmp's packet logger, so it is the level the
// disclosure needs.
func debugLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// The community is the credential of an SNMPv1 or v2c session, and gosnmp logs
// every packet it sends and the community it parses out of every reply. A
// debug run against a real device must leave neither in the log.
func TestClient_CommunityNeverReachesTheDebugLog(t *testing.T) {
	const (
		root      = "1.3.6.1.2.1.2.2.1"
		community = "n0t-in-the-log"
	)
	agent := newFakeAgent(t, interfaceTable(root, 2, 3))
	logger, buf := debugLogger()

	w, err := NewClient(t.Context(), "127.0.0.1", agent.port, 1, 3*time.Second,
		&config.Authentication{ProtocolVersion: ProtocolVersion2c, Community: community}, logger)
	require.NoError(t, err)
	require.NoError(t, w.Connect())
	t.Cleanup(func() { _ = w.Close() })

	values, err := w.Walk(root, 0)
	require.NoError(t, err)
	require.NotEmpty(t, values, "the walk has to reach the agent for the log to hold packets")

	logged := buf.String()
	require.Contains(t, logged, "SENDING PACKET", "the packet logger has to be installed for this to pin anything")
	require.Contains(t, logged, "Parsed community", "the reply path has to have parsed a community")
	assert.NotContains(t, logged, community, "the community reached the debug log")
	assert.Contains(t, logged, "Community:"+redactedCommunity, "the packet line keeps its community field, redacted")
	assert.Contains(t, logged, root, "redaction left the rest of the packet line intact")
}

// gosnmp's packet format is what discloses the community: SafeString prints it
// verbatim. Pinning the adapter against that real output rather than a
// hand-written sample means a gosnmp bump that changes the format fails here.
func TestSlogAdapter_RedactsTheCommunityFromARealPacketLine(t *testing.T) {
	const community = "n0t-in-the-log"
	packet := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: community,
		PDUType:   gosnmp.GetNextRequest,
		RequestID: 42,
		Variables: []gosnmp.SnmpPDU{{Name: "1.3.6.1.2.1.1.1.0", Type: gosnmp.Null}},
	}
	line := packet.SafeString()
	require.Contains(t, line, "Community:"+community,
		"gosnmp no longer prints the community here; revisit what the adapter redacts")

	logger, buf := debugLogger()
	adapter := &SlogAdapter{logger: logger, community: community}
	adapter.Printf("SENDING PACKET: %s", line)

	logged := buf.String()
	assert.NotContains(t, logged, community, "the community survived the adapter")
	assert.Contains(t, logged, "Community:"+redactedCommunity)
	assert.Contains(t, logged, "1.3.6.1.2.1.1.1.0", "the varbind survived the redaction")
	assert.Contains(t, logged, "RequestID:42", "the request ID survived the redaction")
	assert.Contains(t, logged, "Version:2c", "the version survived the redaction")
}

// Print carries the same lines as Printf, so it redacts the same way.
func TestSlogAdapter_PrintRedactsTheCommunity(t *testing.T) {
	const community = "n0t-in-the-log"
	logger, buf := debugLogger()
	adapter := &SlogAdapter{logger: logger, community: community}

	adapter.Print("Parsed community ", community)

	logged := buf.String()
	assert.NotContains(t, logged, community)
	assert.Contains(t, logged, "Parsed community "+redactedCommunity)
}

// A v3 client carries no community, and an empty needle must not be replaced
// between every character of the line.
func TestSlogAdapter_EmptyCommunityLeavesTheLineAlone(t *testing.T) {
	logger, buf := debugLogger()
	adapter := &SlogAdapter{logger: logger}

	adapter.Printf("SECURITY PARAMETERS:%s", "UserName:admin")

	assert.Contains(t, buf.String(), "SECURITY PARAMETERS:UserName:admin")
	assert.NotContains(t, buf.String(), redactedCommunity)
}

// The v3 path is out of scope because gosnmp's USM SafeString prints the
// per-packet authentication and privacy parameters, which are an HMAC and an
// IV, and never the passphrases. This pins that, so a gosnmp bump that starts
// printing one is caught here rather than in a customer's log.
func TestUsmSecurityParameters_SafeStringOmitsThePassphrases(t *testing.T) {
	const (
		authPassphrase = "n0t-in-the-log-auth"
		privPassphrase = "n0t-in-the-log-priv"
	)
	sp := &gosnmp.UsmSecurityParameters{
		UserName:                 "admin",
		AuthenticationProtocol:   gosnmp.SHA,
		AuthenticationPassphrase: authPassphrase,
		AuthenticationParameters: "per-packet-hmac",
		PrivacyProtocol:          gosnmp.AES,
		PrivacyPassphrase:        privPassphrase,
	}

	line := sp.SafeString()

	assert.NotContains(t, line, authPassphrase, "the auth passphrase reached a safe string")
	assert.NotContains(t, line, privPassphrase, "the priv passphrase reached a safe string")
	assert.Contains(t, line, "UserName:admin", "the user name is what makes the line useful")
	assert.Contains(t, line, "per-packet-hmac", "the per-packet authentication parameters survive")
}

// The v3 client installs the same adapter, so the whole debug run must stay
// free of both passphrases.
func TestClient_V3PassphrasesNeverReachTheDebugLog(t *testing.T) {
	const (
		authPassphrase = "n0t-in-the-log-auth"
		privPassphrase = "n0t-in-the-log-priv"
	)
	logger, buf := debugLogger()

	w, err := NewClient(t.Context(), "127.0.0.1", 161, 1, time.Second, &config.Authentication{
		ProtocolVersion: ProtocolVersion3,
		SecurityLevel:   SecurityLevelAuthPriv,
		Username:        "admin",
		AuthProtocol:    "SHA",
		AuthPassphrase:  authPassphrase,
		PrivProtocol:    "AES",
		PrivPassphrase:  privPassphrase,
	}, logger)
	require.NoError(t, err)
	c, ok := w.(*Client)
	require.True(t, ok)

	sp, ok := c.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	require.True(t, ok)
	sp.Logger = c.Logger
	sp.Log()

	logged := buf.String()
	require.Contains(t, logged, "SECURITY PARAMETERS", "the security parameters have to have been logged")
	assert.NotContains(t, logged, authPassphrase)
	assert.NotContains(t, logged, privPassphrase)
}

// ---------------------------------------------------------------------------
// The community must not ride out on an error either
// ---------------------------------------------------------------------------

// A v2c reply carries the community as an octet string near its front:
// 30 <len> 02 01 01 04 <communityLength> <community> ... The two corruptions
// below are the ones that make gosnmp quote those bytes back.
const communityLengthOctet = 6

// overstateCommunityLength rewrites the community's length octet to the BER
// long form, so the parser reads a length running past the buffer and reports
// the whole remaining packet.
func overstateCommunityLength(pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	out[communityLengthOctet] = 0x82
	return out
}

// cutInsideCommunity truncates the packet partway through the community and
// rewrites the outer length to match, so the reply passes gosnmp's sanity
// check and the dump ends inside the community.
func cutInsideCommunity(keep int) func([]byte) []byte {
	return func(pkt []byte) []byte {
		out := append([]byte(nil), pkt[:communityLengthOctet+1+keep]...)
		out[1] = byte(len(out) - 2)
		return out
	}
}

// hexPrefixes returns the lowercase hex of every prefix of the community, from
// the whole value down to its first byte. A dump that ends inside the
// community carries one of these, and a prefix of a credential is still one.
func hexPrefixes(community string) []string {
	out := make([]string, 0, len(community))
	for n := len(community); n > 0; n-- {
		out = append(out, hex.EncodeToString([]byte(community[:n])))
	}
	return out
}

// minRecognisableFragment is the shortest run of the community's bytes the
// assertions treat as a disclosure. Below three bytes a run turns up in an
// unrelated dump by chance, and the request ID of each reply is random.
const minRecognisableFragment = 3

// assertCommunityGone checks that no run of the community's bytes survives:
// every prefix, which is what a dump cut short inside the community carries,
// and every inner run of three bytes or more, which is what a redaction
// replacing the leading byte first would leave behind.
func assertCommunityGone(t *testing.T, subject, community string) {
	t.Helper()
	for _, p := range hexPrefixes(community) {
		assert.NotContains(t, subject, p, "%d bytes of the community appeared in hex", len(p)/2)
	}
	for start := 1; start < len(community); start++ {
		for end := start + minRecognisableFragment; end <= len(community); end++ {
			run := hex.EncodeToString([]byte(community[start:end]))
			assert.NotContains(t, subject, run, "bytes %d..%d of the community appeared in hex", start, end)
		}
	}
}

// walkAgainstCorruptAgent walks a fake agent whose replies are rewritten, and
// returns the error the client reports.
func walkAgainstCorruptAgent(t *testing.T, community string, corrupt func([]byte) []byte) error {
	t.Helper()
	const root = "1.3.6.1.2.1.2.2.1"
	agent := newCorruptingAgent(t, interfaceTable(root, 1, 1), corrupt)
	w, err := NewClient(t.Context(), "127.0.0.1", agent.port, 0, 300*time.Millisecond,
		&config.Authentication{ProtocolVersion: ProtocolVersion2c, Community: community}, clientTestLogger)
	require.NoError(t, err)
	require.NoError(t, w.Connect())
	t.Cleanup(func() { _ = w.Close() })
	_, err = w.Walk(root, 0)
	require.Error(t, err, "the corrupt reply has to have failed the walk")
	return err
}

// A reply whose community length octet is corrupt makes gosnmp quote the rest
// of the packet, community included, into the error it returns. That error is
// logged at warn level and served by the status endpoint, so it discloses the
// credential whatever the log level.
func TestClient_WalkErrorDoesNotCarryTheCommunity(t *testing.T) {
	const community = "s3cr3tc0mmun1ty"
	msg := walkAgainstCorruptAgent(t, community, overstateCommunityLength).Error()

	assert.NotContains(t, msg, community, "the community appeared in plaintext")
	assertCommunityGone(t, msg, community)
	assert.Contains(t, msg, "error parsing community string", "the parse stage survived")
	assert.Contains(t, msg, "not enough data for OctetString", "the parse failure survived")
	assert.Contains(t, msg, redactedCommunity, "the elided span is marked")
	// The bytes after the community are the diagnostic worth keeping: the
	// varbind holding the value the agent answered with.
	assert.Contains(t, msg, hex.EncodeToString([]byte("c1r1")), "the rest of the dump survived")
}

// A reply cut short inside the community leaves a prefix of it in the dump,
// which a redaction matching only the whole value would miss.
func TestClient_WalkErrorDoesNotCarryACommunityPrefix(t *testing.T) {
	const community = "s3cr3tc0mmun1ty"
	for _, keep := range []int{1, 2, 7, len(community) - 1} {
		t.Run(fmt.Sprintf("cut after %d bytes", keep), func(t *testing.T) {
			msg := walkAgainstCorruptAgent(t, community, cutInsideCommunity(keep)).Error()
			assertCommunityGone(t, msg, community)
			assert.Contains(t, msg, "not enough data for OctetString", "the parse failure survived")
			assert.Contains(t, msg, redactedCommunity, "the elided span is marked")
		})
	}
}

// A one-character community is the case a redaction can mangle: its hex is two
// characters and turns up in an unrelated dump by chance. Only hex is matched,
// never the words of the message, so the diagnostic survives however short the
// community is.
func TestClient_ShortCommunityLeavesTheDiagnosticReadable(t *testing.T) {
	const community = "a"
	msg := walkAgainstCorruptAgent(t, community, overstateCommunityLength).Error()

	assertCommunityGone(t, msg, community)
	assert.Contains(t, msg, "error parsing community string", "the parse stage survived")
	assert.Contains(t, msg, "not enough data for OctetString", "the parse failure survived")
}

// A v3 client carries no community, so an error passes through untouched
// rather than having an empty needle matched against every position in it.
func TestClient_V3WalkErrorIsUnchanged(t *testing.T) {
	c := newTestClient(t, &config.Authentication{
		ProtocolVersion: ProtocolVersion3,
		SecurityLevel:   SecurityLevelNoAuthNoPriv,
		Username:        "admin",
	})
	original := errors.New("not enough data for OctetString (17 vs 3): 040f73")
	assert.Same(t, original, c.redactError(original), "an empty community must redact nothing")
	assert.NoError(t, c.redactError(nil))
}

// An error carrying nothing to redact is returned as it was, so a caller that
// compares errors is not handed a copy.
func TestClient_ErrorWithoutTheCommunityIsReturnedUnchanged(t *testing.T) {
	c := newTestClient(t, &config.Authentication{ProtocolVersion: ProtocolVersion2c, Community: "s3cr3tc0mmun1ty"})
	original := errors.New("request timeout (after 0 retries)")
	assert.Same(t, original, c.redactError(original))
}
