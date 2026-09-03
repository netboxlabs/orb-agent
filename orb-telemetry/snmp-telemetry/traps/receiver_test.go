package traps

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// harness binds a receiver on loopback and returns a sender socket.
type harness struct {
	rcv    *Receiver
	reg    *Registry
	tally  *Tally
	sender *net.UDPConn
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, testLogger)
}

// newHarnessWith binds the receiver with the given logger, for tests that
// read what the receiver logs.
func newHarnessWith(t *testing.T, logger *slog.Logger) *harness {
	t.Helper()
	return newHarnessOn(t, "127.0.0.1:0", logger)
}

// newHarnessOn binds the receiver on the given address, for tests that need
// a dual-stack socket to tell two loopback senders apart.
func newHarnessOn(t *testing.T, listen string, logger *slog.Logger) *harness {
	t.Helper()
	reg := NewRegistry()
	tally := NewTally(logger)
	rcv, err := Listen(listen, reg, tally, BuildNames(nil), logger)
	require.NoError(t, err)
	t.Cleanup(rcv.Stop)
	sender, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(rcv.Addr()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sender.Close() })
	return &harness{rcv: rcv, reg: reg, tally: tally, sender: sender}
}

// registerSender claims the sender socket's own address for a policy, which
// is what makes a loopback test's source "known".
func (h *harness) registerSender(t *testing.T, policy string, users ...V3User) netip.Addr {
	t.Helper()
	local := h.sender.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
	d := Device{Policy: policy, Addr: local}
	if len(users) > 0 {
		d.User = &users[0]
	}
	h.reg.Register(policy, []Device{d}, nil)
	return canonical(local)
}

// newSenderOn opens a sending socket towards the receiver from the given
// loopback address, so that a dual-stack receiver sees 127.0.0.1 and ::1 as
// two devices.
func (h *harness) newSenderOn(t *testing.T, network string, ip net.IP) (*net.UDPConn, netip.Addr) {
	t.Helper()
	conn, err := net.DialUDP(network, nil, &net.UDPAddr{IP: ip, Port: int(h.rcv.Addr().Port())})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn, canonical(conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr())
}

func (h *harness) send(t *testing.T, pkt []byte) {
	t.Helper()
	_, err := h.sender.Write(pkt)
	require.NoError(t, err)
}

// waitFor polls a tally accessor until it reaches want or the deadline passes.
func waitFor(t *testing.T, want int64, get func() int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if get() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	assert.Equal(t, want, get())
}

func TestReceiver_CountsAKnownV2cTrap(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "core")
	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V2c) })
	assert.Equal(t, int64(1), h.tally.datagramCount())
}

// The source check runs before any parsing, so an unknown sender costs a map
// lookup and nothing else (F5), and is counted as dropped.
func TestReceiver_DropsAnUnknownSourceBeforeParsing(t *testing.T) {
	h := newHarness(t)
	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropUnknownSource) })
	assert.Equal(t, int64(0), h.tally.receivedCount("127.0.0.1", "", "linkDown", V2c))

	// A datagram no parser could read still drops on the source, which is only
	// true if the source check runs ahead of the parse.
	h.send(t, []byte{0x30, 0x01, 0xff})
	waitFor(t, 2, func() int64 { return h.tally.droppedCount(DropUnknownSource) })
	assert.Equal(t, int64(0), h.tally.droppedCount(DropMalformed))

	// Nor is a stranger's datagram judged on its size first: oversized is a
	// counter an operator reads as "my devices send oversized traps", and a
	// stranger is not one of their devices.
	h.send(t, make([]byte, maxDatagram+1))
	waitFor(t, 3, func() int64 { return h.tally.droppedCount(DropUnknownSource) })
	assert.Equal(t, int64(0), h.tally.droppedCount(DropOversized))
}

// A trap from an address two policies name counts once per policy.
func TestReceiver_CountsOncePerClaimingPolicy(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "core")
	h.reg.Register("edge", []Device{{Policy: "edge", Addr: src}}, nil)
	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V2c) })
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "edge", "linkDown", V2c) })
}

// F4: an inform from a registered source is acknowledged, so the device does
// not retransmit and double count. An inform from anyone else is dropped
// before it is parsed and never answered, so the socket does not reflect.
func TestReceiver_AcknowledgesInformsOnlyFromRegisteredSources(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.sender.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	buf := make([]byte, 512)

	h.send(t, v2cInform("public"))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropUnknownSource) })
	_, err := h.sender.Read(buf)
	assert.Error(t, err, "an inform from an unregistered source is never answered")

	src := h.registerSender(t, "core")
	h.send(t, v2cInform("public"))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V2c) })
	require.NoError(t, h.sender.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, err := h.sender.Read(buf)
	require.NoError(t, err, "a registered inform gets its acknowledgement")
	pkt, err := (&gosnmp.GoSNMP{Version: gosnmp.Version2c}).UnmarshalTrap(buf[:n], false)
	require.NoError(t, err)
	assert.Equal(t, gosnmp.GetResponse, pkt.PDUType)
}

func TestReceiver_RejectsANonTrapPDU(t *testing.T) {
	h := newHarness(t)
	h.registerSender(t, "core")
	h.send(t, v2cGet("public"))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropUnsupportedPDU) })
}

// trapUser is the credential the v3 tests register. gosnmp selects security
// parameters by username before it parses, so a v3 packet only reaches the
// parser under a name the registry holds.
var trapUser = V3User{
	Username:       "trapuser",
	AuthProtocol:   "SHA",
	AuthPassphrase: "authpassphrase",
	PrivProtocol:   "NoPriv",
}

// F1, end to end: the engine discovery shape reaches gosnmp's parser and is
// accepted there, and is rejected here.
func TestReceiver_RejectsUnauthenticatedV3(t *testing.T) {
	h := newHarness(t)
	h.registerSender(t, "core", trapUser)
	h.send(t, v3Unauthenticated("trapuser", ""))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropV3Unauthenticated) })
}

// F1's residual, end to end: a username is not a secret, so naming a known
// user with any engine ID and noAuthNoPriv flags satisfies the identity check
// while gosnmp verifies no digest at all. Nothing about that packet was
// authenticated, so it must not be counted as a v3 trap.
func TestReceiver_RejectsV3WithoutTheAuthFlag(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "core", trapUser)
	h.send(t, v3Unauthenticated("trapuser", "\x80\x00\x1f\x88\x80"))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropV3Unauthenticated) })
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "core", "linkDown", V3))
}

// F15, end to end: gosnmp authenticates only a packet whose msgSecurityModel
// is the user security model, and that field is read straight off the wire.
// A sender that names any other model gets the auth bit believed without a
// digest ever being verified, while its security parameters still carry a
// username and engine ID, so every other guard passes.
func TestReceiver_RejectsV3WithANonUSMSecurityModel(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "core", trapUser)
	h.send(t, v3Packet(v3Options{
		username:     "trapuser",
		engineID:     "\x80\x00\x1f\x88\x80",
		secModel:     1,
		flags:        0x01,
		authParamLen: 12,
	}))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropV3Unauthenticated) })
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "core", "linkDown", V3))
}

// F16: gosnmp blanks the authentication parameters in place with an unchecked
// copy(packet[cursor+2:cursor+len(mac)], ...) (v3_usm.go:1059) as soon as the
// auth bit is set and the named user has a real auth protocol. A datagram
// that ends right after the USM parameter block leaves fewer bytes than the
// digest is wide, and the slice expression panics. The receive goroutine is
// the only reader of the socket, so one such datagram from anyone the
// registry knows would take the process down with it.
func TestReceiver_SurvivesAV3DatagramThatPanicsTheParser(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "core", trapUser)
	h.send(t, v3Packet(v3Options{
		username:         "trapuser",
		engineID:         "\x80\x00\x1f\x88\x80",
		secModel:         3,
		flags:            0x01,
		truncateAfterUSM: true,
	}))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropMalformed) })

	// The receiver is still reading, which is the whole point.
	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V2c) })
}

// trapAuthPrivUser is the credential the acceptance test registers. SHA and
// AES, the pair a real authPriv target is configured with.
var trapAuthPrivUser = V3User{
	Username:       "authprivuser",
	AuthProtocol:   "SHA",
	AuthPassphrase: "authpassphrase",
	PrivProtocol:   "AES",
	PrivPassphrase: "privpassphrase",
}

// The load-bearing acceptance path: a v3 trap a policy's own credentials
// authenticate is counted. Every other v3 test here asserts a drop, so
// without this one rebuildUsersIfChanged, the protocol name mapping, gosnmp's
// credential table and the generation rebuild are all unverified against a
// packet that is supposed to be accepted. The packet is marshalled by gosnmp
// itself, digest and encrypted scoped PDU included.
func TestReceiver_AcceptsAnAuthenticatedV3Trap(t *testing.T) {
	const engineID = "\x80\x00\x1f\x88\x80\x41\x42\x43"
	h := newHarness(t)
	src := h.registerSender(t, "core", trapAuthPrivUser)
	h.send(t, v3AuthPrivTrap(t, trapAuthPrivUser, engineID))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V3) })
	assert.Equal(t, int64(0), h.tally.droppedCount(DropV3Unauthenticated))
	assert.Equal(t, int64(0), h.tally.droppedCount(DropMalformed))
}

func TestReceiver_V1TrapIsNormalisedAndCounted(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "core")
	h.send(t, v1Trap("public", [4]byte{0, 0, 0, 0}, 2, 0))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V1) })
}

// F9, narrow phase 1 rule: a v1 agent-addr that is itself registered wins
// over the source address.
func TestReceiver_V1AgentAddrWinsWhenRegistered(t *testing.T) {
	h := newHarness(t)
	h.registerSender(t, "core")
	h.reg.Register("agent", []Device{{Policy: "agent", Addr: netip.MustParseAddr("10.9.9.9")}}, nil)
	h.send(t, v1Trap("public", [4]byte{10, 9, 9, 9}, 2, 0))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount("10.9.9.9", "agent", "linkDown", V1) })
}

// The agent-addr override is a claim about provenance, and an unregistered
// sender has none to make. A stranger naming a known device in a v1 trap is
// dropped as an unknown source before the field is ever read.
func TestReceiver_V1AgentAddrIsIgnoredFromAnUnregisteredSender(t *testing.T) {
	h := newHarness(t)
	h.reg.Register("agent", []Device{{Policy: "agent", Addr: netip.MustParseAddr("10.9.9.9")}}, nil)
	h.send(t, v1Trap("public", [4]byte{10, 9, 9, 9}, 2, 0))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropUnknownSource) })
	assert.Equal(t, int64(0), h.tally.receivedCount("10.9.9.9", "agent", "linkDown", V1))
}

// A datagram no parser can read, from an address a policy does name, is the
// operator's own device sending something wrong, and lands in malformed
// rather than in any of the source-shaped buckets. With the security model
// guard in place this is also where hostile v3 under an unknown username
// ends up, since gosnmp fails the credential lookup before it parses.
func TestReceiver_MalformedFromARegisteredSourceIsCounted(t *testing.T) {
	h := newHarness(t)
	h.registerSender(t, "core")
	h.send(t, []byte{0x30, 0x01, 0xff})
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropMalformed) })
	assert.Equal(t, int64(0), h.tally.droppedCount(DropUnknownSource))
}

func TestReceiver_OversizedDatagramIsDropped(t *testing.T) {
	h := newHarness(t)
	h.registerSender(t, "core")
	h.send(t, make([]byte, maxDatagram+1))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropOversized) })
}

func TestReceiver_StopIsPromptAndIdempotent(t *testing.T) {
	h := newHarness(t)
	start := time.Now()
	h.rcv.Stop()
	h.rcv.Stop()
	assert.Less(t, time.Since(start), time.Second)
}

// RFC 3414 timeliness on the non-authoritative side: a trap whose engine
// boots are lower than last seen, or whose engine time is more than the
// window behind the clock learned for that engine, is a replay and is
// dropped even though its digest verifies. A later time is accepted and
// learned, so a device's own stream is never refused.
func TestReceiver_RejectsAV3TrapOutsideItsEngineTimeWindow(t *testing.T) {
	const engineID = "\x80\x00\x1f\x88\x80\x41\x42\x43"
	h := newHarness(t)
	src := h.registerSender(t, "core", trapAuthPrivUser)
	counted := func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V3) }
	replayed := func() int64 { return h.tally.droppedCount(DropV3NotInTimeWindow) }

	h.send(t, v3AuthPrivTrapAt(t, trapAuthPrivUser, engineID, 5, 1000))
	waitFor(t, 1, counted)
	h.send(t, v3AuthPrivTrapAt(t, trapAuthPrivUser, engineID, 4, 1000))
	waitFor(t, 1, replayed)
	h.send(t, v3AuthPrivTrapAt(t, trapAuthPrivUser, engineID, 5, 700))
	waitFor(t, 2, replayed)
	h.send(t, v3AuthPrivTrapAt(t, trapAuthPrivUser, engineID, 5, 1001))
	waitFor(t, 2, counted)
	h.send(t, v3AuthPrivTrapAt(t, trapAuthPrivUser, engineID, 6, 0))
	waitFor(t, 3, counted)
	assert.Equal(t, int64(2), replayed())
	assert.Equal(t, int64(0), h.tally.droppedCount(DropMalformed))
	assert.Equal(t, int64(0), h.tally.droppedCount(DropV3Unauthenticated))
}

// A malformed v1 or v2c datagram from a registered sender is the operator's
// own device misbehaving, and gosnmp reports such a fault by quoting the bytes
// it could not parse, which begin right after the community. The community is
// the polling credential more often than not, so the log carries the fault's
// category and nothing the packet said. The corruption here is the one the
// poller's own redaction documents: a community length octet larger than the
// packet, which makes the parser dump everything from the community on.
func TestReceiver_MalformedDetailNeverQuotesThePacket(t *testing.T) {
	buf := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := newHarnessWith(t, logger)
	h.registerSender(t, "core")

	const community = "secretcommunity"
	pkt := v2cTrap(community)
	at := bytes.Index(pkt, append([]byte{0x04, byte(len(community))}, community...))
	require.Positive(t, at, "the community octet string is in the packet")
	pkt[at+1] = 0x7f

	h.send(t, pkt)
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropMalformed) })
	out := buf.String()
	assert.Contains(t, out, "reason=malformed")
	assert.NotContains(t, out, community)
	assert.NotContains(t, out, hex.EncodeToString([]byte(community)))
	assert.Contains(t, out, "detail=\"error parsing community string\"")
}

// lockedBuffer is a bytes.Buffer the receive goroutine can write while the
// test reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A registered sender writing a version integer this backend does not speak
// is dropped under its own reason, never counted as 2c.
func TestReceiver_DropsAVersionItDoesNotSpeak(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "core")
	h.send(t, trapWithVersion(2, "public"))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropUnsupportedVersion) })
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "core", "linkDown", V2c))
	assert.Equal(t, int64(0), h.tally.droppedCount(DropMalformed))
}

// gosnmp keys its credential table by username and tries every entry under a
// name in turn, localising keys for each, so the table a trap is parsed with
// holds only the credentials of the devices claimed at its source. A
// credential the same policy assigned to another device is not tried: it
// does not authenticate this source, and the receive goroutine does not pay
// for it. When the registry changes, the table follows it.
func TestReceiver_TriesOnlyTheSourceDevicesCredentials(t *testing.T) {
	const engineID = "\x80\x00\x1f\x88\x80\x41\x42\x43"
	mine := trapAuthPrivUser
	theirs := trapAuthPrivUser
	theirs.AuthPassphrase = "someone-elses-authpass"
	theirs.PrivPassphrase = "someone-elses-privpass"

	h := newHarness(t)
	src := canonical(h.sender.LocalAddr().(*net.UDPAddr).AddrPort().Addr())
	h.reg.Register("core", []Device{
		{Policy: "core", Addr: src, User: &mine},
		{Policy: "core", Addr: netip.MustParseAddr("10.9.9.9"), User: &theirs},
	}, nil)

	h.send(t, v3AuthPrivTrapAt(t, theirs, engineID, 1, 1))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropMalformed) })
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "core", "linkDown", V3), "another device's credential does not authenticate this source")

	h.send(t, v3AuthPrivTrapAt(t, mine, engineID, 1, 2))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V3) })

	h.reg.Register("core", []Device{{Policy: "core", Addr: src, User: &theirs}}, nil)
	h.send(t, v3AuthPrivTrapAt(t, theirs, engineID, 1, 3))
	waitFor(t, 2, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V3) })
	assert.LessOrEqual(t, h.rcv.tableCacheSize(), 1, "the cache was rebuilt for the new registry generation")
}

// The engine clocks are kept per sender as well as per engine ID. A device
// that authenticates with its own credential and writes another device's
// engine ID with higher boots poisons only its own clock; the other device's
// traps under that engine ID are still inside their own window.
func TestReceiver_KeepsEngineClocksPerSender(t *testing.T) {
	const engineID = "\x80\x00\x1f\x88\x80\x41\x42\x43"
	h := newHarnessOn(t, "[::]:0", testLogger)
	first, src1 := h.newSenderOn(t, "udp4", net.IPv4(127, 0, 0, 1))
	other, src2 := h.newSenderOn(t, "udp6", net.IPv6loopback)
	require.NotEqual(t, src1, src2, "the two senders must be two devices to the registry")
	h.reg.Register("core", []Device{{Policy: "core", Addr: src1, User: &trapAuthPrivUser}}, nil)
	h.reg.Register("edge", []Device{{Policy: "edge", Addr: src2, User: &trapAuthPrivUser}}, nil)

	_, err := first.Write(v3AuthPrivTrapAt(t, trapAuthPrivUser, engineID, 9, 1))
	require.NoError(t, err)
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src1.String(), "core", "linkDown", V3) })

	_, err = other.Write(v3AuthPrivTrapAt(t, trapAuthPrivUser, engineID, 5, 1))
	require.NoError(t, err)
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src2.String(), "edge", "linkDown", V3) })
	assert.Equal(t, int64(0), h.tally.droppedCount(DropV3NotInTimeWindow), "boots 5 after boots 9 is only a replay for the same sender")
}

// Each policy names a trap from its own profile set, so two policies on one
// socket count the same trap under their own names, and a policy with no
// names of its own falls back to the socket's. The RFC 1215 names take
// precedence over any profile's spelling.
func TestReceiver_NamesATrapWithThePolicysOwnNames(t *testing.T) {
	h := newHarness(t)
	src := canonical(h.sender.LocalAddr().(*net.UDPAddr).AddrPort().Addr())
	h.reg.Register("vendor", []Device{{Policy: "vendor", Addr: src}}, map[string]string{
		"1.3.6.1.4.1.9.9.999.0.1": "widgetFailed",
		"1.3.6.1.6.3.1.1.5.3":     "vendorLinkDown",
	})
	h.reg.Register("plain", []Device{{Policy: "plain", Addr: src}}, nil)

	h.send(t, v2cTrapWithOID("public", oidEnterpriseWidget))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "vendor", "widgetFailed", V2c) })
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "plain", OtherName, V2c) })

	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "vendor", "linkDown", V2c) })
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "plain", "linkDown", V2c) })
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "vendor", "vendorLinkDown", V2c), "RFC 1215 wins over the profile's spelling")
}

// Two policies claiming one device with different credentials share a
// credential table, since gosnmp is handed every user at the address, but a
// v3 trap is counted only under the policies holding the credential that
// verified it. A policy naming the device with no v3 user, or with another
// credential, counts its v1 and v2c traps and not its authenticated v3 ones.
func TestReceiver_CountsAV3TrapOnlyForThePoliciesHoldingItsCredential(t *testing.T) {
	const engineID = "\x80\x00\x1f\x88\x80\x41\x42\x43"
	mine := trapAuthPrivUser
	theirs := trapAuthPrivUser
	theirs.AuthPassphrase = "someone-elses-authpass"
	theirs.PrivPassphrase = "someone-elses-privpass"

	h := newHarness(t)
	src := canonical(h.sender.LocalAddr().(*net.UDPAddr).AddrPort().Addr())
	h.reg.Register("core", []Device{{Policy: "core", Addr: src, User: &mine}}, nil)
	h.reg.Register("edge", []Device{{Policy: "edge", Addr: src, User: &theirs}}, nil)
	h.reg.Register("plain", []Device{{Policy: "plain", Addr: src}}, nil)
	count := func(policy string, v Version) int64 {
		return h.tally.receivedCount(src.String(), policy, "linkDown", v)
	}

	h.send(t, v3AuthPrivTrapAt(t, mine, engineID, 1, 1))
	waitFor(t, 1, func() int64 { return count("core", V3) })
	h.send(t, v3AuthPrivTrapAt(t, theirs, engineID, 1, 2))
	waitFor(t, 1, func() int64 { return count("edge", V3) })
	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return count("plain", V2c) })

	assert.Equal(t, int64(1), count("core", V3), "core saw only the trap its credential verified")
	assert.Equal(t, int64(1), count("edge", V3), "edge likewise")
	assert.Equal(t, int64(0), count("plain", V3), "a policy without the credential counts no authenticated v3 trap")
	assert.Equal(t, int64(1), count("core", V2c), "but every claim counts the v2c one")
	assert.Equal(t, int64(1), count("edge", V2c))
	assert.Equal(t, int64(0), h.tally.droppedCount(DropMalformed))
}

// The policies a trap is counted under are resolved when it is counted, not
// when it was read, and the count happens in the same critical section as
// the resolution. A policy released before the count, and replaced by one
// that does not claim the device, gets nothing and the datagram is an
// unknown source. A release that races the count cannot slip between the
// two: it waits for the count, which lands under the old policy and is then
// withdrawn with it, so the replacement never inherits a trap for a device it
// does not claim.
func TestReceiver_ResolvesAndCountsTheClaimsAtomically(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "core")
	h.rcv.setBeforeCount(func() {
		h.reg.Withdraw("core")
		h.reg.Register("next", []Device{{Policy: "next", Addr: netip.MustParseAddr("10.9.9.9")}}, nil)
	})
	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropUnknownSource) })
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "core", "linkDown", V2c), "the released policy is not counted")
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "next", "linkDown", V2c), "nor a replacement that does not claim the device")
	h.rcv.setBeforeCount(nil)

	// Now the race: the replacement under the same name is released and
	// recreated, claiming another device, while the claims are held for
	// counting. It has to wait, so the count lands under the outgoing
	// incarnation and its withdrawal takes the count with it.
	h.registerSender(t, "core")
	h.tally.Activate("core")
	replaced := make(chan struct{})
	h.rcv.setDuringCount(func() {
		go func() {
			defer close(replaced)
			h.reg.Withdraw("core")
			h.tally.Withdraw("core")
			h.reg.Register("core", []Device{{Policy: "core", Addr: netip.MustParseAddr("10.9.9.9")}}, nil)
			h.tally.Activate("core")
		}()
		time.Sleep(50 * time.Millisecond)
	})
	h.send(t, v2cTrap("public"))
	<-replaced
	waitFor(t, 1, func() int64 { return h.tally.datagramCount() - 1 })
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "core", "linkDown", V2c), "the count went to the outgoing incarnation and left with it")
	assert.Equal(t, int64(1), h.tally.retainedCount(src.String(), "core", "linkDown", V2c), "kept as a dormant total, not exported")
}

// An authNoPriv trap carries a digest and no encryption. One signed with a
// wrong passphrase, that is a forged digest under a known username from a
// registered source, must be rejected the same way an authPriv one is: the
// receiver always installs a credential table, and gosnmp's table path
// verifies the digest against the packet's own flags, not the receiver's.
func TestReceiver_RejectsAForgedDigestOnAnAuthNoPrivTrap(t *testing.T) {
	const engineID = "\x80\x00\x1f\x88\x80\x41\x42\x43"
	h := newHarness(t)
	src := h.registerSender(t, "core", trapAuthPrivUser)

	forged := trapAuthPrivUser
	forged.AuthPassphrase = "not-the-passphrase"
	h.send(t, v3AuthNoPrivTrap(t, forged, engineID))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropMalformed) })
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "core", "linkDown", V3), "a forged digest authenticates nothing")

	h.send(t, v3AuthNoPrivTrap(t, trapAuthPrivUser, engineID))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V3) })
	assert.Equal(t, int64(1), h.tally.droppedCount(DropMalformed), "the genuine authNoPriv trap is counted")
}

// fillSeries takes the tally to one slot short of its limit: every real
// series slot, and the overflow reserve but one, each reserve slot holding a
// filler policy's overflow series.
func fillSeries(t *testing.T, tally *Tally) {
	t.Helper()
	for i := range seriesLimit {
		tally.Received(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "filler", "linkDown", V2c)
	}
	for i := range maxSeries - seriesLimit - 1 {
		tally.Received("198.51.100.1", fmt.Sprintf("filler%d", i), "linkUp", V2c)
	}
	require.Equal(t, maxSeries-1, tally.seriesCount())
}

// series_limit is a datagram outcome, recorded once and only when no policy
// could count the trap. A datagram that one claiming policy counts and
// another cannot is not a drop, and one that no policy can count is one
// drop however many policies claimed it.
func TestReceiver_RecordsSeriesLimitOncePerUncountedDatagram(t *testing.T) {
	h := newHarness(t)
	src := canonical(h.sender.LocalAddr().(*net.UDPAddr).AddrPort().Addr())
	fillSeries(t, h.tally)
	// "room" already has an overflow series; "full" and "fuller" have none
	// and cannot get one.
	h.tally.Received("203.0.113.1", "room", "warmStart", V2c)
	require.Equal(t, int64(1), h.tally.receivedCount(OtherName, "room", OtherName, V2c))
	require.Equal(t, maxSeries, h.tally.seriesCount(), "room took the last slot")
	h.reg.Register("room", []Device{{Policy: "room", Addr: src}}, nil)
	h.reg.Register("full", []Device{{Policy: "full", Addr: src}}, nil)
	h.reg.Register("fuller", []Device{{Policy: "fuller", Addr: src}}, nil)

	h.send(t, v2cTrap("public"))
	waitFor(t, 2, func() int64 { return h.tally.receivedCount(OtherName, "room", OtherName, V2c) })
	assert.Equal(t, int64(0), h.tally.droppedCount(DropSeriesLimit), "a datagram one policy counted is not a drop")

	// Take room's claim off the sender, keeping its series live so nothing
	// dormant can be evicted to make room for the others.
	h.reg.Register("room", []Device{{Policy: "room", Addr: netip.MustParseAddr("10.9.9.9")}}, nil)
	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropSeriesLimit) })
	assert.Equal(t, int64(1), h.tally.droppedCount(DropSeriesLimit), "one drop for the datagram, not one per policy")
	assert.Equal(t, int64(2), h.tally.datagramCount())
}

// Once the receiver is closed, nothing it was still doing reaches the tally:
// a datagram whose parse outlasted the stop bound is discarded rather than
// counted after the final export has run.
func TestReceiver_CountsNothingAfterItIsClosed(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "core")
	release := make(chan struct{})
	entered := make(chan struct{})
	h.rcv.setBeforeCount(func() {
		close(entered)
		<-release
	})
	h.send(t, v2cTrap("public"))
	<-entered
	h.rcv.Stop()
	close(release)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int64(0), h.tally.datagramCount(), "a datagram is counted with its outcome, and this one had none before the stop")
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "core", "linkDown", V2c), "not counted after it")
	assert.Equal(t, int64(0), h.tally.droppedCount(DropUnknownSource))
}

// The datagram counter is recorded together with the datagram's outcome, a
// drop or a count, so the two sides of the accounting never disagree, not
// even in a final export taken while a datagram is in flight.
func TestReceiver_CountsADatagramWithItsOutcome(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "core")
	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V2c) })
	assert.Equal(t, int64(1), h.tally.datagramCount())
	h.send(t, []byte{0x30, 0x01, 0xff})
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropMalformed) })
	assert.Equal(t, int64(2), h.tally.datagramCount())
}

// A v2 trap PDU under wire version 1 is not a v1 trap: it is dropped as an
// unsupported PDU, never counted as a coldStart under version 1.
func TestReceiver_DropsAV2TrapPDUUnderVersion1(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "core")
	h.send(t, trapWithVersion(0, "public"))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropUnsupportedPDU) })
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "core", "coldStart", V1))
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "core", "linkDown", V1))
}

// A parsed and attributed inform is acknowledged whether or not a series
// could be allocated for it: the series limit is the tally's problem, not
// the device's, and an unacknowledged inform is retransmitted.
func TestReceiver_AcknowledgesAnInformTheSeriesLimitRefused(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "full")
	fillSeries(t, h.tally)
	h.tally.Received("203.0.113.1", "taker", "warmStart", V2c)
	require.Equal(t, maxSeries, h.tally.seriesCount())
	require.NoError(t, h.sender.SetReadDeadline(time.Now().Add(2*time.Second)))

	h.send(t, v2cInform("public"))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropSeriesLimit) })
	buf := make([]byte, 512)
	n, err := h.sender.Read(buf)
	require.NoError(t, err, "the inform is acknowledged although it was not counted")
	pkt, err := (&gosnmp.GoSNMP{Version: gosnmp.Version2c}).UnmarshalTrap(buf[:n], false)
	require.NoError(t, err)
	assert.Equal(t, gosnmp.GetResponse, pkt.PDUType)
	assert.Equal(t, int64(0), h.tally.receivedCount(src.String(), "full", "linkDown", V2c))
}

// A datagram's terminal drop after the claims visit, series_limit here, is
// recorded in the same intake section as the datagram itself. A close that
// arrives while that section runs waits for it, so the final export never
// holds a datagram without an outcome.
func TestReceiver_RecordsAPostClaimDropWithItsDatagram(t *testing.T) {
	h := newHarness(t)
	h.registerSender(t, "full")
	fillSeries(t, h.tally)
	h.tally.Received("203.0.113.1", "taker", "warmStart", V2c)
	require.Equal(t, maxSeries, h.tally.seriesCount())

	stopped := make(chan struct{})
	h.rcv.setDuringCount(func() {
		go func() {
			defer close(stopped)
			h.rcv.Stop()
		}()
		time.Sleep(50 * time.Millisecond)
	})
	h.send(t, v2cTrap("public"))
	<-stopped
	assert.Equal(t, int64(1), h.tally.datagramCount())
	assert.Equal(t, int64(1), h.tally.droppedCount(DropSeriesLimit), "the outcome landed with the datagram, ahead of the close")
}

// The engine clocks are kept per credential as well as per sender and engine
// ID. Two credentials at one address are two principals: a device holding
// one, writing the other's engine ID with higher boots, poisons only the
// clock its own credential is judged by, and the other principal's traps
// under that engine ID are still inside their own window.
func TestReceiver_KeepsEngineClocksPerCredential(t *testing.T) {
	const engineID = "\x80\x00\x1f\x88\x80\x41\x42\x43"
	mine := trapAuthPrivUser
	theirs := trapAuthPrivUser
	theirs.AuthPassphrase = "someone-elses-authpass"
	theirs.PrivPassphrase = "someone-elses-privpass"

	h := newHarness(t)
	src := canonical(h.sender.LocalAddr().(*net.UDPAddr).AddrPort().Addr())
	h.reg.Register("core", []Device{{Policy: "core", Addr: src, User: &mine}}, nil)
	h.reg.Register("edge", []Device{{Policy: "edge", Addr: src, User: &theirs}}, nil)

	h.send(t, v3AuthPrivTrapAt(t, mine, engineID, 9, 1))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V3) })
	h.send(t, v3AuthPrivTrapAt(t, theirs, engineID, 5, 1))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "edge", "linkDown", V3) })
	assert.Equal(t, int64(0), h.tally.droppedCount(DropV3NotInTimeWindow), "boots 5 after boots 9 is only a replay for the same credential")
	h.send(t, v3AuthPrivTrapAt(t, mine, engineID, 8, 1))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropV3NotInTimeWindow) })
	assert.Equal(t, int64(1), h.tally.receivedCount(src.String(), "core", "linkDown", V3), "and for the same credential it still is one")
}

// The clock key and the credential-table cache key are both built from
// operator-chosen strings, so neither may be a delimiter join: a username
// containing the delimiter could make two principals one clock, or two user
// sets one table. Both are injective: the clock key is a struct, the cache
// key length-prefixes every field.
func TestReceiver_CredentialKeysAreInjective(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.5")
	a := &gosnmp.UsmSecurityParameters{UserName: "u|x", AuthenticationPassphrase: "password", AuthenticationProtocol: gosnmp.SHA, PrivacyProtocol: gosnmp.AES, AuthoritativeEngineID: "e"}
	b := &gosnmp.UsmSecurityParameters{UserName: "u", AuthenticationPassphrase: "x|password", AuthenticationProtocol: gosnmp.SHA, PrivacyProtocol: gosnmp.AES, AuthoritativeEngineID: "e"}
	assert.NotEqual(t, clockKey(src, a), clockKey(src, b), "a delimiter in a username is not a field boundary")
	authOnly := &gosnmp.UsmSecurityParameters{UserName: "u", AuthenticationPassphrase: "other", AuthenticationProtocol: gosnmp.SHA, PrivacyProtocol: gosnmp.AES, AuthoritativeEngineID: "e"}
	assert.NotEqual(t, clockKey(src, b), clockKey(src, authOnly), "the auth passphrase is part of the identity")
	privOnly := &gosnmp.UsmSecurityParameters{UserName: "u", AuthenticationPassphrase: "x|password", PrivacyPassphrase: "other", AuthenticationProtocol: gosnmp.SHA, PrivacyProtocol: gosnmp.AES, AuthoritativeEngineID: "e"}
	assert.NotEqual(t, clockKey(src, b), clockKey(src, privOnly), "so is the priv passphrase")
	assert.Equal(t, clockKey(src, b), clockKey(src, b))

	ua := []V3User{{Username: "u\x00x", AuthProtocol: "SHA", AuthPassphrase: "p"}}
	ub := []V3User{{Username: "u", AuthProtocol: "x\x00SHA", AuthPassphrase: "p"}}
	assert.NotEqual(t, userSetKey(ua), userSetKey(ub), "a NUL in a field is not a field boundary")
	assert.NotEqual(t, userSetKey([]V3User{{Username: "ab", AuthPassphrase: "c"}}), userSetKey([]V3User{{Username: "a", AuthPassphrase: "bc"}}))
	assert.Equal(t, userSetKey(ua), userSetKey(ua))
}

// The receiver accounts a datagram and its outcome in one tally transaction,
// so a periodic export taken while the claims are being visited sees the
// datagram together with its count, never the datagram alone.
func TestReceiver_AccountsADatagramAndItsCountUnderOneTallyLock(t *testing.T) {
	h := newHarness(t)
	src := h.registerSender(t, "core")
	seen := make(chan [2]int64, 1)
	h.rcv.setDuringCount(func() {
		go func() {
			seen <- [2]int64{h.tally.datagramCount(), h.tally.receivedCount(src.String(), "core", "linkDown", V2c)}
		}()
		time.Sleep(50 * time.Millisecond)
	})
	h.send(t, v2cTrap("public"))
	assert.Equal(t, [2]int64{1, 1}, <-seen, "the export waited for the outcome")
}
