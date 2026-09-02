package traps

import (
	"net"
	"net/netip"
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

func newHarness(t *testing.T, acceptUnknown bool) *harness {
	t.Helper()
	reg := NewRegistry()
	tally := NewTally(testLogger)
	rcv, err := Listen("127.0.0.1:0", reg, tally, BuildNames(nil), acceptUnknown, testLogger)
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
	h.reg.Register(policy, []Device{{Policy: policy, Addr: local}}, users)
	return canonical(local)
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
	h := newHarness(t, false)
	src := h.registerSender(t, "core")
	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V2c) })
	assert.Equal(t, int64(1), h.tally.datagramCount())
}

// The source check runs before any parsing, so an unknown sender costs a map
// lookup and nothing else (F5), and is counted as dropped.
func TestReceiver_DropsAnUnknownSourceBeforeParsing(t *testing.T) {
	h := newHarness(t, false)
	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropUnknownSource) })
	assert.Equal(t, int64(0), h.tally.receivedCount("127.0.0.1", "", "linkDown", V2c))

	// A datagram no parser could read still drops on the source, which is only
	// true if the source check runs ahead of the parse.
	h.send(t, []byte{0x30, 0x01, 0xff})
	waitFor(t, 2, func() int64 { return h.tally.droppedCount(DropUnknownSource) })
	assert.Equal(t, int64(0), h.tally.droppedCount(DropMalformed))
}

func TestReceiver_AcceptUnknownLabelsBySourceAddressWithNoPolicy(t *testing.T) {
	h := newHarness(t, true)
	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount("127.0.0.1", "", "linkDown", V2c) })
}

// A trap from an address two policies name counts once per policy.
func TestReceiver_CountsOncePerClaimingPolicy(t *testing.T) {
	h := newHarness(t, false)
	src := h.registerSender(t, "core")
	h.reg.Register("edge", []Device{{Policy: "edge", Addr: src}}, nil)
	h.send(t, v2cTrap("public"))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V2c) })
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "edge", "linkDown", V2c) })
}

// F4: an inform from a registered source is acknowledged, so the device does
// not retransmit and double count. An inform from anyone else never is, so
// the socket does not reflect.
func TestReceiver_AcknowledgesInformsOnlyFromRegisteredSources(t *testing.T) {
	h := newHarness(t, true)
	require.NoError(t, h.sender.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	buf := make([]byte, 512)

	h.send(t, v2cInform("public"))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount("127.0.0.1", "", "linkDown", V2c) })
	_, err := h.sender.Read(buf)
	assert.Error(t, err, "an accepted-unknown inform is counted but never answered")

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
	h := newHarness(t, false)
	h.registerSender(t, "core")
	h.send(t, v2cGet("public"))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropUnsupportedPDU) })
}

// F1, end to end: the engine discovery shape reaches gosnmp's parser and is
// accepted there, and is rejected here.
func TestReceiver_RejectsUnauthenticatedV3(t *testing.T) {
	h := newHarness(t, false)
	h.registerSender(t, "core", V3User{
		Username:       "trapuser",
		AuthProtocol:   "SHA",
		AuthPassphrase: "authpassphrase",
		PrivProtocol:   "NoPriv",
	})
	h.send(t, v3Unauthenticated("trapuser"))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropV3Unauthenticated) })
}

func TestReceiver_V1TrapIsNormalisedAndCounted(t *testing.T) {
	h := newHarness(t, false)
	src := h.registerSender(t, "core")
	h.send(t, v1Trap("public", [4]byte{0, 0, 0, 0}, 2, 0))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount(src.String(), "core", "linkDown", V1) })
}

// F9, narrow phase 1 rule: a v1 agent-addr that is itself registered wins
// over the source address.
func TestReceiver_V1AgentAddrWinsWhenRegistered(t *testing.T) {
	h := newHarness(t, false)
	h.registerSender(t, "core")
	h.reg.Register("agent", []Device{{Policy: "agent", Addr: netip.MustParseAddr("10.9.9.9")}}, nil)
	h.send(t, v1Trap("public", [4]byte{10, 9, 9, 9}, 2, 0))
	waitFor(t, 1, func() int64 { return h.tally.receivedCount("10.9.9.9", "agent", "linkDown", V1) })
}

func TestReceiver_OversizedDatagramIsDropped(t *testing.T) {
	h := newHarness(t, false)
	h.registerSender(t, "core")
	h.send(t, make([]byte, maxDatagram+1))
	waitFor(t, 1, func() int64 { return h.tally.droppedCount(DropOversized) })
}

func TestReceiver_StopIsPromptAndIdempotent(t *testing.T) {
	h := newHarness(t, false)
	start := time.Now()
	h.rcv.Stop()
	h.rcv.Stop()
	assert.Less(t, time.Since(start), time.Second)
}
