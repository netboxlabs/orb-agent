package traps

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// senderAddr is the address a loopback sender will have, without sending.
func senderAddr(t *testing.T, addr netip.AddrPort) (netip.Addr, *net.UDPConn) {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(addr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return canonical(conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr()), conn
}

func TestPool_FirstAcquireBindsAndCountsATrapForThePolicy(t *testing.T) {
	tally := NewTally(testLogger)
	p := NewPool(tally, BuildNames(nil), testLogger)
	t.Cleanup(p.Close)

	lease, err := p.Acquire("127.0.0.1:0", "core", nil, nil)
	require.NoError(t, err)
	t.Cleanup(lease.Release)
	require.Equal(t, 1, p.size())
	addr, ok := p.addr("127.0.0.1:0")
	require.True(t, ok)

	src, conn := senderAddr(t, addr)
	// Register the sender's address under the policy so the trap is known.
	require.True(t, p.register("127.0.0.1:0", "core", []Device{{Policy: "core", Addr: src}}, nil))
	_, err = conn.Write(v2cTrap("public"))
	require.NoError(t, err)
	waitFor(t, 1, func() int64 { return tally.receivedCount(src.String(), "core", "linkDown", V2c) })
}

func TestPool_SameStringSharesOneSocket(t *testing.T) {
	p := NewPool(NewTally(testLogger), BuildNames(nil), testLogger)
	t.Cleanup(p.Close)

	a, err := p.Acquire("127.0.0.1:0", "core", nil, nil)
	require.NoError(t, err)
	addrA, _ := p.addr("127.0.0.1:0")
	b, err := p.Acquire("127.0.0.1:0", "edge", nil, nil)
	require.NoError(t, err)
	addrB, _ := p.addr("127.0.0.1:0")

	assert.Equal(t, 1, p.size(), "one entry for one string")
	assert.Equal(t, addrA, addrB, "the second acquire bound nothing")
	assert.Equal(t, 2, p.refs("127.0.0.1:0"))

	a.Release()
	assert.Equal(t, 1, p.size(), "the socket stays up for the other holder")
	assert.Equal(t, 1, p.refs("127.0.0.1:0"))
	b.Release()
	assert.Equal(t, 0, p.size(), "the last release closes it")
}

func TestPool_ReleaseWithdrawsThePolicyFromRegistryAndTally(t *testing.T) {
	tally := NewTally(testLogger)
	p := NewPool(tally, BuildNames(nil), testLogger)
	t.Cleanup(p.Close)

	core, err := p.Acquire("127.0.0.1:0", "core", []Device{{Policy: "core", Addr: netip.MustParseAddr("10.0.0.5")}}, nil)
	require.NoError(t, err)
	edge, err := p.Acquire("127.0.0.1:0", "edge", []Device{{Policy: "edge", Addr: netip.MustParseAddr("10.0.0.6")}}, nil)
	require.NoError(t, err)
	t.Cleanup(edge.Release)
	tally.Received("10.0.0.5", "core", "linkDown", V2c)
	tally.Received("10.0.0.6", "edge", "linkDown", V2c)

	core.Release()
	assert.Equal(t, int64(0), tally.receivedCount("10.0.0.5", "core", "linkDown", V2c), "the released policy's series are gone")
	assert.Equal(t, int64(1), tally.receivedCount("10.0.0.6", "edge", "linkDown", V2c), "the other policy's are kept")
	assert.Empty(t, p.lookup("127.0.0.1:0", netip.MustParseAddr("10.0.0.5")), "the released policy's address is unknown")
	assert.Equal(t, []string{"edge"}, p.lookup("127.0.0.1:0", netip.MustParseAddr("10.0.0.6")))
}

func TestPool_CollisionFailsTheSecondAndKeepsTheFirst(t *testing.T) {
	blocker, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = blocker.Close() })
	taken := blocker.LocalAddr().String()

	p := NewPool(NewTally(testLogger), BuildNames(nil), testLogger)
	t.Cleanup(p.Close)
	first, err := p.Acquire("127.0.0.1:0", "core", nil, nil)
	require.NoError(t, err)
	t.Cleanup(first.Release)

	_, err = p.Acquire(taken, "edge", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binding trap socket "+taken)
	assert.Equal(t, 1, p.size(), "the failed acquire left no entry")
	assert.Equal(t, 1, p.refs("127.0.0.1:0"), "and touched no other")
}

func TestPool_LastReleaseClosesAndAcquireBindsAgain(t *testing.T) {
	p := NewPool(NewTally(testLogger), BuildNames(nil), testLogger)
	t.Cleanup(p.Close)

	lease, err := p.Acquire("127.0.0.1:0", "core", nil, nil)
	require.NoError(t, err)
	before, _ := p.addr("127.0.0.1:0")
	lease.Release()
	lease.Release() // idempotent
	require.Equal(t, 0, p.size())

	again, err := p.Acquire("127.0.0.1:0", "core", nil, nil)
	require.NoError(t, err)
	t.Cleanup(again.Release)
	after, ok := p.addr("127.0.0.1:0")
	require.True(t, ok)
	// Port 0 is kernel-chosen, so a different port proves a fresh bind. Equal
	// ports are possible but rare; the size assertion above is the load-bearing one.
	t.Logf("before %s after %s", before, after)
	assert.Equal(t, 1, p.refs("127.0.0.1:0"))
}

func TestPool_CloseStopsEverythingAndLaterReleaseIsHarmless(t *testing.T) {
	p := NewPool(NewTally(testLogger), BuildNames(nil), testLogger)
	a, err := p.Acquire("127.0.0.1:0", "core", nil, nil)
	require.NoError(t, err)
	b, err := p.Acquire("[::1]:0", "edge", nil, nil)
	require.NoError(t, err)
	require.Equal(t, 2, p.size())

	p.Close()
	assert.Equal(t, 0, p.size())
	assert.NotPanics(t, a.Release)
	assert.NotPanics(t, b.Release)
	assert.NotPanics(t, p.Close)
}
