package traps

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	p := NewPool(tally, testLogger)
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
	p := NewPool(NewTally(testLogger), testLogger)
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
	p := NewPool(tally, testLogger)
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

	p := NewPool(NewTally(testLogger), testLogger)
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
	p := NewPool(NewTally(testLogger), testLogger)
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
	p := NewPool(NewTally(testLogger), testLogger)
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

// A lease whose entry was replaced under it must not touch the replacement.
// Releasing it decrements nothing and closes nothing: the socket it names now
// belongs to another policy.
func TestPool_StaleLeaseDoesNotTouchAFreshEntry(t *testing.T) {
	tally := NewTally(testLogger)
	p := NewPool(tally, testLogger)
	t.Cleanup(p.Close)

	stale, err := p.Acquire("127.0.0.1:0", "core", nil, nil)
	require.NoError(t, err)
	p.Close()
	// Close refuses every later Acquire, which is what keeps this sequence out
	// of the running agent. The flag is cleared here to reach the case the
	// flag does not cover: an entry replaced under a lease still naming the
	// old one.
	p.mu.Lock()
	p.closed = false
	p.mu.Unlock()

	fresh, err := p.Acquire("127.0.0.1:0", "edge", nil, nil)
	require.NoError(t, err)
	t.Cleanup(fresh.Release)
	addr, ok := p.addr("127.0.0.1:0")
	require.True(t, ok)

	stale.Release()

	assert.Equal(t, 1, p.size(), "the fresh entry is still in the pool")
	assert.Equal(t, 1, p.refs("127.0.0.1:0"), "with the holder it counted for itself")
	src, conn := senderAddr(t, addr)
	require.True(t, p.register("127.0.0.1:0", "edge", []Device{{Policy: "edge", Addr: src}}, nil))
	_, err = conn.Write(v2cTrap("public"))
	require.NoError(t, err)
	waitFor(t, 1, func() int64 { return tally.receivedCount(src.String(), "edge", "linkDown", V2c) })
}

// Acquiring after Close binds nothing. The socket would have no one left to
// stop it, since Close is what stops them and it has already run.
func TestPool_AcquireAfterCloseFails(t *testing.T) {
	p := NewPool(NewTally(testLogger), testLogger)
	p.Close()

	lease, err := p.Acquire("127.0.0.1:0", "core", nil, nil)
	require.Error(t, err)
	assert.Nil(t, lease)
	assert.Contains(t, err.Error(), "trap pool is closed")
	assert.Equal(t, 0, p.size(), "and left no entry behind")
}

// The last release closes the socket under the pool lock, so a policy
// acquiring the same string cannot find the address still in use. Closing
// after the unlock leaves a window where the entry is gone but the socket is
// open, and a bind in that window fails.
func TestPool_ReacquireAfterLastReleaseNeverSeesAddressInUse(t *testing.T) {
	// A port the kernel just handed out and nothing holds, so the loop below
	// binds a fixed string rather than a fresh one each time.
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	listen := probe.LocalAddr().String()
	require.NoError(t, probe.Close())

	p := NewPool(NewTally(testLogger), testLogger)
	t.Cleanup(p.Close)
	for i := range 50 {
		lease, err := p.Acquire(listen, "core", nil, nil)
		require.NoErrorf(t, err, "acquire %d of %s", i, listen)
		lease.Release()
	}
	final, err := p.Acquire(listen, "core", nil, nil)
	require.NoError(t, err)
	t.Cleanup(final.Release)
	assert.Equal(t, 1, p.refs(listen))
}

// The same guarantee under contention, which is where the window was
// reachable: four goroutines taking and dropping the last lease on one string
// see the socket closed before the entry can be replaced, so no bind of it
// ever finds the address in use.
func TestPool_ConcurrentReacquireNeverSeesAddressInUse(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	listen := probe.LocalAddr().String()
	require.NoError(t, probe.Close())

	p := NewPool(NewTally(testLogger), testLogger)
	t.Cleanup(p.Close)
	var failures atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				lease, err := p.Acquire(listen, "core", nil, nil)
				if err != nil {
					failures.Add(1)
					continue
				}
				lease.Release()
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(0), failures.Load(), "a bind failed while another holder's socket was still closing")
}

// Each entry has its own registry, which is what keeps a policy on one socket
// from attributing traps that arrived on another. An address registered only
// on the second socket's entry is unknown to the first, so a trap from it is
// dropped there rather than counted for the policy that named it elsewhere.
//
// The second address is the IPv6 loopback rather than another 127/8 address,
// because macOS has only 127.0.0.1 on lo0 and a bind of 127.0.0.2 fails.
func TestPool_SocketsAreIsolated(t *testing.T) {
	tally := NewTally(testLogger)
	p := NewPool(tally, testLogger)
	t.Cleanup(p.Close)

	core, err := p.Acquire("127.0.0.1:0", "core", nil, nil)
	require.NoError(t, err)
	t.Cleanup(core.Release)
	edge, err := p.Acquire("[::1]:0", "edge", nil, nil)
	require.NoError(t, err)
	t.Cleanup(edge.Release)

	coreAddr, ok := p.addr("127.0.0.1:0")
	require.True(t, ok)
	src, conn := senderAddr(t, coreAddr)
	require.True(t, p.register("[::1]:0", "edge", []Device{{Policy: "edge", Addr: src}}, nil))
	require.Empty(t, p.lookup("127.0.0.1:0", src), "the other socket's entry never learned the address")

	_, err = conn.Write(v2cTrap("public"))
	require.NoError(t, err)
	waitFor(t, 1, func() int64 { return tally.droppedCount(DropUnknownSource) })
	assert.Equal(t, int64(0), tally.receivedCount(src.String(), "edge", "linkDown", V2c),
		"a trap on one socket is never attributed to a policy registered on another")
}

// Acquiring a policy activates its series in the tally, so a count that
// arrived after the previous lease's release, and went dormant, resumes when
// the policy comes back.
func TestPool_ReacquireActivatesThePolicysSeries(t *testing.T) {
	tally := NewTally(testLogger)
	p := NewPool(tally, testLogger)
	t.Cleanup(p.Close)
	lease, err := p.Acquire("127.0.0.1:0", "core", nil, nil)
	require.NoError(t, err)
	tally.Received("10.0.0.5", "core", "linkDown", V2c)
	lease.Release()
	tally.Received("10.0.0.5", "core", "linkDown", V2c)
	assert.Equal(t, int64(0), tally.receivedCount("10.0.0.5", "core", "linkDown", V2c), "dormant after release")

	again, err := p.Acquire("127.0.0.1:0", "core", nil, nil)
	require.NoError(t, err)
	t.Cleanup(again.Release)
	tally.Received("10.0.0.5", "core", "linkDown", V2c)
	assert.Equal(t, int64(3), tally.receivedCount("10.0.0.5", "core", "linkDown", V2c), "live again with every count kept")
}

// Close waits for every receiver under one shared deadline, not one bound
// per receiver in turn, so however many sockets a process holds, shutdown
// spends at most the stop bound before the final flush.
func TestPool_CloseWaitsUnderOneSharedDeadline(t *testing.T) {
	p := NewPool(NewTally(testLogger), testLogger)
	const sockets = 5
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	for i := range sockets {
		// A distinct free port per socket, so each is its own entry.
		probe, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		listen := probe.LocalAddr().String()
		require.NoError(t, probe.Close())
		lease, err := p.Acquire(listen, fmt.Sprintf("p%d", i), nil, nil)
		require.NoError(t, err)
		t.Cleanup(lease.Release)
		addr, ok := p.addr(listen)
		require.True(t, ok)
		// Park each receiver's goroutine after a parse, so none can exit
		// within the bound.
		entered := make(chan struct{})
		rcv := p.receiver(listen)
		rcv.setBeforeCount(func() { close(entered); <-release })
		src, conn := senderAddr(t, addr)
		require.True(t, p.register(listen, fmt.Sprintf("p%d", i), []Device{{Policy: fmt.Sprintf("p%d", i), Addr: src}}, nil))
		_, err = conn.Write(v2cTrap("public"))
		require.NoError(t, err)
		<-entered
	}

	started := time.Now()
	p.Close()
	elapsed := time.Since(started)
	assert.Less(t, elapsed, 2*stopTimeout, "five stalled receivers cost one bound, not five")
	assert.GreaterOrEqual(t, elapsed, stopTimeout, "and the bound was actually waited")
}

// Close closes every receiver concurrently, so the time it spends waiting
// on receivers busy inside an intake section is the slowest one's, not the
// sum: fifty busy sockets must not spend the agent's grace period.
func TestPool_ClosesReceiversConcurrently(t *testing.T) {
	tally := NewTally(testLogger)
	p := NewPool(tally, testLogger)
	const sockets = 5
	const park = 200 * time.Millisecond
	listens := make([]string, sockets)
	for i := range sockets {
		listens[i] = fmt.Sprintf("127.0.0.1:0#%d", i)
	}
	// Each socket needs its own listen string to be its own entry; the
	// kernel-chosen port makes "127.0.0.1:0" the same entry every time, so
	// the entries are bound one at a time on real ports.
	for i := range sockets {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		listens[i] = conn.LocalAddr().String()
		_ = conn.Close()
		lease, err := p.Acquire(listens[i], fmt.Sprintf("p%d", i), nil, nil)
		require.NoError(t, err)
		t.Cleanup(lease.Release)
		addr, ok := p.addr(listens[i])
		require.True(t, ok)
		src, sender := senderAddr(t, addr)
		require.True(t, p.register(listens[i], fmt.Sprintf("p%d", i), []Device{{Policy: fmt.Sprintf("p%d", i), Addr: src}}, nil))
		p.receiver(listens[i]).setDuringCount(func() { time.Sleep(park) })
		_, err = sender.Write(v2cTrap("public"))
		require.NoError(t, err)
	}
	time.Sleep(20 * time.Millisecond)
	started := time.Now()
	p.Close()
	elapsed := time.Since(started)
	assert.Less(t, elapsed, park+stopTimeout+150*time.Millisecond, "closed concurrently: %s", elapsed)
	assert.Equal(t, 0, p.size())
}
