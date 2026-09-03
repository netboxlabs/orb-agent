package traps

import (
	"errors"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// Pool opens one receiver per listen address and shares it between the
// policies that name that address, the way pktvisor shares one input stream
// between the policies that name one tap with one configuration.
//
// The listen string is the identity, verbatim. "0.0.0.0:162" twice is one
// socket; "0.0.0.0:162" and ":162" are two bind attempts at one port and the
// second fails with the operating system's error. The strings are not
// normalised, because normalising would make sharing depend on a rule an
// operator cannot see in their own YAML.
//
// Each entry has its own registry, so a policy on one socket never attributes
// traps arriving on another. The tally is shared: its series carry the policy.
type Pool struct {
	tally  *Tally
	logger *slog.Logger

	mu      sync.Mutex
	entries map[string]*poolEntry
	closed  bool
}

type poolEntry struct {
	receiver *Receiver
	registry *Registry
	refs     int
}

// Lease is one policy's hold on one socket. Release withdraws the policy and
// closes the socket when it was the last holder. Releasing twice, or after
// the pool was closed, does nothing.
type Lease struct {
	pool   *Pool
	entry  *poolEntry
	listen string
	policy string
	once   sync.Once
}

// NewPool returns an empty pool. tally is where every receiver counts; trap
// names come with each policy's claims.
func NewPool(tally *Tally, logger *slog.Logger) *Pool {
	return &Pool{tally: tally, logger: logger, entries: make(map[string]*poolEntry)}
}

// Acquire registers the policy's devices, each with its own v3 user, on the socket for listen,
// binding it first when no policy holds it yet. A bind failure is returned as
// Listen reports it and leaves the pool unchanged. A closed pool binds
// nothing: the socket would have no one left to stop it.
//
// One lease per (listen, policy) pair is what the pool expects. The registry
// replaces a policy's claims rather than accumulating them, so a second
// acquire for the same pair would leave the policy holding the entry twice
// while naming its devices once.
func (p *Pool) Acquire(listen, policy string, devices []Device, names map[string]string) (*Lease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errors.New("trap pool is closed")
	}
	e, ok := p.entries[listen]
	if !ok {
		reg := NewRegistry()
		rcv, err := Listen(listen, reg, p.tally, BuildNames(nil), p.logger)
		if err != nil {
			return nil, err
		}
		e = &poolEntry{receiver: rcv, registry: reg}
		p.entries[listen] = e
		p.logger.Info("Trap receiver listening", "address", rcv.Addr().String(), "policy", config.SanitizeLogValue(policy))
	} else {
		p.logger.Debug("Policy joined an open trap socket", "address", config.SanitizeLogValue(listen), "policy", config.SanitizeLogValue(policy), "holders", e.refs+1)
	}
	// Activated before the claims are published: a receiver already
	// waiting on the registry lock counts the moment the claims land, and a
	// count for a policy the tally still holds withdrawn would sit dormant
	// until the same series key arrived again.
	p.tally.Activate(policy)
	e.registry.Register(policy, devices, names)
	e.refs++
	return &Lease{pool: p, entry: e, listen: listen, policy: policy}, nil
}

// Release withdraws the policy. The tally is withdrawn even when the entry
// this lease held is gone, so a policy released after Close still stops
// exporting.
//
// The entry is matched by identity, not by listen string alone. A pool that
// was closed and then reopened, or any other path that replaces the entry
// under a live lease, would otherwise have this release decrement a holder
// count it never incremented and close a socket another policy is reading.
func (l *Lease) Release() {
	l.once.Do(func() {
		p := l.pool
		p.mu.Lock()
		e, ok := p.entries[l.listen]
		if !ok || e != l.entry {
			p.tally.Withdraw(l.policy)
			p.mu.Unlock()
			return
		}
		// The registry first, then the tally, so nothing is counted for a
		// policy whose addresses the registry still answers for. The reverse
		// window stays open: a datagram already past its lookup when the
		// withdrawal runs can still count once for the released policy. That
		// residual count is accepted, since closing it would mean holding a
		// lock across the whole receive path.
		e.registry.Withdraw(l.policy)
		p.tally.Withdraw(l.policy)
		e.refs--
		var closing *Receiver
		if e.refs == 0 {
			delete(p.entries, l.listen)
			closing = e.receiver
			// Closed under the lock, because the entry is already out of the
			// map: a policy acquiring the same string in the gap would bind
			// while this socket was still open and fail with the operating
			// system's address-in-use error.
			closing.close()
		}
		p.mu.Unlock()
		// The wait for the read goroutine is spent outside the lock, so
		// another policy can acquire meanwhile.
		if closing != nil {
			closing.wait()
			p.logger.Info("Trap receiver closed", "address", config.SanitizeLogValue(l.listen))
		}
	})
}

// Close stops every receiver and refuses every later Acquire. Called once at
// shutdown.
func (p *Pool) Close() {
	p.mu.Lock()
	entries := p.entries
	p.entries = make(map[string]*poolEntry)
	p.closed = true
	// Closed under the lock and waited for outside it, the same split Release
	// makes, so no socket is left open once the map no longer names it.
	for _, e := range entries {
		e.receiver.close()
	}
	p.mu.Unlock()
	for _, e := range entries {
		e.receiver.wait()
	}
}

// Test accessors. Unexported and read under the lock.
func (p *Pool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

func (p *Pool) refs(listen string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[listen]; ok {
		return e.refs
	}
	return 0
}

func (p *Pool) addr(listen string) (netip.AddrPort, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[listen]; ok {
		return e.receiver.Addr(), true
	}
	return netip.AddrPort{}, false
}

func (p *Pool) lookup(listen string, a netip.Addr) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[listen]; ok {
		return e.registry.Lookup(a)
	}
	return nil
}

func (p *Pool) register(listen, policy string, devices []Device, names map[string]string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[listen]
	if !ok {
		return false
	}
	e.registry.Register(policy, devices, names)
	return true
}
