package traps

import (
	"log/slog"
	"net/netip"
	"sync"
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
	names  map[string]string
	logger *slog.Logger

	mu      sync.Mutex
	entries map[string]*poolEntry
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
	listen string
	policy string
	once   sync.Once
}

// NewPool returns an empty pool. names is the closed trap-name set every
// receiver labels with; tally is where every receiver counts.
func NewPool(tally *Tally, names map[string]string, logger *slog.Logger) *Pool {
	return &Pool{tally: tally, names: names, logger: logger, entries: make(map[string]*poolEntry)}
}

// Acquire registers the policy's devices and users on the socket for listen,
// binding it first when no policy holds it yet. A bind failure is returned as
// Listen reports it and leaves the pool unchanged.
func (p *Pool) Acquire(listen, policy string, devices []Device, users []V3User) (*Lease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[listen]
	if !ok {
		reg := NewRegistry()
		rcv, err := Listen(listen, reg, p.tally, p.names, p.logger)
		if err != nil {
			return nil, err
		}
		e = &poolEntry{receiver: rcv, registry: reg}
		p.entries[listen] = e
		p.logger.Info("Trap receiver listening", "address", rcv.Addr().String(), "policy", policy, "trap_names", len(p.names))
	} else {
		p.logger.Debug("Policy joined an open trap socket", "address", listen, "policy", policy, "holders", e.refs+1)
	}
	e.registry.Register(policy, devices, users)
	e.refs++
	return &Lease{pool: p, listen: listen, policy: policy}, nil
}

// Release withdraws the policy. The tally is withdrawn even when the entry is
// gone, so a policy released after Close still stops exporting.
func (l *Lease) Release() {
	l.once.Do(func() {
		p := l.pool
		p.mu.Lock()
		p.tally.Withdraw(l.policy)
		e, ok := p.entries[l.listen]
		var closing *Receiver
		if ok {
			e.registry.Withdraw(l.policy)
			e.refs--
			if e.refs == 0 {
				delete(p.entries, l.listen)
				closing = e.receiver
			}
		}
		p.mu.Unlock()
		// Stopping waits for the read goroutine, up to its bound; that wait
		// is spent outside the lock so another policy can acquire meanwhile.
		if closing != nil {
			closing.Stop()
			p.logger.Info("Trap receiver closed", "address", l.listen)
		}
	})
}

// Close stops every receiver. Called once at shutdown.
func (p *Pool) Close() {
	p.mu.Lock()
	entries := p.entries
	p.entries = make(map[string]*poolEntry)
	p.mu.Unlock()
	for _, e := range entries {
		e.receiver.Stop()
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

func (p *Pool) register(listen, policy string, devices []Device, users []V3User) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[listen]
	if !ok {
		return false
	}
	e.registry.Register(policy, devices, users)
	return true
}
