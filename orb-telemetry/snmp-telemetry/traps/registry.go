package traps

import (
	"maps"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
)

// Device is one address a policy polls. The policy layer builds these from a
// runner's expanded targets. Hostname targets have no address and are not
// registered in phase 1.
type Device struct {
	Policy string
	Addr   netip.Addr
}

// V3User is the USM credential a v3 target carries. The receiver hands every
// registered user to gosnmp, which selects by username and localises the key
// against the sender's own engine ID, so no engine ID is configured here.
type V3User struct {
	Username       string
	AuthProtocol   string
	AuthPassphrase string
	PrivProtocol   string
	PrivPassphrase string
}

// Registry maps a source address to the policies that name it, and holds the
// v3 users those policies carry. Claims are refcounted by policy: two policies
// naming one device is ordinary, and withdrawing one must not remove the
// other's claim.
//
// It has its own lock and is never consulted under the policy manager's. The
// manager holds its write lock across a whole policy start, including
// expansion of up to 65536 targets, and a lookup on every datagram behind that
// lock would stall the receive loop for the duration of every policy push.
type Registry struct {
	mu     sync.RWMutex
	claims map[netip.Addr]map[string]struct{}
	users  map[string][]V3User
	gen    atomic.Uint64
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		claims: make(map[netip.Addr]map[string]struct{}),
		users:  make(map[string][]V3User),
	}
}

// canonical is the one spelling every address is stored and looked up under.
// A dual-stack socket delivers an IPv4 sender as an IPv4-mapped IPv6 address,
// and netip.Addr compares by representation, so without this every IPv4
// device misses the registry. The zone on a link-local address is kept: such
// an address is unique only per interface, and a wildcard socket sees the
// same fe80::1 from two interfaces as two devices. Lookup falls back to the
// zoneless form so a claim written without a zone still matches.
func canonical(a netip.Addr) netip.Addr {
	return a.Unmap()
}

// Register replaces the policy's claims and users with the ones given. A
// runner calls it once its targets are expanded.
func (r *Registry) Register(policy string, devices []Device, users []V3User) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.withdrawLocked(policy)
	for _, d := range devices {
		a := canonical(d.Addr)
		if !a.IsValid() {
			continue
		}
		if r.claims[a] == nil {
			r.claims[a] = make(map[string]struct{})
		}
		r.claims[a][policy] = struct{}{}
	}
	if len(users) > 0 {
		r.users[policy] = slices.Clone(users)
	}
	r.gen.Add(1)
}

// Withdraw removes every claim and user the policy registered.
func (r *Registry) Withdraw(policy string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.withdrawLocked(policy)
	r.gen.Add(1)
}

func (r *Registry) withdrawLocked(policy string) {
	for a, policies := range r.claims {
		delete(policies, policy)
		if len(policies) == 0 {
			delete(r.claims, a)
		}
	}
	delete(r.users, policy)
}

// Lookup returns the policies naming an address, in sorted order, or nil.
func (r *Registry) Lookup(addr netip.Addr) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a := canonical(addr)
	policies := r.claims[a]
	if len(policies) == 0 && a.Zone() != "" {
		// A claim written without a zone names the address on every
		// interface; a claim written with one names only that interface.
		policies = r.claims[a.WithZone("")]
	}
	if len(policies) == 0 {
		return nil
	}
	out := make([]string, 0, len(policies))
	for p := range policies {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// Users returns every registered v3 user across all policies.
func (r *Registry) Users() []V3User {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []V3User
	for _, policy := range slices.Sorted(maps.Keys(r.users)) {
		out = append(out, r.users[policy]...)
	}
	return out
}

// UsersFor returns the v3 users of exactly the policies named, in policy
// order. It is what a receiver hands gosnmp for a datagram whose source those
// policies claimed: gosnmp tries every same-username entry in turn, localising
// keys for each, so the table is kept to the credentials that can apply.
func (r *Registry) UsersFor(policies []string) []V3User {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []V3User
	for _, policy := range slices.Sorted(slices.Values(policies)) {
		out = append(out, r.users[policy]...)
	}
	return out
}

// Generation advances on every change, so a caller caching something derived
// from the registry can tell when to rebuild it without diffing.
func (r *Registry) Generation() uint64 { return r.gen.Load() }

// Size is the number of addresses with at least one claim.
func (r *Registry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.claims)
}
