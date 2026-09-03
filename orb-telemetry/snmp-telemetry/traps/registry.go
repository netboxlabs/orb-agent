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
	// User is the USM credential the policy polls this device with, nil for
	// a v1 or v2c target. A trap from the device is authenticated with this
	// credential and no other: one a policy assigned to a different device
	// must not vouch for this one.
	User *V3User
}

// V3User is the USM credential a v3 target carries. The receiver hands gosnmp
// the users of the devices claimed at a datagram's source, and gosnmp selects
// by username and localises the key against the sender's own engine ID, so no
// engine ID is configured here.
type V3User struct {
	Username       string
	AuthProtocol   string
	AuthPassphrase string
	PrivProtocol   string
	PrivPassphrase string
}

// Registry maps a source address to the policies that name it, each with the
// v3 user it polls that device with. Claims are refcounted by policy: two
// policies naming one device is ordinary, and withdrawing one must not remove
// the other's claim.
//
// It has its own lock and is never consulted under the policy manager's. The
// manager holds its write lock across a whole policy start, including
// expansion of up to 65536 targets, and a lookup on every datagram behind that
// lock would stall the receive loop for the duration of every policy push.
type Registry struct {
	mu sync.RWMutex
	// claims maps an address to the policies claiming it and the user each
	// polls it with, nil for a v1 or v2c target.
	claims map[netip.Addr]map[string]*V3User
	gen    atomic.Uint64
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{claims: make(map[netip.Addr]map[string]*V3User)}
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

// Register replaces the policy's claims with the ones given, each carrying
// the user the policy polls that device with. A runner calls it once its
// targets are expanded.
func (r *Registry) Register(policy string, devices []Device) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.withdrawLocked(policy)
	for _, d := range devices {
		a := canonical(d.Addr)
		if !a.IsValid() {
			continue
		}
		if r.claims[a] == nil {
			r.claims[a] = make(map[string]*V3User)
		}
		var u *V3User
		if d.User != nil {
			copied := *d.User
			u = &copied
		}
		r.claims[a][policy] = u
	}
	r.gen.Add(1)
}

// Withdraw removes every claim the policy registered.
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
}

// claimsAt is the claims on an address, read under the lock. A claim written
// without a zone names the address on every interface; a claim written with
// one names only that interface.
func (r *Registry) claimsAt(addr netip.Addr) map[string]*V3User {
	a := canonical(addr)
	policies := r.claims[a]
	if len(policies) == 0 && a.Zone() != "" {
		policies = r.claims[a.WithZone("")]
	}
	return policies
}

// Lookup returns the policies naming an address, in sorted order, or nil.
func (r *Registry) Lookup(addr netip.Addr) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	policies := r.claimsAt(addr)
	if len(policies) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(policies))
}

// UsersAt returns the v3 users the claiming policies poll an address with,
// in policy order, and nothing else. It is what a receiver hands gosnmp for a
// datagram from that address: gosnmp tries every same-username entry in turn,
// localising keys for each, so the table is kept to the credentials assigned
// to this device.
func (r *Registry) UsersAt(addr netip.Addr) []V3User {
	r.mu.RLock()
	defer r.mu.RUnlock()
	policies := r.claimsAt(addr)
	var out []V3User
	for _, policy := range slices.Sorted(maps.Keys(policies)) {
		if u := policies[policy]; u != nil {
			out = append(out, *u)
		}
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
