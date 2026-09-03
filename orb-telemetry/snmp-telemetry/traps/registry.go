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
	// claims maps an address to the policies claiming it and the users each
	// polls it with: none for a v1 or v2c target, more than one when a
	// policy keeps two targets at the address under different IDs or
	// contexts with different credentials.
	claims map[netip.Addr]map[string][]V3User
	// names is each policy's trap names, from its own profile set.
	names map[string]map[string]string
	gen   atomic.Uint64
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{claims: make(map[netip.Addr]map[string][]V3User), names: make(map[string]map[string]string)}
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
// the user the policy polls that device with, and its trap names. A runner
// calls it once its targets are expanded. Two devices at one address keep
// both their users; a repeat of one user is kept once.
func (r *Registry) Register(policy string, devices []Device, names map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.withdrawLocked(policy)
	for _, d := range devices {
		a := canonical(d.Addr)
		if !a.IsValid() {
			continue
		}
		if r.claims[a] == nil {
			r.claims[a] = make(map[string][]V3User)
		}
		users := r.claims[a][policy]
		if d.User != nil && !slices.Contains(users, *d.User) {
			users = append(users, *d.User)
		}
		r.claims[a][policy] = users
	}
	if names != nil {
		r.names[policy] = names
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
	delete(r.names, policy)
}

// claimsAt is the claims on an address, read under the lock. A claim written
// without a zone names the address on every interface, so for a zoned
// address it is merged with the claims written for that zone rather than
// consulted only when there are none.
func (r *Registry) claimsAt(addr netip.Addr) map[string][]V3User {
	a := canonical(addr)
	exact := r.claims[a]
	if a.Zone() == "" {
		return exact
	}
	zoneless := r.claims[a.WithZone("")]
	if len(zoneless) == 0 {
		return exact
	}
	if len(exact) == 0 {
		return zoneless
	}
	merged := make(map[string][]V3User, len(exact)+len(zoneless))
	for p, u := range zoneless {
		merged[p] = u
	}
	for p, u := range exact {
		merged[p] = append(slices.Clone(merged[p]), u...)
	}
	return merged
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
		for _, u := range policies[policy] {
			if !slices.Contains(out, u) {
				out = append(out, u)
			}
		}
	}
	return out
}

// NamesFor is the trap names a policy registered, or nil when it registered
// none.
func (r *Registry) NamesFor(policy string) map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.names[policy]
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
