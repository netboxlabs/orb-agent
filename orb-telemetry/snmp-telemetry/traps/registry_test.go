package traps

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// Two policies legitimately name one device. Withdrawing one must not take
// the other's claim with it; that is why claims are refcounted by policy.
func TestRegistry_TwoPoliciesOneAddress(t *testing.T) {
	r := NewRegistry()
	r.Register("core", []Device{{Policy: "core", Addr: addr("10.0.0.5")}}, nil)
	r.Register("edge", []Device{{Policy: "edge", Addr: addr("10.0.0.5")}}, nil)

	assert.ElementsMatch(t, []string{"core", "edge"}, r.Lookup(addr("10.0.0.5")))

	r.Withdraw("core")
	assert.Equal(t, []string{"edge"}, r.Lookup(addr("10.0.0.5")), "edge still names the device")

	r.Withdraw("edge")
	assert.Empty(t, r.Lookup(addr("10.0.0.5")))
	assert.Equal(t, 0, r.Size(), "an address with no claims is deleted, not left empty")
}

func TestRegistry_WithdrawOfAnUnknownPolicyIsANoOp(t *testing.T) {
	r := NewRegistry()
	r.Register("core", []Device{{Policy: "core", Addr: addr("10.0.0.5")}}, nil)
	r.Withdraw("never-registered")
	assert.Equal(t, []string{"core"}, r.Lookup(addr("10.0.0.5")))
}

// F14: on a dual-stack bind an IPv4 sender arrives as ::ffff:10.0.0.5, and
// netip.Addr compares by representation. Both sides canonicalise.
func TestRegistry_CanonicalisesIPv4MappedAndZonedAddresses(t *testing.T) {
	r := NewRegistry()
	r.Register("p", []Device{{Policy: "p", Addr: addr("10.0.0.5")}}, nil)

	mapped := netip.AddrFrom16(addr("10.0.0.5").As16())
	require.True(t, mapped.Is4In6(), "the fixture must be the 4-in-6 form")
	assert.Equal(t, []string{"p"}, r.Lookup(mapped), "a 4-in-6 lookup finds the IPv4 registration")

	r.Register("q", []Device{{Policy: "q", Addr: mapped}}, nil)
	assert.ElementsMatch(t, []string{"p", "q"}, r.Lookup(addr("10.0.0.5")), "a 4-in-6 registration is found by the IPv4 form")

	zoned := addr("fe80::1").WithZone("eth0")
	r.Register("z", []Device{{Policy: "z", Addr: zoned}}, nil)
	assert.Equal(t, []string{"z"}, r.Lookup(addr("fe80::1")), "the zone is dropped")
}

// F11: gosnmp's credential table is keyed by username and holds a list per
// username, tried in turn. Two targets sharing a username with different
// passphrases both have to reach it.
func TestRegistry_UsersAreCollectedAcrossPoliciesAndWithdrawnPerPolicy(t *testing.T) {
	r := NewRegistry()
	r.Register("a", nil, []V3User{{Username: "ops", AuthProtocol: "SHA", AuthPassphrase: "one"}})
	r.Register("b", nil, []V3User{{Username: "ops", AuthProtocol: "SHA", AuthPassphrase: "two"}, {Username: "ro", AuthProtocol: "SHA", AuthPassphrase: "three"}})

	assert.Len(t, r.Users(), 3)

	r.Withdraw("b")
	users := r.Users()
	require.Len(t, users, 1)
	assert.Equal(t, "one", users[0].AuthPassphrase, "only a's user remains")
}

// The receiver rebuilds gosnmp's table when the users change. It learns that
// from a generation counter rather than by diffing lists on every packet.
func TestRegistry_GenerationAdvancesOnEveryChange(t *testing.T) {
	r := NewRegistry()
	g0 := r.Generation()
	r.Register("a", []Device{{Policy: "a", Addr: addr("10.0.0.1")}}, nil)
	g1 := r.Generation()
	r.Withdraw("a")
	g2 := r.Generation()
	assert.Less(t, g0, g1)
	assert.Less(t, g1, g2)
}

func TestRegistry_ReRegisterReplacesAPolicysClaims(t *testing.T) {
	r := NewRegistry()
	r.Register("p", []Device{{Policy: "p", Addr: addr("10.0.0.1")}}, nil)
	r.Register("p", []Device{{Policy: "p", Addr: addr("10.0.0.2")}}, nil)
	assert.Empty(t, r.Lookup(addr("10.0.0.1")), "the old claim is gone")
	assert.Equal(t, []string{"p"}, r.Lookup(addr("10.0.0.2")))
}
