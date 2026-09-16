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
	assert.Equal(t, []string{"z"}, r.Lookup(zoned), "the zone is part of the claim")
	assert.Empty(t, r.Lookup(addr("fe80::1")), "and a zoned claim is not matched without it")
}

// F11: gosnmp's credential table is keyed by username and holds a list per
// username, tried in turn. Two policies polling one device under the same
// username with different passphrases both have to reach it for that device,
// and withdrawing one policy takes only its credential away.
func TestRegistry_UsersAtCollectsAcrossPoliciesAndWithdrawsPerPolicy(t *testing.T) {
	r := NewRegistry()
	one := V3User{Username: "ops", AuthProtocol: "SHA", AuthPassphrase: "one"}
	two := V3User{Username: "ops", AuthProtocol: "SHA", AuthPassphrase: "two"}
	r.Register("a", []Device{{Policy: "a", Addr: addr("10.0.0.1"), User: &one}}, nil)
	r.Register("b", []Device{{Policy: "b", Addr: addr("10.0.0.1"), User: &two}}, nil)

	assert.Equal(t, []V3User{one, two}, r.UsersAt(addr("10.0.0.1")))

	r.Withdraw("b")
	assert.Equal(t, []V3User{one}, r.UsersAt(addr("10.0.0.1")), "only a's credential remains")
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

// Link-local IPv6 addresses are only unique per interface, and a wildcard
// socket receives them from every interface with the zone the kernel saw
// them on. Two devices at fe80::1 on different interfaces are two devices,
// so a zoned claim matches only its own zone. A claim written without a zone
// still matches the address on any interface, so an operator who did not
// spell the zone is not silently unmatched.
func TestRegistry_ZonesDistinguishLinkLocalDevices(t *testing.T) {
	r := NewRegistry()
	r.Register("a", []Device{{Policy: "a", Addr: addr("fe80::1").WithZone("eth0")}}, nil)
	r.Register("b", []Device{{Policy: "b", Addr: addr("fe80::1").WithZone("eth1")}}, nil)
	r.Register("c", []Device{{Policy: "c", Addr: addr("fe80::2")}}, nil)

	assert.Equal(t, []string{"a"}, r.Lookup(addr("fe80::1").WithZone("eth0")))
	assert.Equal(t, []string{"b"}, r.Lookup(addr("fe80::1").WithZone("eth1")))
	assert.Empty(t, r.Lookup(addr("fe80::1").WithZone("eth2")), "a zone no policy named")
	assert.Equal(t, []string{"c"}, r.Lookup(addr("fe80::2").WithZone("eth0")), "a claim without a zone matches the address on any interface")
	assert.Equal(t, []string{"c"}, r.Lookup(addr("fe80::2")))
	assert.Equal(t, 3, r.Size())
}

// UsersAt returns the v3 users of the devices claimed at an address, one per
// claiming policy, so a receiver tries only the credentials a policy assigned
// to that device rather than every credential the policy carries.
func TestRegistry_UsersAtNamesOnlyThatDevicesCredentials(t *testing.T) {
	r := NewRegistry()
	ua := V3User{Username: "shared", AuthProtocol: "SHA", AuthPassphrase: "a-pass"}
	ub := V3User{Username: "shared", AuthProtocol: "SHA", AuthPassphrase: "b-pass"}
	uc := V3User{Username: "other", AuthProtocol: "SHA", AuthPassphrase: "c-pass"}
	r.Register("core", []Device{
		{Policy: "core", Addr: addr("10.0.0.1"), User: &ua},
		{Policy: "core", Addr: addr("10.0.0.2"), User: &ub},
		{Policy: "core", Addr: addr("10.0.0.3")},
	}, nil)
	r.Register("edge", []Device{{Policy: "edge", Addr: addr("10.0.0.1"), User: &uc}}, nil)

	assert.Equal(t, []V3User{ua, uc}, r.UsersAt(addr("10.0.0.1")), "one per claiming policy, in policy order")
	assert.Equal(t, []V3User{ub}, r.UsersAt(addr("10.0.0.2")), "a's credential is not tried for b")
	assert.Empty(t, r.UsersAt(addr("10.0.0.3")), "a v2c device has no user")
	assert.Empty(t, r.UsersAt(addr("10.0.0.9")), "an unclaimed address has none")
	assert.Equal(t, []V3User{ua, uc}, r.UsersAt(netip.AddrFrom16(addr("10.0.0.1").As16())), "through the 4-in-6 form")

	r.Withdraw("edge")
	assert.Equal(t, []V3User{ua}, r.UsersAt(addr("10.0.0.1")), "withdrawal takes the policy's credential with it")
}

// A zoneless claim names the address on every interface, so it is matched
// alongside an exact zoned claim rather than only when no zoned claim exists.
func TestRegistry_ZonedAndZonelessClaimsCoexist(t *testing.T) {
	r := NewRegistry()
	ua := V3User{Username: "a", AuthProtocol: "SHA", AuthPassphrase: "a-pass"}
	ub := V3User{Username: "b", AuthProtocol: "SHA", AuthPassphrase: "b-pass"}
	r.Register("any", []Device{{Policy: "any", Addr: addr("fe80::1"), User: &ua}}, nil)
	r.Register("eth0", []Device{{Policy: "eth0", Addr: addr("fe80::1").WithZone("eth0"), User: &ub}}, nil)

	assert.Equal(t, []string{"any", "eth0"}, r.Lookup(addr("fe80::1").WithZone("eth0")), "both claim the address on eth0")
	assert.Equal(t, []V3User{ua, ub}, r.UsersAt(addr("fe80::1").WithZone("eth0")))
	assert.Equal(t, []string{"any"}, r.Lookup(addr("fe80::1").WithZone("eth1")), "only the zoneless claim reaches eth1")
	assert.Equal(t, []string{"any"}, r.Lookup(addr("fe80::1")))
}

// A policy may keep two targets at one address under different IDs or SNMP
// contexts, each with its own credential. Both credentials belong to that
// source and both are kept.
func TestRegistry_KeepsEveryCredentialOfDuplicateAddressTargets(t *testing.T) {
	r := NewRegistry()
	one := V3User{Username: "ctx-a", AuthProtocol: "SHA", AuthPassphrase: "one"}
	two := V3User{Username: "ctx-b", AuthProtocol: "SHA", AuthPassphrase: "two"}
	r.Register("core", []Device{
		{Policy: "core", Addr: addr("10.0.0.1"), User: &one},
		{Policy: "core", Addr: addr("10.0.0.1"), User: &two},
		{Policy: "core", Addr: addr("10.0.0.1"), User: &one},
	}, nil)
	assert.Equal(t, []V3User{one, two}, r.UsersAt(addr("10.0.0.1")), "both kept, the repeat once")
	assert.Equal(t, 1, r.Size())
}

// A policy registers the trap names of its own profile set, so two policies
// on one socket can name the same OID differently, and a policy registered
// without names has none.
func TestRegistry_NamesForPolicy(t *testing.T) {
	r := NewRegistry()
	r.Register("a", []Device{{Policy: "a", Addr: addr("10.0.0.1")}}, map[string]string{"1.2.3": "aName"})
	r.Register("b", []Device{{Policy: "b", Addr: addr("10.0.0.1")}}, nil)
	assert.Equal(t, "aName", r.NamesFor("a")["1.2.3"])
	assert.Nil(t, r.NamesFor("b"))
	assert.Nil(t, r.NamesFor("nobody"))
	r.Withdraw("a")
	assert.Nil(t, r.NamesFor("a"), "withdrawn with the claims")
}

// PoliciesAt with a credential predicate returns only the policies whose
// registered users at the address satisfy it, so a v3 trap is attributed to
// the policies holding the credential that verified it and to no other.
func TestRegistry_PoliciesAtFiltersByCredential(t *testing.T) {
	r := NewRegistry()
	mine := V3User{Username: "shared", AuthProtocol: "SHA", AuthPassphrase: "mine"}
	theirs := V3User{Username: "shared", AuthProtocol: "SHA", AuthPassphrase: "theirs"}
	r.Register("core", []Device{{Policy: "core", Addr: addr("10.0.0.1"), User: &mine}}, nil)
	r.Register("edge", []Device{{Policy: "edge", Addr: addr("10.0.0.1"), User: &theirs}}, nil)
	r.Register("plain", []Device{{Policy: "plain", Addr: addr("10.0.0.1")}}, nil)

	assert.Equal(t, []string{"core", "edge", "plain"}, r.PoliciesAt(addr("10.0.0.1"), nil), "no predicate: every claim")
	holds := func(want V3User) func(V3User) bool { return func(u V3User) bool { return u == want } }
	assert.Equal(t, []string{"core"}, r.PoliciesAt(addr("10.0.0.1"), holds(mine)))
	assert.Equal(t, []string{"edge"}, r.PoliciesAt(addr("10.0.0.1"), holds(theirs)))
	assert.Empty(t, r.PoliciesAt(addr("10.0.0.1"), holds(V3User{Username: "nobody"})))
	assert.Empty(t, r.PoliciesAt(addr("10.0.0.9"), nil))
}
