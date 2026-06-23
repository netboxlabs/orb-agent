package mapping

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOCSpeedToKbps(t *testing.T) {
	require.Equal(t, int64(10000000), ocSpeedToKbps["SPEED_10GB"])
	require.Equal(t, int64(1000000), ocSpeedToKbps["SPEED_1GB"])
	require.Equal(t, int64(400000000), ocSpeedToKbps["SPEED_400GB"])
	_, ok := ocSpeedToKbps["SPEED_UNKNOWN"]
	require.False(t, ok)
}

func TestOCSpeedToType(t *testing.T) {
	require.Equal(t, "10gbase-x-sfpp", ocSpeedToType["SPEED_10GB"])
	require.Equal(t, "25gbase-x-sfp28", ocSpeedToType["SPEED_25GB"])
	require.Equal(t, "1000base-t", ocSpeedToType["SPEED_1GB"])
	_, ok := ocSpeedToType["SPEED_10MB"] // no clean NetBox media slug -> not in table
	require.False(t, ok)
}

func TestResolveInterfaceType(t *testing.T) {
	userPats := []compiledIfacePattern{
		{re: regexp.MustCompile(`^mgmt`), typ: "1000base-t"},
	}

	// 1) user pattern wins over everything (even an OC lag type)
	require.Equal(t, "1000base-t",
		resolveInterfaceType("mgmt0", "IEEE8023ADLAG", "SPEED_10GB", "other", userPats))

	// 2) OC state/type lag beats name/speed heuristics
	require.Equal(t, "lag",
		resolveInterfaceType("Ethernet1", "IEEE8023ADLAG", "SPEED_10GB", "other", nil))
	require.Equal(t, "virtual",
		resolveInterfaceType("Loopback0", "SOFTWARELOOPBACK", "", "other", nil))

	// 3) built-in name pattern when OC type is ethernet/absent (Cisco Te -> 10G media)
	require.Equal(t, "10gbase-x-sfpp",
		resolveInterfaceType("TenGigE0/0/0/1", "ETHERNETCSMACD", "SPEED_1GB", "other", nil))
	require.Equal(t, "lag",
		resolveInterfaceType("Port-Channel1", "", "", "other", nil))

	// 4) speed-based when name has no media hint (Arista/Nokia style)
	require.Equal(t, "25gbase-x-sfp28",
		resolveInterfaceType("Ethernet5", "ETHERNETCSMACD", "SPEED_25GB", "other", nil))
	require.Equal(t, "1000base-t",
		resolveInterfaceType("ethernet-1/1", "", "SPEED_1GB", "other", nil))

	// 5) default when nothing matches
	require.Equal(t, "other",
		resolveInterfaceType("Ethernet9", "ETHERNETCSMACD", "", "other", nil))
	require.Equal(t, "mydefault",
		resolveInterfaceType("weird0", "", "SPEED_UNKNOWN", "mydefault", nil))

	// Juniper et- is intentionally NOT a built-in name rule (40G/100G ambiguous):
	// it resolves via the authoritative speed tier instead.
	require.Equal(t, "100gbase-x-qsfp28",
		resolveInterfaceType("et-0/0/0", "ETHERNETCSMACD", "SPEED_100GB", "other", nil))
	require.Equal(t, "40gbase-x-qsfpp",
		resolveInterfaceType("et-0/0/0", "ETHERNETCSMACD", "SPEED_40GB", "other", nil))
	// xe-/ge- remain media-encoding name rules (beat speed).
	require.Equal(t, "10gbase-x-sfpp",
		resolveInterfaceType("xe-0/0/0", "ETHERNETCSMACD", "SPEED_1GB", "other", nil))
}

func TestResolveInterfaceTypeVendorNames(t *testing.T) {
	// Huawei media names (authoritative, unambiguous prefixes).
	require.Equal(t, "100gbase-x-qsfp28",
		resolveInterfaceType("100GE1/0/1", "ETHERNETCSMACD", "", "other", nil))
	require.Equal(t, "40gbase-x-qsfpp",
		resolveInterfaceType("40GE1/0/1", "ETHERNETCSMACD", "", "other", nil))
	require.Equal(t, "25gbase-x-sfp28",
		resolveInterfaceType("25GE1/0/1", "ETHERNETCSMACD", "", "other", nil))
	require.Equal(t, "10gbase-x-sfpp",
		resolveInterfaceType("10GE1/0/1", "ETHERNETCSMACD", "", "other", nil))
	require.Equal(t, "1000base-t",
		resolveInterfaceType("GE1/0/1", "ETHERNETCSMACD", "", "other", nil))
	// Huawei aggregate + SVI.
	require.Equal(t, "lag",
		resolveInterfaceType("Eth-Trunk10", "ETHERNETCSMACD", "", "other", nil))
	require.Equal(t, "virtual",
		resolveInterfaceType("Vlanif100", "ETHERNETCSMACD", "", "other", nil))
	// SONiC / Dell port-channel (hyphen-less — the existing Po rule does NOT match).
	require.Equal(t, "lag",
		resolveInterfaceType("PortChannel01", "ETHERNETCSMACD", "", "other", nil))
	// Ladder precedence intact: an OC state/type lag still beats a name guess.
	require.Equal(t, "lag",
		resolveInterfaceType("10GE1/0/1", "IEEE8023ADLAG", "", "other", nil))

	// An empty-typed user pattern is skipped (must not set Type to "" or
	// short-circuit the fallback chain) — falls through to the OC state/type.
	emptyTyped := []compiledIfacePattern{{re: regexp.MustCompile(`^mgmt`), typ: ""}}
	require.Equal(t, "lag",
		resolveInterfaceType("mgmt0", "IEEE8023ADLAG", "", "other", emptyTyped))
}

func TestOCDuplex(t *testing.T) {
	require.Equal(t, "full", ocDuplex["FULL"])
	require.Equal(t, "half", ocDuplex["HALF"])
	_, ok := ocDuplex["AUTO"]
	require.False(t, ok)
}
