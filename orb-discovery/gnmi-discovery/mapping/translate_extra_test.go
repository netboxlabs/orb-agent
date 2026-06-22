package mapping

import (
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// firstKeyVal
// ---------------------------------------------------------------------------

func TestFirstKeyValHappyPath(t *testing.T) {
	// basic "[key=value]/rest" case
	val, rest, ok := firstKeyVal("[name=Ethernet1]/state/mtu")
	require.True(t, ok)
	require.Equal(t, "Ethernet1", val)
	require.Equal(t, "/state/mtu", rest)
}

func TestFirstKeyValEmptyString(t *testing.T) {
	val, rest, ok := firstKeyVal("")
	require.False(t, ok)
	require.Equal(t, "", val)
	require.Equal(t, "", rest)
}

func TestFirstKeyValNoLeadingBracket(t *testing.T) {
	// s does not start with '['
	val, rest, ok := firstKeyVal("name=Ethernet1]/state/mtu")
	require.False(t, ok)
	require.Equal(t, "", val)
	require.Equal(t, "", rest)
}

func TestFirstKeyValNoClosingBracket(t *testing.T) {
	// '[' present but ']' missing
	val, rest, ok := firstKeyVal("[name=Ethernet1/state/mtu")
	require.False(t, ok)
	require.Equal(t, "", val)
	require.Equal(t, "", rest)
}

func TestFirstKeyValNoEquals(t *testing.T) {
	// bracket pair present but no '=' in the key=value portion
	val, rest, ok := firstKeyVal("[nameEthernet1]")
	require.False(t, ok)
	require.Equal(t, "", val)
	require.Equal(t, "", rest)
}

func TestFirstKeyValValueWithSlash(t *testing.T) {
	// slash inside the value (e.g. interface "Eth1/1") must survive intact
	val, rest, ok := firstKeyVal("[name=Eth1/1]/subinterfaces")
	require.True(t, ok)
	require.Equal(t, "Eth1/1", val)
	require.Equal(t, "/subinterfaces", rest)
}

func TestFirstKeyValIPv6Value(t *testing.T) {
	// colon-containing IPv6 address as value
	val, rest, ok := firstKeyVal("[ip=2001:db8::1]/state/prefix-length")
	require.True(t, ok)
	require.Equal(t, "2001:db8::1", val)
	require.Equal(t, "/state/prefix-length", rest)
}

// ---------------------------------------------------------------------------
// parseIPAddressPath additional branches
// ---------------------------------------------------------------------------

func TestParseIPAddressPathEmptyIfaceListPath(t *testing.T) {
	// ifaceListPath="" must return ok=false immediately
	_, _, _, _, _, ok := parseIPAddressPath(
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length",
		"",
	)
	require.False(t, ok)
}

func TestParseIPAddressPathNoSubinterface(t *testing.T) {
	// path starts under iface list but does not contain /subinterfaces/subinterface
	_, _, _, _, _, ok := parseIPAddressPath(
		"/interfaces/interface[name=Ethernet1]/state/mtu",
		"/interfaces/interface",
	)
	require.False(t, ok)
}

func TestParseIPAddressPathNoAddressesAddress(t *testing.T) {
	// hits /ipv4/ but does not have /addresses/address after the family
	_, _, _, _, _, ok := parseIPAddressPath(
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/state/counters",
		"/interfaces/interface",
	)
	require.False(t, ok)
}

func TestParseIPAddressPathNeitherIPv4NorIPv6(t *testing.T) {
	// rest after subinterface key has neither /ipv4/ nor /ipv6/ prefix
	_, _, _, _, _, ok := parseIPAddressPath(
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/mpls/something",
		"/interfaces/interface",
	)
	require.False(t, ok)
}

func TestParseIPAddressPathNonPrefixLengthLeaf(t *testing.T) {
	// valid address path but leaf is "state/ip", not "state/prefix-length"
	iface, index, family, ip, leaf, ok := parseIPAddressPath(
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/ip",
		"/interfaces/interface",
	)
	require.True(t, ok)
	require.Equal(t, "Ethernet1", iface)
	require.Equal(t, "0", index)
	require.Equal(t, "ipv4", family)
	require.Equal(t, "10.0.0.1", ip)
	require.Equal(t, "state/ip", leaf) // translateIPs skips this because leaf != "state/prefix-length"
}

func TestParseIPAddressPathIPv6Family(t *testing.T) {
	// explicitly confirm /ipv6/ path sets family="ipv6"
	_, _, family, _, _, ok := parseIPAddressPath(
		"/interfaces/interface[name=Eth0]/subinterfaces/subinterface[index=0]/ipv6/addresses/address[ip=::1]/state/prefix-length",
		"/interfaces/interface",
	)
	require.True(t, ok)
	require.Equal(t, "ipv6", family)
}

func TestParseIPAddressPathMalformedSubinterfaceKey(t *testing.T) {
	// subinterface list key missing '=' → firstKeyVal fails for index → ok=false
	_, _, _, _, _, ok := parseIPAddressPath(
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length",
		"/interfaces/interface",
	)
	require.False(t, ok)
}

func TestParseIPAddressPathMalformedIfaceKey(t *testing.T) {
	// The iface list key itself has no '=' → firstKeyVal for iface fails → ok=false.
	// Path starts with ifaceListPath+"[" but the bracket contents have no '='.
	_, _, _, _, _, ok := parseIPAddressPath(
		"/interfaces/interface[Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length",
		"/interfaces/interface",
	)
	require.False(t, ok)
}

func TestParseIPAddressPathMalformedIPKey(t *testing.T) {
	// ip list key has no '=' → third firstKeyVal call returns ok=false
	_, _, _, _, _, ok := parseIPAddressPath(
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[10.0.0.1]/state/prefix-length",
		"/interfaces/interface",
	)
	require.False(t, ok)
}

// ---------------------------------------------------------------------------
// translateIPs edge cases
// ---------------------------------------------------------------------------

func TestTranslateIPsEmptyListPath(t *testing.T) {
	// Profile with no interfaces list_path → translateIPs returns nil immediately.
	p := &Profile{} // Interfaces.ListPath is ""
	dev := &diode.Device{Name: strptr("r1")}
	require.Nil(t, translateIPs(p, map[string]any{}, dev, nil, nil))
}

func TestTranslateIPsDuplicateAddrKey(t *testing.T) {
	// The same (iface, index, family, ip) key appearing twice in the snap: only one
	// order entry must be appended (dedup), and the last value wins.
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	dev := &diode.Device{Name: strptr("r1")}
	pfx := "/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length"
	snap := map[string]any{pfx: 24}
	ents := translateIPs(base, snap, dev, nil, nil)
	var ips []*diode.IPAddress
	for _, e := range ents {
		if ip, ok := e.(*diode.IPAddress); ok {
			ips = append(ips, ip)
		}
	}
	require.Len(t, ips, 1)
	require.Equal(t, "10.0.0.1/24", *ips[0].Address)
}

func TestTranslateIPsEmptyPrefixLengthSkipped(t *testing.T) {
	// A snap entry that parses as a valid IP path but whose value is empty string
	// (prefix-length = "") must be skipped — no IPAddress emitted.
	store, _ := LoadProfiles("")
	base, _ := store.Get("_base")
	dev := &diode.Device{Name: strptr("r1")}
	snap := map[string]any{
		"/interfaces/interface[name=Ethernet1]/subinterfaces/subinterface[index=0]/ipv4/addresses/address[ip=10.0.0.1]/state/prefix-length": "",
	}
	ents := translateIPs(base, snap, dev, nil, nil)
	for _, e := range ents {
		_, isIP := e.(*diode.IPAddress)
		require.False(t, isIP, "empty prefix-length must not emit an IPAddress")
	}
}

// ---------------------------------------------------------------------------
// listKeyAndLeaf additional branches
// ---------------------------------------------------------------------------

func TestListKeyAndLeafMissingCloseBracket(t *testing.T) {
	// path starts with listPath+"[" but has no ']'
	_, _, ok := listKeyAndLeaf(
		"/interfaces/interface[name=Ethernet1/state/mtu", // ']' intentionally absent
		"/interfaces/interface",
	)
	require.False(t, ok)
}

func TestListKeyAndLeafMissingEquals(t *testing.T) {
	// key=value portion has no '='
	_, _, ok := listKeyAndLeaf(
		"/interfaces/interface[nameEthernet1]/state/mtu",
		"/interfaces/interface",
	)
	require.False(t, ok)
}

// ---------------------------------------------------------------------------
// toInt64Ptr additional branches (int, int64, float64, string, nil/invalid)
// ---------------------------------------------------------------------------

func TestToInt64PtrInt(t *testing.T) {
	got := toInt64Ptr(int(42))
	require.NotNil(t, got)
	require.Equal(t, int64(42), *got)
}

func TestToInt64PtrInt64(t *testing.T) {
	got := toInt64Ptr(int64(1234567890))
	require.NotNil(t, got)
	require.Equal(t, int64(1234567890), *got)
}

func TestToInt64PtrFloat64(t *testing.T) {
	got := toInt64Ptr(float64(9214.9))
	require.NotNil(t, got)
	require.Equal(t, int64(9214), *got) // truncation, not rounding
}

func TestToInt64PtrStringNumber(t *testing.T) {
	got := toInt64Ptr("9000")
	require.NotNil(t, got)
	require.Equal(t, int64(9000), *got)
}

func TestToInt64PtrStringInvalid(t *testing.T) {
	require.Nil(t, toInt64Ptr("not-a-number"))
}

func TestToInt64PtrNil(t *testing.T) {
	require.Nil(t, toInt64Ptr(nil))
}

func TestToInt64PtrBoolInvalid(t *testing.T) {
	// bool is not handled by any case → returns nil
	require.Nil(t, toInt64Ptr(true))
}

// ---------------------------------------------------------------------------
// firstNonEmpty additional branches
// ---------------------------------------------------------------------------

func TestFirstNonEmptyAllEmpty(t *testing.T) {
	require.Equal(t, "", firstNonEmpty("", "  ", "\t"))
}

func TestFirstNonEmptyWhitespaceSkipped(t *testing.T) {
	// whitespace-only values must be skipped; the first trimmed non-empty wins
	require.Equal(t, "hello", firstNonEmpty("  ", "\t", "hello"))
}

func TestFirstNonEmptyNoArgs(t *testing.T) {
	require.Equal(t, "", firstNonEmpty())
}

func TestFirstNonEmptyFirstWins(t *testing.T) {
	require.Equal(t, "first", firstNonEmpty("first", "second"))
}
