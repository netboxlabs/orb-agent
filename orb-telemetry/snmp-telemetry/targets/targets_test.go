package targets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpand_SingleIP(t *testing.T) {
	ips, err := Expand("192.168.1.1")
	require.NoError(t, err)
	assert.Equal(t, []string{"192.168.1.1"}, ips)
}

func TestExpand_Hostname(t *testing.T) {
	ips, err := Expand("example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"example.com"}, ips)
}

func TestExpand_HostnameWithHyphen(t *testing.T) {
	ips, err := Expand("my-router.example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"my-router.example.com"}, ips)
}

// A /30 covers four addresses and holds two hosts: the network address and the
// broadcast address are not polled.
func TestExpand_CIDR_Slash30(t *testing.T) {
	ips, err := Expand("10.0.0.0/30")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, ips)
}

func TestExpand_CIDR_Slash32(t *testing.T) {
	ips, err := Expand("10.0.0.5/32")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.5"}, ips)
}

func TestExpand_CIDR_InvalidFormat(t *testing.T) {
	_, err := Expand("999.0.0.0/24")
	assert.Error(t, err)
}

func TestExpand_CIDR_IPv6Rejected(t *testing.T) {
	_, err := Expand("2001:db8::/32")
	assert.Error(t, err)
}

func TestExpand_LastOctetRange(t *testing.T) {
	ips, err := Expand("10.0.0.5-7")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.5", "10.0.0.6", "10.0.0.7"}, ips)
}

func TestExpand_LastOctetRange_Single(t *testing.T) {
	ips, err := Expand("10.0.0.10-10")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.10"}, ips)
}

func TestExpand_LastOctetRange_EndBeforeStart(t *testing.T) {
	_, err := Expand("10.0.0.10-5")
	assert.Error(t, err)
}

func TestExpand_FullIPRange(t *testing.T) {
	ips, err := Expand("10.0.0.1-10.0.0.3")
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, ips)
}

func TestExpand_FullIPRange_EndBeforeStart(t *testing.T) {
	_, err := Expand("10.0.0.10-10.0.0.5")
	assert.Error(t, err)
}

func TestExpand_FullIPRange_SameStartEnd(t *testing.T) {
	ips, err := Expand("192.168.0.1-192.168.0.1")
	require.NoError(t, err)
	assert.Equal(t, []string{"192.168.0.1"}, ips)
}

// pinnedExpansions is the agreed expansion table.
//
// A CIDR prefix names a subnet, so its network and broadcast addresses are not
// hosts and are excluded for a /30 and wider. A /31 is a point-to-point link
// under RFC 3021 and a /32 is a single host, so neither has a pair to exclude
// and both keep every address they cover.
//
// The range row is a deliberate divergence rather than an oversight: a range
// keeps every address the operator wrote, including a .0 and a .255, because
// they enumerated it explicitly. 192.168.1.0-255 yields 256 where
// 192.168.1.0/24 yields 254, and the two forms are not meant to agree.
var pinnedExpansions = []struct {
	name   string
	target string
	count  int
	first  string
	last   string
}{
	{"slash 24 excludes network and broadcast", "192.168.1.0/24", 254, "192.168.1.1", "192.168.1.254"},
	{"slash 30 excludes network and broadcast", "192.168.1.0/30", 2, "192.168.1.1", "192.168.1.2"},
	{"slash 31 keeps both point-to-point addresses", "192.168.1.0/31", 2, "192.168.1.0", "192.168.1.1"},
	{"slash 32 keeps the single host", "192.168.1.1/32", 1, "192.168.1.1", "192.168.1.1"},
	{"range keeps every address written", "192.168.1.0-255", 256, "192.168.1.0", "192.168.1.255"},
}

func TestExpand_PinnedTable(t *testing.T) {
	for _, tc := range pinnedExpansions {
		t.Run(tc.name, func(t *testing.T) {
			ips, err := Expand(tc.target)
			require.NoError(t, err)
			require.Len(t, ips, tc.count, "target %s", tc.target)
			assert.Equal(t, tc.first, ips[0], "first address of %s", tc.target)
			assert.Equal(t, tc.last, ips[len(ips)-1], "last address of %s", tc.target)
		})
	}
}

// A poll aimed at a broadcast address is not a wasted probe. The request is
// delivered to every host on the segment, so a credentialed poll hands the
// community string to all of them at once rather than to the one address the
// operator meant to reach.
func TestExpand_CIDRExcludesNetworkAndBroadcastAddresses(t *testing.T) {
	ips, err := Expand("192.168.1.0/24")
	require.NoError(t, err)
	assert.NotContains(t, ips, "192.168.1.0", "the network address is not a host")
	assert.NotContains(t, ips, "192.168.1.255", "polling the broadcast address leaks the credential to the segment")
}

// The CIDR form and the range form disagree on purpose, and this pins that
// divergence so a later reader does not make them consistent. A prefix names a
// subnet, whose network and broadcast addresses are not hosts. A range names
// addresses one by one, so someone who wrote 192.168.1.0-255 meant the .0 and
// the .255 as well.
func TestExpand_RangeKeepsWhatTheCIDRDrops(t *testing.T) {
	viaRange, err := Expand("192.168.1.0-255")
	require.NoError(t, err)
	viaCIDR, err := Expand("192.168.1.0/24")
	require.NoError(t, err)

	assert.Contains(t, viaRange, "192.168.1.0", "a range keeps the address the operator enumerated")
	assert.Contains(t, viaRange, "192.168.1.255", "a range keeps the address the operator enumerated")
	assert.NotContains(t, viaCIDR, "192.168.1.0")
	assert.NotContains(t, viaCIDR, "192.168.1.255")
	assert.Len(t, viaRange, len(viaCIDR)+2, "the range covers the same span plus the two addresses a prefix excludes")
}
