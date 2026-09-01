package targets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countableShapes lists every input shape Expand accepts or rejects, sized
// small enough to expand in a test. A new shape belongs here so Count is held
// to Expand rather than assumed to agree with it.
var countableShapes = []struct {
	name   string
	target string
}{
	{"bare IPv4", "192.0.2.1"},
	{"bare IPv6", "2001:db8::1"},
	{"IPv4 CIDR", "192.0.2.0/24"},
	{"IPv4 CIDR with host bits set", "192.0.2.5/24"},
	{"single address CIDR", "192.0.2.1/32"},
	{"IPv6 CIDR", "2001:db8::/32"},
	{"prefix length out of range", "192.0.2.0/33"},
	{"last octet range", "192.0.2.10-20"},
	{"last octet range, CIDR suffix on base", "192.0.2.0/24-20"},
	{"last octet range, CIDR suffix on end", "192.0.2.0-20/24"},
	{"full range", "192.0.2.0-192.0.2.9"},
	{"full range, CIDR suffix on both ends", "192.0.2.0/24-192.0.3.0/24"},
	{"full range, CIDR suffix on one end", "192.0.2.0-192.0.3.0/24"},
	{"reversed full range", "192.0.2.9-192.0.2.0"},
	{"reversed last octet range", "192.0.2.9-0"},
	{"three range parts", "192.0.2.0-192.0.2.5-192.0.2.9"},
	{"IPv6 range", "2001:db8::1-2001:db8::5"},
	{"last octet above 255", "192.0.2.0-999"},
	{"invalid octet in base", "192.0.2.256-192.0.2.255"},
	{"hostname", "router.example.com"},
	{"hostname with hyphen", "switch-01.example.com"},
	{"bare hyphenated hostname", "host-1"},
	{"hostname with colon", "device:161"},
	{"empty target", ""},
	{"non-target text", "not a target"},
	{"range padded with spaces", " 192.0.2.1 - 192.0.2.5 "},
	{"trailing hyphen", "192.0.2.0-"},
	{"leading hyphen", "-192.0.2.5"},
}

// Count and Expand must never disagree about a target: the guard that bounds a
// policy target is built on Count, and a shape the two read differently walks
// straight past it.
func TestCountAgreesWithExpand(t *testing.T) {
	for _, shape := range countableShapes {
		t.Run(shape.name, func(t *testing.T) {
			count, countErr := Count(shape.target)
			addrs, expandErr := Expand(shape.target)

			if expandErr != nil {
				require.Error(t, countErr, "Expand rejected %q but Count accepted it", shape.target)
				assert.Equal(t, expandErr.Error(), countErr.Error())
				assert.Zero(t, count)
				return
			}

			require.NoError(t, countErr, "Expand accepted %q but Count rejected it", shape.target)
			assert.Equal(t, uint64(len(addrs)), count)
		})
	}
}

// Targets too large to expand in a test, which are the ones the count exists
// for. The expected values are derived by hand from the notation: a prefix
// holds two fewer hosts than the addresses it spans, because the network and
// broadcast addresses are not polled, while a range holds every address it
// names.
func TestCountLargeTargets(t *testing.T) {
	cases := []struct {
		target string
		want   uint64
	}{
		{"10.0.0.0/16", 65534},
		{"10.0.0.0/15", 131070},
		{"10.0.0.0/8", 16777214},
		{"0.0.0.0/0", 4294967294},
		{"10.0.0.0-10.255.255.255", 16777216},
		{"10.0.0.0/8-10.1.0.0/8", 65537},
		{"0.0.0.0-255.255.255.255", 4294967296},
	}
	for _, tc := range cases {
		count, err := Count(tc.target)
		require.NoError(t, err, "target %s", tc.target)
		assert.Equal(t, tc.want, count, "target %s", tc.target)
	}
}

// Count feeds the pre-allocation budget guard, which is only trustworthy while
// it reports exactly what Expand returns. Narrowing the expander alone would
// charge every CIDR two addresses it never polls, which is precisely the drift
// this file exists to prevent, so the pinned table is held against both.
func TestCountMatchesThePinnedTable(t *testing.T) {
	for _, tc := range pinnedExpansions {
		t.Run(tc.name, func(t *testing.T) {
			count, err := Count(tc.target)
			require.NoError(t, err)
			assert.Equal(t, uint64(tc.count), count, "Count(%s)", tc.target)

			addrs, err := Expand(tc.target)
			require.NoError(t, err)
			assert.Equal(t, uint64(len(addrs)), count, "Count and Expand disagree about %s", tc.target)
		})
	}
}
