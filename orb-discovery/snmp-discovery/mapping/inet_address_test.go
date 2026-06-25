package mapping

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodeInetAddressIndex_IPv4(t *testing.T) {
	got, ok := decodeInetAddressIndex([]string{"1", "4", "10", "0", "0", "1"})
	assert.True(t, ok)
	assert.Equal(t, "ipv4:10.0.0.1", got)
}

func TestDecodeInetAddressIndex_IPv6(t *testing.T) {
	// 2001:db8::1 → bytes 32 1 13 184 0 0 0 0 0 0 0 0 0 0 0 1
	suffix := []string{"2", "16", "32", "1", "13", "184", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1"}
	got, ok := decodeInetAddressIndex(suffix)
	assert.True(t, ok)
	assert.Equal(t, "ipv6:2001:db8::1", got)
}

func TestDecodeInetAddressIndex_Scoped_Skipped(t *testing.T) {
	cases := [][]string{
		// ipv4z (header only — never decoded by us)
		{"3", "4", "10", "0", "0", "1"},
		// ipv6z
		{"4", "16", "32", "1", "13", "184", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "1"},
		// dns-form
		{"16", "5", "104", "111", "115", "116", "46"},
	}
	for _, c := range cases {
		_, ok := decodeInetAddressIndex(c)
		assert.False(t, ok, "scoped/dns addrType must be rejected: %v", c)
	}
}

func TestDecodeInetAddressIndex_Malformed(t *testing.T) {
	cases := [][]string{
		{},                                   // empty
		{"1"},                                // no length
		{"1", "5", "10", "0", "0", "1", "1"}, // wrong addrLen for ipv4
		{"2", "16", "32", "1"},               // truncated ipv6
		{"1", "4", "10", "0", "0", "256"},    // byte > 255
		{"99", "4", "10", "0", "0", "1"},     // unknown addrType
		{"1", "4", "10", "0", "0", "x"},      // non-numeric
		{"a", "4", "10", "0", "0", "1"},      // non-numeric addrType
	}
	for _, c := range cases {
		_, ok := decodeInetAddressIndex(c)
		assert.False(t, ok, "malformed input must be rejected: %v", c)
	}
}

func TestDecodeInetAddressIndex_IPv4MappedIPv6_KeepsIPv6Form(t *testing.T) {
	// ::ffff:10.0.0.1  — bytes 0,0,0,0,0,0,0,0,0,0,255,255,10,0,0,1
	suffix := []string{"2", "16", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "255", "255", "10", "0", "0", "1"}
	got, ok := decodeInetAddressIndex(suffix)
	assert.True(t, ok)
	// Must NOT collapse to ipv4: form. RFC 4001 says addrType=2 is
	// canonical IPv6; the dotted-quad rendering would silently
	// reclassify the row as IPv4 in the IPAddressMapper family check.
	assert.Equal(t, "ipv6:::ffff:10.0.0.1", got)
}

func TestStripIndexFamilyPrefix(t *testing.T) {
	assert.Equal(t, "10.0.0.1", stripIndexFamilyPrefix("ipv4:10.0.0.1"))
	assert.Equal(t, "2001:db8::1", stripIndexFamilyPrefix("ipv6:2001:db8::1"))
	assert.Equal(t, "10.0.0.1", stripIndexFamilyPrefix("10.0.0.1")) // legacy passthrough
	assert.Equal(t, "", stripIndexFamilyPrefix(""))
}
