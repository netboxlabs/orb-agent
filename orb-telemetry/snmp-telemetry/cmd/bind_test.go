package main

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The policy API has no authentication, so whatever it binds by default is
// reachable by anyone who can route to it. Resolve the default rather than
// comparing the string: a name is only safe here when every address behind it
// is a loopback address.
func TestDefaultHostBindsLoopbackOnly(t *testing.T) {
	if ip := net.ParseIP(defaultHost); ip != nil {
		assert.True(t, ip.IsLoopback(), "default host %s is not a loopback address", defaultHost)
		return
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), defaultHost)
	require.NoError(t, err)
	require.NotEmpty(t, addrs)
	for _, addr := range addrs {
		assert.True(t, addr.IP.IsLoopback(), "default host %s resolves to non-loopback %s", defaultHost, addr.IP)
	}
}

// The allowlist flag is one string, so the split is what decides which names a
// policy may read. A stray space or trailing comma must not become a name, and
// must not silently widen or narrow the list.
func TestSplitList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty allows nothing", in: "", want: nil},
		{name: "single name", in: "SNMP_COMMUNITY", want: []string{"SNMP_COMMUNITY"}},
		{name: "spaces are trimmed", in: " SNMP_COMMUNITY , SNMP_AUTH_PASS ", want: []string{"SNMP_COMMUNITY", "SNMP_AUTH_PASS"}},
		{name: "empty entries are dropped", in: ",SNMP_COMMUNITY,,", want: []string{"SNMP_COMMUNITY"}},
		{name: "separators only", in: " , ", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, splitList(tt.in))
		})
	}
}
