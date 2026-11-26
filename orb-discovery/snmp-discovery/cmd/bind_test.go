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
