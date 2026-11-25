package pktvisor_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/backend/pktvisor"
)

// pktvisor reports a refusal for an address in use, which pktvisord answers
// for a flow or dnstap listener that overlaps one already running, as one
// another policy causes, so the policy manager applies the policy again once
// a policy is removed. It reports no other refusal that way.
func TestRetryAfterRemovalIsForAnAddressInUse(t *testing.T) {
	require.True(t, pktvisor.Register())
	retrier, ok := backend.GetBackend("pktvisor").(backend.RemovalRetrier)
	require.True(t, ok, "pktvisor is a backend.RemovalRetrier")
	for reason, want := range map[string]bool{
		"409 policy [netflow] failed to start: unable to bind flow UDP server on 0.0.0.0:6343: address already in use":    true,
		"409 policy [dns] failed to start: unable to listen with dnstap server on 127.0.0.1:6000: Address already in use": true,
		"409 module name 'netflow-edge_pcap-net_summary' already exists":                                                  false,
		"422 invalid flow config": false,
		"backend starting":        false,
	} {
		assert.Equal(t, want, retrier.RetryAfterRemoval(reason), reason)
	}
}
