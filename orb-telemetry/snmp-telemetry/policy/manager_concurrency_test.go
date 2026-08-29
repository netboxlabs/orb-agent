package policy

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// The orb agent polls GET /status on a timer while pushing policy updates, so
// gin serves StartPolicy, StopPolicy and GetPolicyStatuses from concurrent
// request goroutines. An unguarded policies map turns that overlap into
// "fatal error: concurrent map read and map write", which no recover can catch.
func TestManagerPolicyMapIsConcurrencySafe(t *testing.T) {
	m := newTestManager()
	interval := 3600

	policyFor := func(host string) config.Policy {
		return config.Policy{
			Config: config.PolicyConfig{MetricsInterval: &interval},
			Scope: config.Scope{
				Authentication: v2cAuth(),
				Targets:        []config.Target{{Host: host, Port: 161}},
			},
		}
	}

	// Warm the shared collector so the goroutines below contend on the policies
	// map rather than serialising on the profile load.
	require.NoError(t, m.StartPolicy("warmup", policyFor("192.0.2.1")))
	require.NoError(t, m.StopPolicy("warmup"))

	const workers = 8
	const rounds = 40
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := range rounds {
				name := fmt.Sprintf("policy-%d-%d", w, r)
				_ = m.StartPolicy(name, policyFor("192.0.2.1"))
				m.HasPolicy(name)
				_ = m.StopPolicy(name)
			}
		}(w)
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range rounds * 4 {
				m.GetPolicyStatuses()
			}
		}()
	}
	wg.Wait()

	require.NoError(t, m.Stop())
	require.Empty(t, m.GetPolicyStatuses())
}
