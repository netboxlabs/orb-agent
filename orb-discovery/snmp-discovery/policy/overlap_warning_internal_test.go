package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The policy warns at load about entries that reach the same hosts, and
// still loads.
func TestLoadWarnsAboutOverlappingEntries(t *testing.T) {
	warnings := func(t *testing.T, targets string) [][2]any {
		t.Helper()
		logs := &lockedBuffer{}
		newPolicyRunner(t, `
policies:
  p1:
    config:
      timeout: 10
      snmp_timeout: 3
      snmp_probe_timeout: 1
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: example-community
      targets:
`+targets, newFakeAgents(time.Second).dial, &recordingClient{}, jsonLogger(logs))
		var named [][2]any
		for _, record := range logRecords(t, logs.String()) {
			if record["level"] == "WARN" {
				assert.Equal(t, "p1", record["policy"])
				named = append(named, [2]any{record["target"], record["other_target"]})
			}
		}
		return named
	}

	t.Run("overlapping ranges", func(t *testing.T) {
		assert.Equal(t, [][2]any{{"192.0.2.4-5", "192.0.2.0/29"}}, warnings(t, `
        - host: 192.0.2.0/29
        - host: 192.0.2.4-5
`))
	})
	t.Run("ranges sharing one address", func(t *testing.T) {
		assert.Equal(t, [][2]any{{"192.0.2.2-3", "192.0.2.1-2"}}, warnings(t, `
        - host: 192.0.2.1-2
        - host: 192.0.2.2-3
`))
	})
	t.Run("one host listed twice", func(t *testing.T) {
		assert.Equal(t, [][2]any{{"192.0.2.9/32", "192.0.2.9"}}, warnings(t, `
        - host: 192.0.2.9
        - host: 192.0.2.9/32
`))
	})
	t.Run("an entry without a port is on 161", func(t *testing.T) {
		assert.Equal(t, [][2]any{{"192.0.2.9", "192.0.2.9"}}, warnings(t, `
        - host: 192.0.2.9
        - host: 192.0.2.9
          port: 161
`))
	})
	t.Run("disjoint entries", func(t *testing.T) {
		assert.Empty(t, warnings(t, `
        - host: 192.0.2.0/30
        - host: 192.0.2.4-5
        - host: 192.0.2.6-7
          port: 1161
        - host: 192.0.2.6-7
        - host: 192.0.2.9
        - host: 192.0.2.9
          port: 1161
        - host: 192.0.2.1
`))
	})
}
