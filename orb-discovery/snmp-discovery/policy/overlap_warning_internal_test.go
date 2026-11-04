package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// overlapWarnings loads policy p1 with the given targets and returns the
// entries named by each warning logged at load.
func overlapWarnings(t *testing.T, targets string) []any {
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
	var named []any
	for _, record := range logRecords(t, logs.String()) {
		if record["level"] == "WARN" {
			assert.Equal(t, "p1", record["policy"])
			assert.Equal(t, "scope entries with the same authentication reach the same hosts; "+
				"a host that answers both entries is discovered by each", record["msg"])
			named = append(named, record["entries"])
		}
	}
	return named
}

// The policy warns once at load about entries with the same authentication
// that reach the same hosts, and still loads.
func TestLoadWarnsAboutOverlappingEntries(t *testing.T) {
	t.Run("overlapping ranges", func(t *testing.T) {
		assert.Equal(t, []any{"192.0.2.0/29 with 192.0.2.4-5"}, overlapWarnings(t, `
        - host: 192.0.2.0/29
        - host: 192.0.2.4-5
`))
	})
	t.Run("ranges sharing one address", func(t *testing.T) {
		assert.Equal(t, []any{"192.0.2.1-2 with 192.0.2.2-3"}, overlapWarnings(t, `
        - host: 192.0.2.1-2
        - host: 192.0.2.2-3
`))
	})
	t.Run("one host listed twice", func(t *testing.T) {
		assert.Equal(t, []any{"192.0.2.9 with 192.0.2.9/32"}, overlapWarnings(t, `
        - host: 192.0.2.9
        - host: 192.0.2.9/32
`))
	})
	t.Run("an entry without a port is on 161", func(t *testing.T) {
		assert.Equal(t, []any{"192.0.2.9 with 192.0.2.9"}, overlapWarnings(t, `
        - host: 192.0.2.9
        - host: 192.0.2.9
          port: 161
`))
	})
	t.Run("one range twice with the same community", func(t *testing.T) {
		assert.Equal(t, []any{"192.0.2.0/24 with 192.0.2.0/24"}, overlapWarnings(t, `
        - host: 192.0.2.0/24
          authentication:
            protocol_version: SNMPv2c
            community: community-a
        - host: 192.0.2.0/24
          authentication:
            protocol_version: SNMPv2c
            community: community-a
`))
	})
	t.Run("one line names a few pairs and counts the rest", func(t *testing.T) {
		assert.Equal(t, []any{"192.0.2.0/30 with 192.0.2.1-2, 192.0.2.0/30 with 192.0.2.1-192.0.2.2, " +
			"192.0.2.1-2 with 192.0.2.1-192.0.2.2, 192.0.2.0/30 with 192.0.2.2-3, 192.0.2.1-2 with 192.0.2.2-3 and 1 more"},
			overlapWarnings(t, `
        - host: 192.0.2.0/30
        - host: 192.0.2.1-2
        - host: 192.0.2.1-192.0.2.2
        - host: 192.0.2.2-3
`))
	})
	t.Run("disjoint entries", func(t *testing.T) {
		assert.Empty(t, overlapWarnings(t, `
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

// Listing a range once per credential is how a range is scanned with several:
// each entry probes with its own, so a host is found only by the entries
// whose credentials it accepts. Such entries are not warned about.
func TestLoadDoesNotWarnAboutOneRangePerCredential(t *testing.T) {
	t.Run("one /24 per community", func(t *testing.T) {
		require.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.0/24
          authentication:
            protocol_version: SNMPv2c
            community: community-a
        - host: 192.0.2.0/24
          authentication:
            protocol_version: SNMPv2c
            community: community-b
        - host: 192.0.2.0/24
          authentication:
            protocol_version: SNMPv2c
            community: community-c
`))
	})
	t.Run("one /24 on the policy's credentials and one on its own", func(t *testing.T) {
		require.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.0/24
        - host: 192.0.2.0/24
          authentication:
            protocol_version: SNMPv3
            security_level: authPriv
            username: example-user
            auth_protocol: SHA
            auth_passphrase: example-auth-pass
            priv_protocol: AES
            priv_passphrase: example-priv-pass
`))
	})
	t.Run("one host per community", func(t *testing.T) {
		require.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.9
          authentication:
            protocol_version: SNMPv2c
            community: community-a
        - host: 192.0.2.9/32
          authentication:
            protocol_version: SNMPv2c
            community: community-b
`))
	})
}
