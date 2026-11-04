package policy

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// overlapWarning is one warning logged at load: its message and the entries
// it names.
type overlapWarning struct {
	msg, entries any
}

// overlapWarnings loads policy p1 with the given targets and returns the
// warnings logged at load.
func overlapWarnings(t *testing.T, targets string) []overlapWarning {
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
	var warnings []overlapWarning
	for _, record := range recordsAt(t, logs, "WARN") {
		assert.Equal(t, "p1", record["policy"])
		warnings = append(warnings, overlapWarning{record["msg"], record["entries"]})
	}
	return warnings
}

// v2cAuth and v3Auth are a target's authentication, as YAML under the target.
func v2cAuth(version, community string) string {
	return `
          authentication:
            protocol_version: ` + version + `
            community: ` + community
}

func v3Auth(user string) string {
	return `
          authentication:
            protocol_version: SNMPv3
            security_level: authPriv
            username: ` + user + `
            auth_protocol: SHA
            auth_passphrase: example-auth-pass
            priv_protocol: AES
            priv_passphrase: example-priv-pass`
}

const (
	sameCommunityOverlap = "subnets or ranges probe the same hosts with the same version and community; " +
		"each crawls every host that answers"
	v3Overlap = "SNMPv3 subnets or ranges reach the same hosts; SNMPv3 probes do not present the entry's user, " +
		"so each crawls every host that answers, and a crawl with credentials the host does not accept fails; " +
		"list such hosts on entries of their own, or use disjoint ranges"
	hostListedTwice = "a host is listed on several entries; each crawls it, " +
		"and a crawl with credentials the host does not accept fails"
)

// The policy warns at load about entries that crawl the same hosts, and still
// loads.
func TestLoadWarnsAboutOverlappingEntries(t *testing.T) {
	t.Run("overlapping ranges", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{{sameCommunityOverlap, "192.0.2.0/29 with 192.0.2.4-5"}}, overlapWarnings(t, `
        - host: 192.0.2.0/29
        - host: 192.0.2.4-5
`))
	})
	t.Run("ranges sharing one address", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{{sameCommunityOverlap, "192.0.2.1-2 with 192.0.2.2-3"}}, overlapWarnings(t, `
        - host: 192.0.2.1-2
        - host: 192.0.2.2-3
`))
	})
	t.Run("one range written twice", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{{sameCommunityOverlap, "192.0.2.0/24 with 192.0.2.0/24"}},
			overlapWarnings(t, `
        - host: 192.0.2.0/24`+v2cAuth("SNMPv2c", "community-a")+`
        - host: 192.0.2.0/24`+v2cAuth("SNMPv2c", "community-a")+`
`))
	})
	t.Run("one line names a few pairs and counts the rest", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{{
			sameCommunityOverlap,
			"192.0.2.0/30 with 192.0.2.1-2, 192.0.2.0/30 with 192.0.2.1-192.0.2.2, " +
				"192.0.2.1-2 with 192.0.2.1-192.0.2.2, 192.0.2.0/30 with 192.0.2.2-3, 192.0.2.1-2 with 192.0.2.2-3 and 1 more",
		}},
			overlapWarnings(t, `
        - host: 192.0.2.0/30
        - host: 192.0.2.1-2
        - host: 192.0.2.1-192.0.2.2
        - host: 192.0.2.2-3
`))
	})
	t.Run("one host listed twice", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{{hostListedTwice, "192.0.2.9 with 192.0.2.9/32"}}, overlapWarnings(t, `
        - host: 192.0.2.9
        - host: 192.0.2.9/32
`))
	})
	t.Run("an entry without a port is on 161", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{{hostListedTwice, "192.0.2.9 with 192.0.2.9"}}, overlapWarnings(t, `
        - host: 192.0.2.9
        - host: 192.0.2.9
          port: 161
`))
	})
	// A host listed on its own is crawled without a probe, so a second entry
	// for it crawls it too, whatever its community.
	t.Run("one host per community", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{{hostListedTwice, "192.0.2.9 with 192.0.2.9/32"}}, overlapWarnings(t, `
        - host: 192.0.2.9`+v2cAuth("SNMPv2c", "community-a")+`
        - host: 192.0.2.9/32`+v2cAuth("SNMPv2c", "community-b")+`
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

// The SNMPv3 probe presents a placeholder user, so every SNMPv3 entry over a
// host finds it, and the crawls with credentials the host does not accept
// fail.
func TestLoadWarnsAboutSNMPv3EntriesOverTheSameHosts(t *testing.T) {
	t.Run("two users over one range", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{{v3Overlap, "192.0.2.0/30 with 192.0.2.1-2"}}, overlapWarnings(t, `
        - host: 192.0.2.0/30`+v3Auth("user-a")+`
        - host: 192.0.2.1-2`+v3Auth("user-b")+`
`))
	})
	t.Run("two users over one range written twice", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{{v3Overlap, "192.0.2.0/30 with 192.0.2.0/30"}}, overlapWarnings(t, `
        - host: 192.0.2.0/30`+v3Auth("user-a")+`
        - host: 192.0.2.0/30`+v3Auth("user-b")+`
`))
	})
	t.Run("one per kind, each on its own line", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{
			{hostListedTwice, "192.0.2.9 with 192.0.2.9/32"},
			{sameCommunityOverlap, "192.0.2.16-17 with 192.0.2.17-18"},
			{v3Overlap, "192.0.2.0/30 with 192.0.2.1-2"},
		}, overlapWarnings(t, `
        - host: 192.0.2.0/30`+v3Auth("user-a")+`
        - host: 192.0.2.1-2`+v3Auth("user-b")+`
        - host: 192.0.2.16-17
        - host: 192.0.2.17-18
        - host: 192.0.2.9
        - host: 192.0.2.9/32
`))
	})
}

// With SNMPv1 and SNMPv2c the probe sends each entry's own community, so a
// host is found only by the entries whose community it accepts: listing a
// range once per community is how it is scanned with several, and such
// entries are not warned about.
func TestLoadDoesNotWarnAboutOneRangePerCommunity(t *testing.T) {
	t.Run("one /24 per community", func(t *testing.T) {
		require.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.0/24`+v2cAuth("SNMPv2c", "community-a")+`
        - host: 192.0.2.0/24`+v2cAuth("SNMPv2c", "community-b")+`
        - host: 192.0.2.0/24`+v2cAuth("SNMPv2c", "community-c")+`
`))
	})
	t.Run("one /24 per protocol version", func(t *testing.T) {
		require.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.0/24`+v2cAuth("SNMPv1", "community-a")+`
        - host: 192.0.2.0/24`+v2cAuth("SNMPv2c", "community-a")+`
        - host: 192.0.2.0/24`+v3Auth("user-a")+`
`))
	})
}

const differentDefaults = "scope entries with different override_defaults reach the same hosts; " +
	"a host that answers several of these entries is sent with each entry's defaults in turn; " +
	"give such a host an entry of its own"

// Each entry sends a host it crawls with its own override_defaults, so a host
// two entries crawl flips between them every cycle, whatever the credentials.
func TestLoadWarnsAboutOverlappingEntriesWithDifferentDefaults(t *testing.T) {
	site := func(name string) string {
		return `
          override_defaults:
            site: ` + name
	}
	t.Run("one range per community, each with its own site", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{{differentDefaults, "192.0.2.0/30 with 192.0.2.0/30"}}, overlapWarnings(t, `
        - host: 192.0.2.0/30`+v2cAuth("SNMPv2c", "community-a")+site("site-a")+`
        - host: 192.0.2.0/30`+v2cAuth("SNMPv2c", "community-b")+site("site-b")+`
`))
	})
	t.Run("one range with defaults over another without", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{{differentDefaults, "192.0.2.0/29 with 192.0.2.4-5"}}, overlapWarnings(t, `
        - host: 192.0.2.0/29`+v3Auth("user-a")+`
        - host: 192.0.2.4-5`+v2cAuth("SNMPv2c", "community-b")+site("site-b")+`
`))
	})
	t.Run("one host listed twice, each with its own site", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{
			{hostListedTwice, "192.0.2.9 with 192.0.2.9/32"},
			{differentDefaults, "192.0.2.9 with 192.0.2.9/32"},
		}, overlapWarnings(t, `
        - host: 192.0.2.9`+site("site-a")+`
        - host: 192.0.2.9/32`+site("site-b")+`
`))
	})
	t.Run("the same defaults", func(t *testing.T) {
		assert.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.0/30`+v2cAuth("SNMPv2c", "community-a")+site("site-a")+`
        - host: 192.0.2.0/30`+v2cAuth("SNMPv2c", "community-b")+site("site-a")+`
`))
	})
	t.Run("no defaults", func(t *testing.T) {
		assert.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.0/30`+v2cAuth("SNMPv2c", "community-a")+`
        - host: 192.0.2.0/30`+v2cAuth("SNMPv2c", "community-b")+`
`))
	})
	t.Run("an override that changes nothing", func(t *testing.T) {
		assert.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.0/30`+v2cAuth("SNMPv2c", "community-a")+`
        - host: 192.0.2.0/30`+v2cAuth("SNMPv2c", "community-b")+site("undefined")+`
`))
	})
	t.Run("disjoint ranges, or another port", func(t *testing.T) {
		assert.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.0/30`+site("site-a")+`
        - host: 192.0.2.4-5`+site("site-b")+`
        - host: 192.0.2.0/30
          port: 1161`+site("site-c")+`
`))
	})
	// A host listed on its own is taken out of the range, so only its own
	// entry's defaults reach it.
	t.Run("a range and a host listed on its own", func(t *testing.T) {
		assert.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.0/30`+site("site-a")+`
        - host: 192.0.2.1`+site("site-b")+`
`))
	})
}

// Hosts listed on their own leave every range, so ranges that share only
// such hosts no longer reach the same hosts, and are not warned about.
func TestOverlapIsJudgedAfterListedHostsLeaveTheRanges(t *testing.T) {
	site := func(name string) string {
		return `
          override_defaults:
            site: ` + name
	}
	t.Run("ranges that share only a listed host", func(t *testing.T) {
		assert.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.1-2`+v2cAuth("SNMPv2c", "community-a")+site("site-a")+`
        - host: 192.0.2.2-3`+v2cAuth("SNMPv2c", "community-b")+site("site-b")+`
        - host: 192.0.2.2`+site("site-c")+`
`))
	})
	t.Run("same community, sharing only listed hosts", func(t *testing.T) {
		assert.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.1-3
        - host: 192.0.2.2-4
        - host: 192.0.2.2
        - host: 192.0.2.3/32
`))
	})
	t.Run("SNMPv3, sharing only a listed host", func(t *testing.T) {
		assert.Empty(t, overlapWarnings(t, `
        - host: 192.0.2.1-2`+v3Auth("user-a")+`
        - host: 192.0.2.2-3`+v3Auth("user-b")+`
        - host: 192.0.2.2
`))
	})
	t.Run("ranges that still share a host", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{
			{sameCommunityOverlap, "192.0.2.1-3 with 192.0.2.2-4"},
			{differentDefaults, "192.0.2.1-3 with 192.0.2.2-4"},
		}, overlapWarnings(t, `
        - host: 192.0.2.1-3`+site("site-a")+`
        - host: 192.0.2.2-4`+site("site-b")+`
        - host: 192.0.2.2
`))
	})
	t.Run("a host listed on another port stays in the ranges", func(t *testing.T) {
		assert.Equal(t, []overlapWarning{{sameCommunityOverlap, "192.0.2.1-2 with 192.0.2.2-3"}}, overlapWarnings(t, `
        - host: 192.0.2.1-2
        - host: 192.0.2.2-3
        - host: 192.0.2.2
          port: 1161
`))
	})
}

// An overlap warning keeps the pairs it names, not every pair: a policy with
// thousands of overlapping entries holds five strings and a count.
func TestOverlapsKeepOnlyThePairsNamed(t *testing.T) {
	var o overlaps
	for i := range maxOverlapsNamed + 3 {
		o.add(fmt.Sprintf("192.0.2.%d", i), "192.0.2.0/24")
	}
	assert.Len(t, o.named, maxOverlapsNamed)
	assert.Equal(t, maxOverlapsNamed+3, o.count)
}
