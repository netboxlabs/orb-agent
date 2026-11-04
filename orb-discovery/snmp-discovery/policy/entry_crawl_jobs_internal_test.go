package policy

import (
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
)

// credentialAgents answers by credential: each host accepts the communities
// or SNMPv3 users it lists. An SNMPv3 probe presents no user of the entry's,
// so every SNMPv3 agent answers it. A probe slowed for a host and community
// holds that entry's scan back, so the other entry schedules its crawls first.
type credentialAgents struct {
	accepts map[string][]string
	slow    map[string]string
	mu      sync.Mutex
	crawls  map[string]int
}

func (a *credentialAgents) dial(host string, _ uint16, _ int, timeout time.Duration, auth *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
	v3 := auth.ProtocolVersion == snmp.ProtocolVersion3
	credential := auth.Community
	if v3 {
		credential = auth.Username
	}
	if timeout == time.Second {
		if !v3 && a.slow[host] == credential {
			time.Sleep(600 * time.Millisecond)
		}
		if v3 || slices.Contains(a.accepts[host], credential) {
			return &rowWalker{rows: agentRows(host)}, nil
		}
		return failingWalker{}, nil
	}
	a.mu.Lock()
	a.crawls[host+"/"+credential]++
	a.mu.Unlock()
	if slices.Contains(a.accepts[host], credential) {
		return &rowWalker{rows: agentRows(host)}, nil
	}
	return failingWalker{}, nil
}

func (a *credentialAgents) crawled(host, credential string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.crawls[host+"/"+credential]
}

// One range listed once per community, written identically: each entry
// crawls every host its own probe finds.
func TestIdenticalRangesPerCommunityEachCrawlWhatTheyFind(t *testing.T) {
	agents := &credentialAgents{
		accepts: map[string][]string{"192.0.2.1": {"community-a", "community-b"}, "192.0.2.2": {"community-a"}},
		slow:    map[string]string{"192.0.2.2": "community-b"},
		crawls:  map[string]int{},
	}
	r, _ := newPolicyRunner(t, `
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
        - host: 192.0.2.0/30`+v2cAuth("SNMPv2c", "community-a")+`
        - host: 192.0.2.0/30`+v2cAuth("SNMPv2c", "community-b")+`
`, agents.dial, &recordingClient{}, discardLogger())

	r.Start()
	require.Eventually(t, func() bool {
		return agents.crawled("192.0.2.1", "community-a") > 0 && agents.crawled("192.0.2.1", "community-b") > 0 &&
			agents.crawled("192.0.2.2", "community-a") > 0
	}, 10*time.Second, 10*time.Millisecond, "a host that accepts both communities is crawled by each entry")
	time.Sleep(500 * time.Millisecond)
	require.NoError(t, r.Stop())

	assert.Equal(t, 1, agents.crawled("192.0.2.1", "community-a"))
	assert.Equal(t, 1, agents.crawled("192.0.2.1", "community-b"))
	assert.Equal(t, 1, agents.crawled("192.0.2.2", "community-a"))
	assert.Zero(t, agents.crawled("192.0.2.2", "community-b"), "a host that accepts one community is crawled only by its entry")
}

// v3Entry is an expanded SNMPv3 range of 192.0.2.1 and 192.0.2.2 for user.
func v3Entry(user string) []config.Target {
	auth := &config.Authentication{
		ProtocolVersion: snmp.ProtocolVersion3, SecurityLevel: "authPriv", Username: user,
		AuthProtocol: "SHA", AuthPassphrase: "example-auth-pass", PrivProtocol: "AES", PrivPassphrase: "example-priv-pass",
	}
	return []config.Target{{Host: "192.0.2.1", Port: 161, Authentication: auth}, {Host: "192.0.2.2", Port: 161, Authentication: auth}}
}

// One range listed once per SNMPv3 user, written identically: the probe finds
// every host for each entry, so each entry crawls every host, and the crawl
// with a user the host does not know fails.
func TestIdenticalRangesPerSNMPv3UserEachCrawlEveryHost(t *testing.T) {
	agents := &credentialAgents{
		accepts: map[string][]string{"192.0.2.1": {"user-a", "user-b"}, "192.0.2.2": {"user-a"}},
		crawls:  map[string]int{},
	}
	scheduler := notStartedScheduler(t)
	r := scanRunner(t, scheduler, agents.dial, nil)
	scheduler.Start()

	r.runScanWithOriginal(0, v3Entry("user-a"), "192.0.2.0/30")
	r.runScanWithOriginal(1, v3Entry("user-b"), "192.0.2.0/30")

	require.Eventually(t, func() bool {
		for _, host := range []string{"192.0.2.1", "192.0.2.2"} {
			for _, user := range []string{"user-a", "user-b"} {
				if agents.crawled(host, user) == 0 {
					return false
				}
			}
		}
		return true
	}, 10*time.Second, 10*time.Millisecond, "each entry crawls every host")
	require.Eventually(t, func() bool {
		runs := r.runStore.GetRunsForTarget("p1", "192.0.2.2", 161)
		return len(runs) == 2 && runs[0].Status != RunStatusRunning && runs[1].Status != RunStatusRunning
	}, 10*time.Second, 10*time.Millisecond)
	statuses := map[RunStatus]int{}
	for _, run := range r.runStore.GetRunsForTarget("p1", "192.0.2.2", 161) {
		statuses[run.Status]++
	}
	assert.Equal(t, map[RunStatus]int{RunStatusCompleted: 1, RunStatusFailed: 1}, statuses,
		"the crawl with a user the host does not know fails")
}

// Each entry's re-scan starts no second job for a host it already crawls,
// and no entry's job stands in for another's.
func TestRescanKeepsOneCrawlJobPerEntryAndHost(t *testing.T) {
	agents := &credentialAgents{
		accepts: map[string][]string{"192.0.2.1": {"user-a", "user-b"}, "192.0.2.2": {"user-a", "user-b"}},
		crawls:  map[string]int{},
	}
	schedule := "0 0 1 1 *"
	scheduler := notStartedScheduler(t)
	r := scanRunner(t, scheduler, agents.dial, &schedule)

	for range 2 {
		r.runScanWithOriginal(0, v3Entry("user-a"), "192.0.2.0/30")
		r.runScanWithOriginal(1, v3Entry("user-b"), "192.0.2.0/30")
	}

	assert.Len(t, scheduler.Jobs(), 4, "one per entry and host")
	var keys []string
	for key := range r.activeHostJobs {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	assert.Equal(t, []string{
		fmt.Sprintf("0::192.0.2.0/30::%s:161", "192.0.2.1"), fmt.Sprintf("0::192.0.2.0/30::%s:161", "192.0.2.2"),
		fmt.Sprintf("1::192.0.2.0/30::%s:161", "192.0.2.1"), fmt.Sprintf("1::192.0.2.0/30::%s:161", "192.0.2.2"),
	}, keys)
}

// An entry's scan forgets its own crawl jobs that are gone, and leaves every
// other entry's to that entry's scans.
func TestScanPrunesOnlyItsOwnEntrysJobs(t *testing.T) {
	agents := &credentialAgents{accepts: map[string][]string{}, crawls: map[string]int{}}
	r := scanRunner(t, notStartedScheduler(t), agents.dial, nil)
	own, other := "0::192.0.2.0/30::192.0.2.9:161", "1::192.0.2.0/30::192.0.2.9:161"
	r.activeHostJobs[own] = uuid.New()
	r.activeHostJobs[other] = uuid.New()

	r.runScanWithOriginal(0, nil, "192.0.2.0/30")

	assert.NotContains(t, r.activeHostJobs, own, "entry 1's dead job is forgotten")
	assert.Contains(t, r.activeHostJobs, other, "entry 2's is left to its own scans")
}

// A crawl's lines say which scope entry it came from, counting from 1, so
// crawls of one host by identical entries can be told apart.
func TestCrawlLinesNameTheirEntry(t *testing.T) {
	agents := &credentialAgents{
		accepts: map[string][]string{"192.0.2.1": {"community-a", "community-b"}, "192.0.2.9": {"example-community"}},
		crawls:  map[string]int{},
	}
	logs := &lockedBuffer{}
	r, _ := newPolicyRunner(t, `
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
        - host: 192.0.2.0/30`+v2cAuth("SNMPv2c", "community-a")+`
        - host: 192.0.2.0/30`+v2cAuth("SNMPv2c", "community-b")+`
        - host: 192.0.2.9
`, agents.dial, &recordingClient{}, jsonLogger(logs))

	r.Start()
	require.Eventually(t, func() bool {
		return agents.crawled("192.0.2.1", "community-a") > 0 && agents.crawled("192.0.2.1", "community-b") > 0 &&
			agents.crawled("192.0.2.9", "example-community") > 0
	}, 10*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		complete := 0
		for _, record := range logRecords(t, logs.String()) {
			if record["msg"] == "entities ingested successfully" {
				complete++
			}
		}
		return complete == 3
	}, 10*time.Second, 10*time.Millisecond)
	require.NoError(t, r.Stop())

	entries := map[string][]any{}
	for _, record := range logRecords(t, logs.String()) {
		if record["msg"] != "SNMP crawl complete" {
			continue
		}
		host := record["host"].(string)
		entries[host] = append(entries[host], record["entry"])
	}
	assert.ElementsMatch(t, []any{float64(1), float64(2)}, entries["192.0.2.1"])
	assert.Equal(t, []any{float64(3)}, entries["192.0.2.9"])
}
