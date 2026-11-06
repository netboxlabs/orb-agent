package policy

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// A host a policy lists on its own is left out of a range of the same
// policy: it is crawled once, with its own entry's settings, and never probed
// with the range's.
func TestOwnEntryWinsOverRange(t *testing.T) {
	agents := newFakeAgents(time.Second)
	client := &recordingClient{}
	r, store := newPolicyRunner(t, `
policies:
  p1:
    config:
      timeout: 10
      snmp_timeout: 3
      snmp_probe_timeout: 1
      defaults:
        site: policy-site
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: example-community
      targets:
        - host: 192.0.2.0/30
          override_defaults:
            site: range-site
        - host: 192.0.2.1
          override_defaults:
            site: single-site
`, agents.dial, client, discardLogger())

	r.Start()
	require.Eventually(t, func() bool {
		return len(client.devicesOf("192.0.2.1")) > 0 && len(client.devicesOf("192.0.2.2")) > 0
	}, 10*time.Second, 20*time.Millisecond)
	// A copy of 192.0.2.1 from the range would be crawled alongside 192.0.2.2.
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, r.Stop())

	assert.Zero(t, agents.probeCount("192.0.2.1", 161), "the range never probes the listed host")
	assert.Equal(t, 1, agents.crawlCount("192.0.2.1", 161))
	listed := client.devicesOf("192.0.2.1")
	require.Len(t, listed, 1, "one ingest for the listed host")
	assert.Equal(t, "single-site", listed[0].GetSite().GetName())
	runs := store.GetRunsForTarget("p1", "192.0.2.1", 161)
	require.Len(t, runs, 1)
	assert.Empty(t, runs[0].Metadata["parent_target"], "the run is the host's own entry's")

	// The range, down to one address, still probes it before crawling it.
	assert.Equal(t, 1, agents.probeCount("192.0.2.2", 161))
	scanned := client.devicesOf("192.0.2.2")
	require.Len(t, scanned, 1)
	assert.Equal(t, "range-site", scanned[0].GetSite().GetName())
}

// A host listed on its own with netbox_id and emit_device_name: false is sent
// once, matched by its netbox_id, with no named copy from the range.
func TestOwnEntryKeepsNetboxIDInsideRange(t *testing.T) {
	agents := newFakeAgents(time.Second)
	client := &recordingClient{}
	r, _ := newPolicyRunner(t, `
policies:
  p1:
    config:
      timeout: 10
      snmp_timeout: 3
      snmp_probe_timeout: 1
      options:
        emit_device_name: false
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: example-community
      targets:
        - host: 192.0.2.0/30
        - host: 192.0.2.1
          netbox_id: 42
`, agents.dial, client, discardLogger())

	r.Start()
	require.Eventually(t, func() bool {
		return len(client.devicesOf("192.0.2.1")) > 0 && len(client.devicesOf("192.0.2.2")) > 0
	}, 10*time.Second, 20*time.Millisecond)
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, r.Stop())

	listed := client.devicesOf("192.0.2.1")
	require.Len(t, listed, 1)
	assert.Nil(t, listed[0].Name, "the name is suppressed")
	assert.Equal(t, diode.Metadata{"netbox_id": 42}, listed[0].Metadata["source_match"])
}

func TestLeaveOutOwnEntries(t *testing.T) {
	type group struct {
		original string
		hosts    []string
		several  bool
	}
	tests := []struct {
		name    string
		targets []config.Target
		want    []group
	}{
		{
			name:    "a range leaves out a host listed on its own",
			targets: []config.Target{{Host: "192.0.2.0/30", Port: 161}, {Host: "192.0.2.1", Port: 161}},
			want: []group{
				{"192.0.2.0/30", []string{"192.0.2.2"}, true},
				{"192.0.2.1", []string{"192.0.2.1"}, false},
			},
		},
		{
			name:    "the same address on another port stays in the range",
			targets: []config.Target{{Host: "192.0.2.0/30", Port: 1161}, {Host: "192.0.2.1", Port: 161}},
			want: []group{
				{"192.0.2.0/30", []string{"192.0.2.1", "192.0.2.2"}, true},
				{"192.0.2.1", []string{"192.0.2.1"}, false},
			},
		},
		{
			name:    "an entry without a port matches a range on 161",
			targets: []config.Target{{Host: "192.0.2.0/30", Port: 161}, {Host: "192.0.2.1"}},
			want: []group{
				{"192.0.2.0/30", []string{"192.0.2.2"}, true},
				{"192.0.2.1", []string{"192.0.2.1"}, false},
			},
		},
		{
			name:    "a /32 does not leave itself out",
			targets: []config.Target{{Host: "192.0.2.1/32", Port: 161}},
			want:    []group{{"192.0.2.1/32", []string{"192.0.2.1"}, false}},
		},
		{
			name:    "a /32 and a one-address range are listed hosts",
			targets: []config.Target{{Host: "192.0.2.1-4", Port: 161}, {Host: "192.0.2.1/32", Port: 161}, {Host: "192.0.2.2-192.0.2.2", Port: 161}},
			want: []group{
				{"192.0.2.1-4", []string{"192.0.2.3", "192.0.2.4"}, true},
				{"192.0.2.1/32", []string{"192.0.2.1"}, false},
				{"192.0.2.2-192.0.2.2", []string{"192.0.2.2"}, false},
			},
		},
		{
			name:    "a range down to one address is still a range",
			targets: []config.Target{{Host: "192.0.2.1-2", Port: 161}, {Host: "192.0.2.1", Port: 161}},
			want: []group{
				{"192.0.2.1-2", []string{"192.0.2.2"}, true},
				{"192.0.2.1", []string{"192.0.2.1"}, false},
			},
		},
		{
			name:    "a range its listed hosts cover is dropped",
			targets: []config.Target{{Host: "192.0.2.1-2", Port: 161}, {Host: "192.0.2.1", Port: 161}, {Host: "192.0.2.2", Port: 161}},
			want: []group{
				{"192.0.2.1", []string{"192.0.2.1"}, false},
				{"192.0.2.2", []string{"192.0.2.2"}, false},
			},
		},
		{
			name:    "overlapping ranges are left alone",
			targets: []config.Target{{Host: "192.0.2.0/29", Port: 161}, {Host: "192.0.2.4-5", Port: 161}},
			want: []group{
				{"192.0.2.0/29", []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"}, true},
				{"192.0.2.4-5", []string{"192.0.2.4", "192.0.2.5"}, true},
			},
		},
		{
			name:    "a hostname is not matched against range addresses",
			targets: []config.Target{{Host: "192.0.2.0/30", Port: 161}, {Host: "sw1.example.net", Port: 161}},
			want: []group{
				{"192.0.2.0/30", []string{"192.0.2.1", "192.0.2.2"}, true},
				{"sw1.example.net", []string{"sw1.example.net"}, false},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Runner{
				ctx:    context.WithValue(context.Background(), policyKey, "p1"),
				logger: discardLogger(),
				scope:  config.Scope{Targets: tt.targets},
			}
			var got []group
			for _, g := range r.leaveOutOwnEntries(r.expandTargetRanges(tt.targets)) {
				hosts := make([]string, 0, len(g.targets))
				for _, target := range g.targets {
					hosts = append(hosts, target.Host)
				}
				got = append(got, group{g.originalTarget, hosts, g.several})
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

// One line per range names the first ten hosts it leaves out and counts the
// rest.
func TestLeaveOutOwnEntriesLogsOneLinePerRange(t *testing.T) {
	targets := []config.Target{{Host: "192.0.2.0/28", Port: 161}, {Host: "192.0.2.16-18", Port: 161}}
	for i := 1; i <= 12; i++ {
		targets = append(targets, config.Target{Host: "192.0.2." + strconv.Itoa(i), Port: 161})
	}
	targets = append(targets, config.Target{Host: "192.0.2.17", Port: 161})
	logs := &lockedBuffer{}
	r := &Runner{
		ctx:    context.WithValue(context.Background(), policyKey, "p1"),
		logger: slogText(logs),
		scope:  config.Scope{Targets: targets},
	}
	r.leaveOutOwnEntries(r.expandTargetRanges(targets))

	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if strings.Contains(line, "Leaving out") {
			lines = append(lines, line)
		}
	}
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], `level=INFO msg="Leaving out 192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4, 192.0.2.5, `+
		`192.0.2.6, 192.0.2.7, 192.0.2.8, 192.0.2.9, 192.0.2.10 and 2 more, discovered from their own scope entries"`)
	assert.Contains(t, lines[0], "target=192.0.2.0/28")
	assert.Contains(t, lines[1], `msg="Leaving out 192.0.2.17, discovered from their own scope entries"`)
	assert.Contains(t, lines[1], "target=192.0.2.16-18")
}

// A range every host of which is listed on its own is never scanned, so it
// records no run, and no "no hosts responded" failure.
func TestRangeCoveredByOwnEntriesIsNotScanned(t *testing.T) {
	agents := newFakeAgents(time.Second)
	client := &recordingClient{}
	r, store := newPolicyRunner(t, `
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
        - host: 192.0.2.1-2
        - host: 192.0.2.1
        - host: 192.0.2.2
`, agents.dial, client, discardLogger())
	assert.Len(t, r.scheduler.Jobs(), 2, "one job per listed host, none for the range")

	r.Start()
	require.Eventually(t, func() bool {
		return len(client.devicesOf("192.0.2.1")) > 0 && len(client.devicesOf("192.0.2.2")) > 0
	}, 10*time.Second, 20*time.Millisecond)
	require.NoError(t, r.Stop())
	assert.Empty(t, store.GetRunsForTarget("p1", "192.0.2.1-2", 161))
	assert.Zero(t, agents.probeCount("192.0.2.1", 161)+agents.probeCount("192.0.2.2", 161))
}
