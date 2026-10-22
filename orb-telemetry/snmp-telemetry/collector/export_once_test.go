package collector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/profiles"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/snmp"
)

const (
	onceCPUOID  = "1.3.6.1.4.1.9999.140.1"
	onceSysObj  = "1.3.6.1.4.1.9999.140"
	onceMetric  = "snmp.cpuutil"
	defaultTick = 10 // seconds: otel_export_period's default
)

// pollValue polls target for policy once, the device answering value, the
// way one run of the policy's job for that target does.
func pollValue(t *testing.T, c *MetricsCollector, policy string, target config.Target, value int) {
	t.Helper()
	c.clientFactory = walkerFactory(&recordingWalker{responses: map[string]map[string]snmp.PDU{
		sysObjectIDOID: {sysObjectIDOID: oIDPDU(onceSysObj)},
		sysDescrOID:    {},
		onceCPUOID:     {onceCPUOID: intPDU(onceCPUOID, value)},
	}})
	require.NoError(t, c.CollectTarget(context.Background(), target, mustAuth(), policy, DialOptions{}))
}

func onceProfile() *profiles.Profile {
	return profileWithOID(onceSysObj, "once.yml", []profiles.MetricEntry{
		{Symbol: &profiles.Symbol{Name: "cpuUtil", OID: onceCPUOID}},
	})
}

// values is what one collection exported for policy.
func values(points map[string][]exportedPoint, policy string) []int64 {
	var out []int64
	for _, pt := range points[policy] {
		out = append(out, pt.value)
	}
	return out
}

// At metrics_interval 60 and the default export period the reader collects
// six times per poll. Each poll's value leaves in the first collection after
// it and in none of the other five, so one poll is one sample downstream, not
// six, each stamped with a new time.
func TestCollectTarget_APollIsExportedByOneCollectionNotEvery(t *testing.T) {
	reader := withManualReader(t)
	c := newCollector(nil, onceProfile())
	target := config.Target{Host: "10.0.0.140", Port: 161}

	for poll, value := range []int{11, 22, 33} {
		pollValue(t, c, "p", target, value)
		assert.Equal(t, []int64{int64(value)}, values(exportedByPolicy(t, reader, onceMetric), "p"),
			"poll %d: the first collection after it exports its value", poll)
		for tick := 1; tick < 60/defaultTick; tick++ {
			assert.Empty(t, exportedByPolicy(t, reader, onceMetric)["p"],
				"poll %d, collection %d: the value already left", poll, tick+1)
		}
	}
}

// A policy on a 30 second interval and one on 300 seconds, sharing one
// collector and one reader that collects every 10 seconds, for ten minutes:
// each poll of each policy is exported exactly once, by the collection after
// it, whatever the other policy is doing.
func TestCollectTarget_PoliciesOnDifferentIntervalsEachExportOncePerPoll(t *testing.T) {
	reader := withManualReader(t)
	c := newCollector(nil, onceProfile())
	intervals := map[string]int{"every-30s": 30, "every-300s": 300}
	targets := map[string]config.Target{
		"every-30s":  {Host: "10.0.0.141", Port: 161},
		"every-300s": {Host: "10.0.0.142", Port: 161},
	}

	polled := map[string][]int64{}
	exported := map[string][]int64{}
	for second := 0; second < 600; second++ {
		for policy, interval := range intervals {
			if second%interval == 0 {
				// The value is the second of the poll, so each export can be
				// traced to the poll it came from.
				pollValue(t, c, policy, targets[policy], second)
				polled[policy] = append(polled[policy], int64(second))
			}
		}
		// The ticks fall between polls, as they do when the reader and the
		// scheduler start apart.
		if second%defaultTick != defaultTick/2 {
			continue
		}
		points := exportedByPolicy(t, reader, onceMetric)
		for policy := range intervals {
			for _, v := range values(points, policy) {
				assert.Equal(t, int64(second-defaultTick/2), v,
					"%s: the collection at %ds exports only the poll just before it", policy, second)
				exported[policy] = append(exported[policy], v)
			}
		}
	}

	require.Len(t, polled["every-30s"], 20)
	require.Len(t, polled["every-300s"], 2)
	for policy := range intervals {
		assert.Equal(t, polled[policy], exported[policy], "%s: every poll exported once, in order", policy)
	}
}

// A declaration throttled by poll_time_sec is read on a poll from what it
// left, and that reading leaves once per poll like the rest of the poll,
// rather than on every collection or only once per poll_time_sec.
func TestCollectTarget_ARetainedReadingIsExportedOncePerPoll(t *testing.T) {
	reader := withManualReader(t)
	c := newCollector(nil, interruptionProfile(interruptSysObj, "retained.yml"))

	runCollectionValued(t, c, "p", interruptSysObj, 7)
	assert.Equal(t, []int64{7}, values(exportedByPolicy(t, reader, "snmp.slowmetric"), "p"))
	assert.Empty(t, exportedByPolicy(t, reader, "snmp.slowmetric")["p"])

	w := runCollectionValued(t, c, "p", interruptSysObj, 99)
	require.NotContains(t, w.walkCalls, interruptSlow, "the declaration is throttled on the second poll")
	assert.Equal(t, []int64{7}, values(exportedByPolicy(t, reader, "snmp.slowmetric"), "p"),
		"the retained reading leaves with the poll that kept it")
	assert.Empty(t, exportedByPolicy(t, reader, "snmp.slowmetric")["p"])
}

// A run cut short publishes nothing. The device keeps its readings for the
// next run, but the last poll's values, already exported, are not sent again
// as if the interrupted run had read them.
func TestCollectTarget_AnInterruptedRunExportsNothingAgain(t *testing.T) {
	reader := withManualReader(t)
	c := newCollector(nil, interruptionProfile(interruptSysObj, "interrupted-once.yml"))

	runCollection(t, c, "p", interruptSysObj)
	assert.Len(t, exportedByPolicy(t, reader, "snmp.fastmetric")["p"], 1)

	runInterrupted(t, c, "p", interruptSysObj)
	require.Len(t, c.testDeviceStore("p", interruptHost)["snmp.fastmetric"], 1, "the readings are kept")
	assert.Empty(t, exportedByPolicy(t, reader, "snmp.fastmetric")["p"], "but not exported again")

	runCollection(t, c, "p", interruptSysObj)
	assert.Len(t, exportedByPolicy(t, reader, "snmp.fastmetric")["p"], 1, "the next complete run exports")
}

// What a device's last poll left and no collection has exported yet goes
// with the device, its policy and the collector, so nothing is held for a
// device that is not polled any more.
func TestForgettingADeviceDropsWhatItHasNotExported(t *testing.T) {
	c := newCollector(nil, onceProfile())
	a := config.Target{Host: "10.0.0.143", Port: 161}
	b := config.Target{Host: "10.0.0.144", Port: 161}
	pollValue(t, c, "a", a, 1)
	pollValue(t, c, "b", b, 2)
	pollValue(t, c, "c", a, 3)
	require.Len(t, c.unexported, 3)

	c.forgetDevice(testKey("a", a.Host))
	assert.NotContains(t, c.unexported, testKey("a", a.Host))

	c.ForgetPolicy("b")
	assert.NotContains(t, c.unexported, testKey("b", b.Host))

	c.Close()
	assert.Empty(t, c.unexported)
}
