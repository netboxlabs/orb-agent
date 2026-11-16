package traps

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/metrics"
)

func device(policy, addr string, kvs ...attribute.KeyValue) Device {
	return Device{Policy: policy, Addr: netip.MustParseAddr(addr), Attributes: kvs}
}

// receivedOnly keeps the traps_received entries of exportedCounters.
func receivedOnly(got map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for key, n := range got {
		if strings.Contains(key, "|snmp.traps_received|") {
			out[key] = n
		}
	}
	return out
}

// A policy's received series carry the attributes of the target the trap's
// address belongs to, beside the series' own dimensions, with the type each
// value was given.
func TestTally_ReceivedSeriesCarryTheirTargetsAttributes(t *testing.T) {
	reader := withProvider(t)
	ta := NewTally(testLogger)
	ta.Register()
	t.Cleanup(ta.Close)
	ta.SetAttributes("core", []Device{
		device("core", "10.0.0.5", attribute.String("site", "dc-west"), attribute.Int64("rack_units", 2)),
		device("core", "10.0.0.6", attribute.String("site", "dc-east"), attribute.Bool("monitored", true)),
	})
	ta.Activate("core")
	ta.Received("10.0.0.5", "core", "linkDown", V2c)
	ta.Received("10.0.0.6", "core", "linkDown", V2c)
	ta.Received("10.0.0.6", "core", "linkDown", V2c)

	got := exportedCounters(t, reader)
	assert.Equal(t, int64(1), got["core|snmp.traps_received|device_ip=10.0.0.5|rack_units=2|site=dc-west|trap_name=linkDown|version=2c"])
	assert.Equal(t, int64(2), got["core|snmp.traps_received|device_ip=10.0.0.6|monitored=true|site=dc-east|trap_name=linkDown|version=2c"])
	assert.Len(t, receivedOnly(got), 2, "no series without the attributes beside them")
}

// Two targets of one policy at one address, apart by port, ID or context,
// receive one stream of traps between them. The series carries the
// attributes they agree on and leaves off any key they disagree on, since
// nothing in a trap says which of them sent it.
func TestTally_TargetsSharingAnAddressExportWhatTheyAgreeOn(t *testing.T) {
	reader := withProvider(t)
	ta := NewTally(testLogger)
	ta.Register()
	t.Cleanup(ta.Close)
	ta.SetAttributes("core", []Device{
		device("core", "10.0.0.5", attribute.String("site", "dc-west"), attribute.String("role", "edge"), attribute.String("tenant", "tenant-a")),
		device("core", "10.0.0.5", attribute.String("site", "dc-west"), attribute.String("role", "core")),
	})
	ta.Activate("core")
	ta.Received("10.0.0.5", "core", "linkDown", V2c)

	got := exportedCounters(t, reader)
	assert.Equal(t, int64(1), got["core|snmp.traps_received|device_ip=10.0.0.5|site=dc-west|trap_name=linkDown|version=2c"])
	assert.Len(t, receivedOnly(got), 1)
}

// Attributes belong to the policy that set them: another policy naming the
// same address exports its own, and withdrawing the policy forgets them, so a
// policy coming back without attributes exports none.
func TestTally_AttributesArePerPolicyAndGoWithTheWithdrawal(t *testing.T) {
	reader := withProvider(t)
	ta := NewTally(testLogger)
	ta.Register()
	t.Cleanup(ta.Close)
	ta.SetAttributes("core", []Device{device("core", "10.0.0.5", attribute.String("site", "dc-west"))})
	ta.Activate("core")
	ta.Activate("edge")
	ta.Received("10.0.0.5", "core", "linkDown", V2c)
	ta.Received("10.0.0.5", "edge", "linkDown", V2c)

	got := exportedCounters(t, reader)
	assert.Contains(t, got, "core|snmp.traps_received|device_ip=10.0.0.5|site=dc-west|trap_name=linkDown|version=2c")
	assert.Contains(t, got, "edge|snmp.traps_received|device_ip=10.0.0.5|trap_name=linkDown|version=2c")

	ta.Withdraw("core")
	ta.Activate("core")
	ta.Received("10.0.0.5", "core", "linkDown", V2c)
	got = exportedCounters(t, reader)
	assert.Contains(t, got, "core|snmp.traps_received|device_ip=10.0.0.5|trap_name=linkDown|version=2c")
}

// The overflow series stands for many devices, so it carries none of their
// attributes.
func TestTally_OverflowSeriesCarriesNoAttributes(t *testing.T) {
	reader := withProvider(t, sdkmetric.WithCardinalityLimit(metrics.CardinalityLimit))
	ta := NewTally(testLogger)
	ta.Register()
	t.Cleanup(ta.Close)
	ta.SetAttributes("core", []Device{device("core", "192.0.2.1", attribute.String("site", "dc-west"))})
	ta.Activate("core")
	for i := range seriesLimit {
		ta.Received(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "core", "linkDown", V2c)
	}
	ta.Received("192.0.2.1", "core", "linkUp", V2c)

	got := exportedCounters(t, reader)
	assert.Equal(t, int64(1), got["core|snmp.traps_received|device_ip=other|trap_name=other|version=2c"])
}

// A target written without a zone matches a link-local sender on any
// interface, so its attributes do too.
func TestTally_ZonedSenderTakesTheZonelessTargetsAttributes(t *testing.T) {
	reader := withProvider(t)
	ta := NewTally(testLogger)
	ta.Register()
	t.Cleanup(ta.Close)
	ta.SetAttributes("core", []Device{device("core", "fe80::1", attribute.String("site", "dc-west"))})
	ta.Activate("core")
	ta.Received("fe80::1%eth0", "core", "linkDown", V2c)

	got := exportedCounters(t, reader)
	assert.Equal(t, int64(1), got["core|snmp.traps_received|device_ip=fe80::1%eth0|site=dc-west|trap_name=linkDown|version=2c"])
}

// A target written with a zone and one written without it both claim a trap
// from that interface, so the series carries only what the two agree on. A
// sender on another interface is claimed by the zoneless target alone.
func TestTally_ZonedAndZonelessTargetsShareWhatTheyAgreeOn(t *testing.T) {
	reader := withProvider(t)
	ta := NewTally(testLogger)
	ta.Register()
	t.Cleanup(ta.Close)
	ta.SetAttributes("core", []Device{
		device("core", "fe80::1%eth0", attribute.String("role", "edge"), attribute.String("site", "dc-west")),
		device("core", "fe80::1", attribute.String("role", "core"), attribute.String("site", "dc-west")),
		// Agreeing on nothing leaves the zoned address with no attributes,
		// not with the zoneless target's.
		device("core", "fe80::2%eth0", attribute.String("role", "edge")),
		device("core", "fe80::2", attribute.String("role", "core")),
		device("core", "fe80::3%eth0"),
		device("core", "fe80::3", attribute.String("site", "dc-west")),
	})
	ta.Activate("core")
	ta.Received("fe80::1%eth0", "core", "linkDown", V2c)
	ta.Received("fe80::1%eth1", "core", "linkDown", V2c)
	ta.Received("fe80::2%eth0", "core", "linkDown", V2c)
	ta.Received("fe80::3%eth0", "core", "linkDown", V2c)

	got := receivedOnly(exportedCounters(t, reader))
	assert.Equal(t, int64(1), got["core|snmp.traps_received|device_ip=fe80::1%eth0|site=dc-west|trap_name=linkDown|version=2c"])
	assert.Equal(t, int64(1), got["core|snmp.traps_received|device_ip=fe80::1%eth1|role=core|site=dc-west|trap_name=linkDown|version=2c"])
	assert.Equal(t, int64(1), got["core|snmp.traps_received|device_ip=fe80::2%eth0|trap_name=linkDown|version=2c"])
	assert.Equal(t, int64(1), got["core|snmp.traps_received|device_ip=fe80::3%eth0|trap_name=linkDown|version=2c"])
	assert.Len(t, got, 4)
}

// A policy applied again with other attributes for an address starts that
// address's series afresh: a count carried into the new attribute set would
// read as traps the new set never received.
func TestTally_ANewAttributeSetStartsANewSeries(t *testing.T) {
	reader := withProvider(t)
	ta := NewTally(testLogger)
	ta.Register()
	t.Cleanup(ta.Close)
	ta.SetAttributes("core", []Device{device("core", "10.0.0.5", attribute.String("site", "dc-west"))})
	ta.Activate("core")
	for range 500 {
		ta.Received("10.0.0.5", "core", "linkDown", V2c)
	}
	got := receivedOnly(exportedCounters(t, reader))
	require.Equal(t, int64(500), got["core|snmp.traps_received|device_ip=10.0.0.5|site=dc-west|trap_name=linkDown|version=2c"])

	ta.Withdraw("core")
	ta.SetAttributes("core", []Device{device("core", "10.0.0.5", attribute.String("site", "dc-east"))})
	ta.Activate("core")
	ta.Received("10.0.0.5", "core", "linkDown", V2c)

	got = receivedOnly(exportedCounters(t, reader))
	assert.Equal(t, int64(1), got["core|snmp.traps_received|device_ip=10.0.0.5|site=dc-east|trap_name=linkDown|version=2c"])
	assert.Len(t, got, 1, "the old attribute set is not exported once withdrawn")
}

// The same attributes applied again are the same series, which resumes its
// total as a recreated policy's series always has.
func TestTally_TheSameAttributesResumeTheirSeries(t *testing.T) {
	reader := withProvider(t)
	ta := NewTally(testLogger)
	ta.Register()
	t.Cleanup(ta.Close)
	devices := []Device{device("core", "10.0.0.5", attribute.String("site", "dc-west"))}
	ta.SetAttributes("core", devices)
	ta.Activate("core")
	for range 5 {
		ta.Received("10.0.0.5", "core", "linkDown", V2c)
	}
	ta.Withdraw("core")
	ta.SetAttributes("core", devices)
	ta.Activate("core")
	ta.Received("10.0.0.5", "core", "linkDown", V2c)

	got := receivedOnly(exportedCounters(t, reader))
	assert.Equal(t, int64(6), got["core|snmp.traps_received|device_ip=10.0.0.5|site=dc-west|trap_name=linkDown|version=2c"])
}

// Validation refuses an attribute that takes one of the series' own keys, so
// this only happens to a caller that skips it; even then the series' own
// value is the one exported.
func TestTally_TheSeriesOwnDimensionsWinOverAnAttribute(t *testing.T) {
	reader := withProvider(t)
	ta := NewTally(testLogger)
	ta.Register()
	t.Cleanup(ta.Close)
	ta.SetAttributes("core", []Device{device("core", "10.0.0.5",
		attribute.String("device_ip", "198.51.100.1"), attribute.String("trap_name", "spoofed"), attribute.String("version", "9"))})
	ta.Activate("core")
	ta.Received("10.0.0.5", "core", "linkDown", V2c)

	got := receivedOnly(exportedCounters(t, reader))
	assert.Equal(t, int64(1), got["core|snmp.traps_received|device_ip=10.0.0.5|trap_name=linkDown|version=2c"])
	assert.Len(t, got, 1)
}

// Acquiring a socket hands the tally the attributes of the devices it
// registers.
func TestPool_AcquireCarriesTheDevicesAttributes(t *testing.T) {
	reader := withProvider(t)
	tally := NewTally(testLogger)
	tally.Register()
	t.Cleanup(tally.Close)
	p := NewPool(tally, testLogger)
	t.Cleanup(p.Close)

	lease, err := p.Acquire("127.0.0.1:0", "core", []Device{device("core", "10.0.0.5", attribute.String("site", "dc-west"))}, nil)
	require.NoError(t, err)
	t.Cleanup(lease.Release)
	tally.Received("10.0.0.5", "core", "linkDown", V2c)

	got := exportedCounters(t, reader)
	assert.Equal(t, int64(1), got["core|snmp.traps_received|device_ip=10.0.0.5|site=dc-west|trap_name=linkDown|version=2c"])
}

func TestReservedAttributeName_IsTheReceivedSeriesOwnDimensions(t *testing.T) {
	for _, name := range []string{"device_ip", "trap_name", "version"} {
		assert.True(t, ReservedAttributeName(name), name)
	}
	assert.False(t, ReservedAttributeName("site"))
	assert.False(t, ReservedAttributeName("reason"), "drops are process-level and carry no policy attributes")
}
