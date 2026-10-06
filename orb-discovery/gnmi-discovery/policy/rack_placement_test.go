package policy

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// rackPolicy returns a one-policy document with the given policy defaults and
// a single target, both written as indented YAML bodies.
func rackPolicy(defaults, target string) []byte {
	return []byte(`
policies:
  p1:
    config:
      defaults:
` + defaults + `
    scope:
      targets:
` + target + `
`)
}

func TestRackPlacementIsRejected(t *testing.T) {
	cases := []struct {
		name     string
		defaults string
		target   string
		want     string
	}{
		{
			name:     "position in policy defaults",
			defaults: "        rack: R12\n        position: 40",
			target:   "        - host: 192.0.2.10",
			want:     "defaults: position and face are set per target, in override_defaults",
		},
		{
			name:     "face in policy defaults",
			defaults: "        rack: R12\n        face: front",
			target:   "        - host: 192.0.2.10",
			want:     "defaults: position and face are set per target, in override_defaults",
		},
		{
			name:     "position without face",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            position: 40",
			want:     "target 192.0.2.10: position and face must be set together",
		},
		{
			name:     "face without position",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            face: front",
			want:     "target 192.0.2.10: position and face must be set together",
		},
		{
			name:     "no rack anywhere",
			defaults: "        site: DC1",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            position: 40\n            face: front",
			want:     "target 192.0.2.10: position and face need a rack",
		},
		{
			name:     "blank racks do not count",
			defaults: "        rack: \"  \"",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            rack: \" \"\n            position: 40\n            face: front",
			want:     "target 192.0.2.10: position and face need a rack",
		},
		{
			name:     "face not front or rear",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            position: 40\n            face: side",
			want:     `target 192.0.2.10: face "side" must be front or rear`,
		},
		{
			name:     "position zero",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            position: 0\n            face: front",
			want:     "target 192.0.2.10: position 0 must be at least 1, in increments of 0.5",
		},
		{
			name:     "position below one",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            position: 0.5\n            face: front",
			want:     "target 192.0.2.10: position 0.5 must be at least 1, in increments of 0.5",
		},
		{
			name:     "negative position",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            position: -3\n            face: front",
			want:     "target 192.0.2.10: position -3 must be at least 1",
		},
		{
			name:     "position not a half U",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            position: 40.25\n            face: front",
			want:     "target 192.0.2.10: position 40.25 must be at least 1, in increments of 0.5",
		},
		{
			name:     "position not a number",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            position: .nan\n            face: front",
			want:     "target 192.0.2.10: position NaN must be at least 1",
		},
		{
			name:     "infinite position",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            position: .inf\n            face: front",
			want:     "target 192.0.2.10: position +Inf must be at least 1",
		},
		{
			name:     "subnet with position and face",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.0/30\n          override_defaults:\n            position: 40\n            face: front",
			want:     `target "192.0.2.0/30": position and face need a single host; a range or subnet would place every device at the same U`,
		},
		{
			name:     "range with position and face",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.1-4\n          override_defaults:\n            position: 40\n            face: front",
			want:     `target "192.0.2.1-4": position and face need a single host; a range or subnet would place every device at the same U`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTestManager(t).ParsePolicies(rackPolicy(tc.defaults, tc.target))
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

// The range check runs on the resolved host: a subnet written as ${VAR} is an
// opaque string until then and would otherwise pass as one host.
func TestRackPlacementOnASubnetFromAnEnvVarIsRejected(t *testing.T) {
	t.Setenv("RACK_SUBNET", "192.0.2.0/29")
	_, err := newTestManager(t).ParsePolicies(rackPolicy(
		"        rack: R12",
		"        - host: ${RACK_SUBNET}\n          override_defaults:\n            position: 40\n            face: front",
	))
	require.Error(t, err)
	require.Contains(t, err.Error(), "position and face need a single host")
}

func TestRackPlacementIsAccepted(t *testing.T) {
	cases := []struct {
		name     string
		defaults string
		target   string
	}{
		{
			name:     "rack from policy defaults, half U and upper-case face from the override",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            position: 40.5\n            face: FRONT",
		},
		{
			name:     "rack, position and face all in the override",
			defaults: "        site: DC1",
			target:   "        - host: 192.0.2.10\n          override_defaults:\n            rack: R12\n            position: 1\n            face: Rear",
		},
		{
			name:     "rack alone on a subnet",
			defaults: "        site: DC1",
			target:   "        - host: 192.0.2.0/30\n          override_defaults:\n            rack: R12",
		},
		{
			name:     "rack alone in policy defaults",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.1-4",
		},
		{
			name:     "a blank face is unset, like a blank rack",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.0/30\n          override_defaults:\n            face: \" \"",
		},
		{
			name:     "a /32 is one host",
			defaults: "        rack: R12",
			target:   "        - host: 192.0.2.10/32\n          override_defaults:\n            position: 40\n            face: front",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTestManager(t).ParsePolicies(rackPolicy(tc.defaults, tc.target))
			require.NoError(t, err)
		})
	}
}

// A target's placement, end to end: parsed and validated, merged over the policy
// defaults, translated, and pruned at the runner boundary.
func TestRackPlacementReachesTheIngestedDevice(t *testing.T) {
	policies, err := newTestManager(t).ParsePolicies([]byte(`
policies:
  p1:
    config:
      mode: on_change
      debounce_ms: 20
      defaults:
        site: DC1
        location: Hall 1
        rack: R1
    scope:
      targets:
        - host: 192.0.2.10
          override_defaults:
            rack: R12
            position: 40.5
            face: FRONT
`))
	require.NoError(t, err)

	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	fake := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "Arista"}, OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{
			{Updates: []gnmi.Update{
				{Path: "/system/state/hostname", Value: "leaf1"},
				{Path: "/interfaces/interface[name=Ethernet1]/state/admin-status", Value: "UP"},
			}},
			{SyncDone: true},
		},
	}
	client := &recordingClient{}
	r, err := NewRunner(context.Background(), slog.New(slog.DiscardHandler), "p1", policies["p1"],
		client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	defer func() { require.NoError(t, r.Stop()) }()

	require.Eventually(t, func() bool { return client.count() >= 1 }, 2*time.Second, 20*time.Millisecond)
	entities := client.lastIngested()
	dev, ok := entities[0].(*diode.Device)
	require.True(t, ok)
	require.NotNil(t, dev.Rack)
	require.Equal(t, "R12", *dev.Rack.Name, "the target's rack replaces the policy rack")
	require.NotNil(t, dev.Rack.Site)
	require.Equal(t, "DC1", *dev.Rack.Site.Name)
	require.NotNil(t, dev.Rack.Location)
	require.Equal(t, "Hall 1", *dev.Rack.Location.Name)
	require.NotNil(t, dev.Position)
	require.InDelta(t, 40.5, *dev.Position, 0)
	require.NotNil(t, dev.Face)
	require.Equal(t, "front", *dev.Face)

	var eth *diode.Interface
	for _, e := range entities {
		if i, ok := e.(*diode.Interface); ok && i.Name != nil && *i.Name == "Ethernet1" {
			eth = i
		}
	}
	require.NotNil(t, eth)
	require.NotNil(t, eth.Device)
	require.Nil(t, eth.Device.Rack, "a nested device reference carries no placement")
	require.Nil(t, eth.Device.Position)
	require.Nil(t, eth.Device.Face)
}

// twoTargets returns a policy with the given defaults and two single-host
// targets, each with its own override_defaults body.
func twoTargets(defaults, first, second string) []byte {
	return rackPolicy(defaults,
		"        - host: 192.0.2.10\n          override_defaults:\n"+first+"\n"+
			"        - host: 192.0.2.11\n          override_defaults:\n"+second)
}

// Diode matches a device on rack, position and face after name and site, so a
// second, new device sent to an occupied U lands on the first one's record.
func TestTwoTargetsAtTheSameUAreRejected(t *testing.T) {
	cases := []struct {
		name          string
		defaults      string
		first, second string
		want          string
	}{
		{
			name:     "same rack, U and face",
			defaults: "        rack: R12",
			first:    "            position: 40\n            face: front",
			second:   "            position: 40\n            face: front",
			want:     "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front",
		},
		{
			name:     "face compared case-insensitively",
			defaults: "        rack: R12",
			first:    "            position: 40.5\n            face: FRONT",
			second:   "            position: 40.5\n            face: front",
			want:     "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40.5 front",
		},
		{
			name:     "padded policy rack and an equal override rack",
			defaults: "        rack: \" R12 \"",
			first:    "            position: 40\n            face: rear",
			second:   "            rack: R12\n            position: 40\n            face: rear",
			want:     "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 rear",
		},
		{
			name:     "policy location and an equal override location",
			defaults: "        site: DC1\n        location: Hall 1\n        rack: R12",
			first:    "            position: 40\n            face: front",
			second:   "            location: Hall 1\n            position: 40\n            face: front",
			want:     "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front",
		},
		{
			name:     "a target without a location clashes with one in a location",
			defaults: "        site: DC1\n        rack: R12",
			first:    "            position: 40\n            face: front",
			second:   "            location: Hall 1\n            position: 40\n            face: front",
			want:     "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front",
		},
		{
			name:     "a target in a location clashes with one without",
			defaults: "        site: DC1\n        rack: R12",
			first:    "            location: Hall 1\n            position: 40\n            face: front",
			second:   "            position: 40\n            face: front",
			want:     "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front",
		},
		{
			name:     "an unset site is the default site",
			defaults: "        rack: R12",
			first:    "            position: 40\n            face: front",
			second:   "            site: undefined\n            position: 40\n            face: front",
			want:     "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTestManager(t).ParsePolicies(twoTargets(tc.defaults, tc.first, tc.second))
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestTwoTargetsAtDifferentPlacementsAreAccepted(t *testing.T) {
	cases := []struct {
		name          string
		defaults      string
		first, second string
	}{
		{
			name:     "opposite faces of one U",
			defaults: "        rack: R12",
			first:    "            position: 40\n            face: front",
			second:   "            position: 40\n            face: rear",
		},
		{
			name:     "different U",
			defaults: "        rack: R12",
			first:    "            position: 40\n            face: front",
			second:   "            position: 40.5\n            face: front",
		},
		{
			name:     "different racks",
			defaults: "        rack: R12",
			first:    "            position: 40\n            face: front",
			second:   "            rack: R13\n            position: 40\n            face: front",
		},
		{
			name:     "same rack name in different locations",
			defaults: "        site: DC1\n        rack: R12",
			first:    "            location: Hall 1\n            position: 40\n            face: front",
			second:   "            location: Hall 2\n            position: 40\n            face: front",
		},
		{
			name:     "same rack name in different sites",
			defaults: "        rack: R12",
			first:    "            site: DC1\n            position: 40\n            face: front",
			second:   "            site: DC2\n            position: 40\n            face: front",
		},
		{
			name:     "a rack alone places nothing",
			defaults: "        rack: R12",
			first:    "            role: leaf",
			second:   "            role: leaf",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTestManager(t).ParsePolicies(twoTargets(tc.defaults, tc.first, tc.second))
			require.NoError(t, err)
		})
	}
}

func TestRackPlacementYAMLTypes(t *testing.T) {
	t.Run("a bool position is refused", func(t *testing.T) {
		_, err := newTestManager(t).ParsePolicies(rackPolicy("        rack: R12",
			"        - host: 192.0.2.10\n          override_defaults:\n            position: true\n            face: front"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot unmarshal !!bool")
	})

	// The agent re-marshals a policy before posting it, so only a quoted
	// numeric rack name reaches the backend as written (the docs say so).
	t.Run("a quoted numeric rack name is kept as written", func(t *testing.T) {
		policies, err := newTestManager(t).ParsePolicies(rackPolicy("        rack: \"12\"",
			"        - host: 192.0.2.10\n          override_defaults:\n            rack: \"012\"\n            position: 40\n            face: front"))
		require.NoError(t, err)
		p := policies["p1"]
		require.Equal(t, "12", string(p.Config.Defaults.Rack))
		require.Equal(t, "012", string(p.Scope.Targets[0].OverrideDefaults.Rack))
	})

	// An unquoted 01 would arrive as 1 and 010 as 8, so a number is refused
	// rather than taken as another rack's name.
	for _, rack := range []string{"12", "012", "0x1A", "1e3", "true"} {
		t.Run("unquoted "+rack+" is refused", func(t *testing.T) {
			_, err := newTestManager(t).ParsePolicies(rackPolicy("        rack: "+rack,
				"        - host: 192.0.2.10\n          override_defaults:\n            position: 40\n            face: front"))
			require.Error(t, err)
			require.Contains(t, err.Error(), `quote a numeric rack name, e.g. rack: "01"`)
		})
	}
}

// Two targets with one netbox_id update one device: they must place it at
// the same slot, and doing so is not a clash.
func TestOneNetboxIDPlacement(t *testing.T) {
	pinned := func(host string, position string) string {
		return "        - host: " + host + "\n          netbox_id: 42\n          override_defaults:\n            position: " +
			position + "\n            face: front"
	}
	_, err := newTestManager(t).ParsePolicies(rackPolicy("        rack: R12",
		pinned("192.0.2.10", "40")+"\n"+pinned("192.0.2.11", "41")))
	require.Error(t, err)
	require.Contains(t, err.Error(), "targets 192.0.2.10 and 192.0.2.11 place netbox_id 42 at different slots")

	_, err = newTestManager(t).ParsePolicies(rackPolicy("        rack: R12",
		pinned("192.0.2.10", "40")+"\n"+pinned("192.0.2.11", "40")))
	require.NoError(t, err, "one device at one slot, named twice")
}

// netbox_id survives only on a target written as a single address, as the
// runner applies it: a /32 or a one-address range drops it and is its own device.
func TestNetboxIDOnRangeSyntaxPinsNothing(t *testing.T) {
	pinned := func(host, rack, position string) string {
		return "        - host: " + host + "\n          netbox_id: 42\n          override_defaults:\n            rack: " + rack +
			"\n            position: " + position + "\n            face: front"
	}
	_, err := newTestManager(t).ParsePolicies(rackPolicy("        site: DC1",
		pinned("192.0.2.10/32", "R12", "40")+"\n"+pinned("192.0.2.11/32", "R12", "40")))
	require.Error(t, err, "two devices at one U, though they name one netbox_id")
	require.Contains(t, err.Error(), "are both placed at R12 U40 front")

	_, err = newTestManager(t).ParsePolicies(rackPolicy("        site: DC1",
		pinned("192.0.2.10/32", "R12", "40")+"\n"+pinned("192.0.2.11", "R13", "41")))
	require.NoError(t, err, "the /32 pins nothing, so the literal target's placement is its own")
}

// The netbox_id rule reads the resolved host: ${VAR} hosts are opaque
// strings until then, and would otherwise pass as single addresses.
func TestNetboxIDOnAnEnvVarHostReadsTheResolvedHost(t *testing.T) {
	t.Setenv("RACK_HOST_A", "192.0.2.10/32")
	t.Setenv("RACK_HOST_B", "192.0.2.11/32")
	pinned := func(host string) string {
		return "        - host: " + host + "\n          netbox_id: 42\n          override_defaults:\n            position: 40\n            face: front"
	}
	_, err := newTestManager(t).ParsePolicies(rackPolicy("        rack: R12",
		pinned("${RACK_HOST_A}")+"\n"+pinned("${RACK_HOST_B}")))
	require.Error(t, err, "both /32s drop the netbox_id, so they are two devices at one U")
	require.Contains(t, err.Error(), "targets 192.0.2.10/32 and 192.0.2.11/32 are both placed at R12 U40 front")
}

// Targets naming one endpoint collapse to one device, a literal winning, so
// only the winner's placement is sent and checked.
func TestRackSlotsFollowEndpointDedupe(t *testing.T) {
	placedAt := func(host string) string {
		return "        - host: " + host + "\n          override_defaults:\n            position: 40\n            face: front"
	}
	_, err := newTestManager(t).ParsePolicies(rackPolicy("        rack: R12",
		placedAt("192.0.2.10")+"\n"+placedAt("192.0.2.10/32")))
	require.NoError(t, err, "one endpoint written twice is one device")

	_, err = newTestManager(t).ParsePolicies(rackPolicy("        rack: R12",
		"        - host: 192.0.2.10\n"+placedAt("192.0.2.10/32")+"\n"+placedAt("192.0.2.11")))
	require.NoError(t, err, "the literal wins, so the /32's U is never sent")

	_, err = newTestManager(t).ParsePolicies(rackPolicy("        rack: R12",
		strings.Replace(placedAt("192.0.2.10/32"), "40", "41", 1)+"\n"+placedAt("192.0.2.10")+"\n"+placedAt("192.0.2.11")))
	require.Error(t, err, "the literal wins written second too, and its U is taken")
	require.Contains(t, err.Error(), "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front")

	_, err = newTestManager(t).ParsePolicies(rackPolicy("        rack: R12",
		placedAt("192.0.2.10/32")+"\n"+placedAt("192.0.2.11")))
	require.Error(t, err, "two endpoints are two devices")
	require.Contains(t, err.Error(), "targets 192.0.2.10/32 and 192.0.2.11 are both placed at R12 U40 front")
}

// The asset tag is the device matcher Diode tries first, so targets sending
// one literal tag update one device and must send it one placement.
func TestOneAssetTagPlacement(t *testing.T) {
	tagged := func(host, tag, rack string) string {
		return "        - host: " + host + "\n          override_defaults:\n            asset_tag: \"" + tag +
			"\"\n            rack: " + rack
	}
	placedAt := func(host, position string) string {
		return "        - host: " + host + "\n          override_defaults:\n            position: " + position + "\n            face: front"
	}
	differentSlots := "place asset_tag A1 at different slots"
	for name, tc := range map[string]struct {
		defaults, targets, wantErr string
	}{
		"one tag in two racks": {
			"        site: DC1",
			tagged("192.0.2.10", "A1", "R12") + "\n" + tagged("192.0.2.11", "A1", "R13"),
			"targets 192.0.2.10 and 192.0.2.11 " + differentSlots,
		},
		"a padded tag is the same tag": {
			"        site: DC1",
			tagged("192.0.2.10", " A1 ", "R12") + "\n" + tagged("192.0.2.11", "A1", "R13"), differentSlots,
		},
		"a subnet's devices share its tag": {
			"        site: DC1",
			tagged("192.0.2.16/29", "A1", "R12") + "\n" + tagged("192.0.2.10", "A1", "R13"),
			"targets 192.0.2.16/29 and 192.0.2.10 " + differentSlots,
		},
		"a policy tag over two Us": {
			"        rack: R12\n        asset_tag: A1",
			placedAt("192.0.2.10", "40") + "\n" + placedAt("192.0.2.11", "41"), differentSlots,
		},
		"one tag at one U is one device": {
			"        rack: R12\n        asset_tag: A1",
			placedAt("192.0.2.10", "40") + "\n" + placedAt("192.0.2.11", "40"), "",
		},
		"different tags": {
			"        site: DC1",
			tagged("192.0.2.10", "A1", "R12") + "\n" + tagged("192.0.2.11", "A2", "R13"), "",
		},
		"a tag read from a path": {
			"        site: DC1",
			tagged("192.0.2.10", "/components/component[name=Chassis]/state/id", "R12") + "\n" +
				tagged("192.0.2.11", "/components/component[name=Chassis]/state/id", "R13"), "",
		},
		"a placeholder is not sent": {
			"        site: DC1",
			tagged("192.0.2.10", "N/A", "R12") + "\n" + tagged("192.0.2.11", "N/A", "R13"), "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newTestManager(t).ParsePolicies(rackPolicy(tc.defaults, tc.targets))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// A shared identifier means two targets may update one device, so their
// placements must agree; only a shared strongest one, in Diode's matching
// order, says they do, so only that lets two targets share a U.
func TestPlacementIdentityPrecedence(t *testing.T) {
	target := func(host, id, tag, rack, position string) string {
		out := "        - host: " + host + "\n"
		if id != "" {
			out += "          netbox_id: " + id + "\n"
		}
		out += "          override_defaults:\n            asset_tag: " + tag + "\n            rack: " + rack
		if position != "" {
			out += "\n            position: " + position + "\n            face: front"
		}
		return out
	}
	_, err := newTestManager(t).ParsePolicies(rackPolicy("        site: DC1",
		target("192.0.2.10", "41", "A1", "R12", "40")+"\n"+target("192.0.2.11", "42", "A1", "R12", "40")))
	require.Error(t, err, "two netbox_ids are two devices, whatever tag they share")
	require.Contains(t, err.Error(), "targets 192.0.2.10 and 192.0.2.11 are both placed at R12 U40 front")

	_, err = newTestManager(t).ParsePolicies(rackPolicy("        site: DC1",
		target("192.0.2.10", "42", "A1", "R12", "")+"\n"+target("192.0.2.11", "", "A1", "R13", "")))
	require.Error(t, err, "the tag may match the netbox_id device, so the racks must agree")
	require.Contains(t, err.Error(), "place asset_tag A1 at different slots")

	for _, order := range [][2]string{{"42", ""}, {"", "42"}} {
		_, err = newTestManager(t).ParsePolicies(rackPolicy("        site: DC1",
			target("192.0.2.10", order[0], "A1", "R12", "40")+"\n"+target("192.0.2.11", order[1], "A1", "R12", "40")))
		require.Error(t, err, "a tag alongside a netbox_id does not show the tag-only target is that device")
		require.Contains(t, err.Error(), "are both placed at R12 U40 front")
	}

	_, err = newTestManager(t).ParsePolicies(rackPolicy("        site: DC1",
		target("192.0.2.10", "42", "A1", "R12", "40")+"\n"+target("192.0.2.11", "42", "A1", "R12", "40")))
	require.NoError(t, err, "one netbox_id at one U is one device")
}

// A target is matched by its strongest identifier, so a shared one ties two
// targets only when it is the strongest of at least one.
func TestPlacementTiesOnlyByAMatchedIdentifier(t *testing.T) {
	target := func(host, id, rack string) string {
		out := "        - host: " + host + "\n"
		if id != "" {
			out += "          netbox_id: " + id + "\n"
		}
		return out + "          override_defaults:\n            asset_tag: A1\n            rack: " + rack
	}
	_, err := newTestManager(t).ParsePolicies(rackPolicy("        site: DC1",
		target("192.0.2.10", "41", "R12")+"\n"+target("192.0.2.11", "42", "R13")))
	require.NoError(t, err, "each is matched by its own netbox_id, so the shared tag ties nothing")

	_, err = newTestManager(t).ParsePolicies(rackPolicy("        site: DC1",
		target("192.0.2.11", "", "R13")+"\n"+target("192.0.2.10", "42", "R12")))
	require.Error(t, err, "the tag-only target is matched by the tag the netbox_id device carries")
	require.Contains(t, err.Error(), "place asset_tag A1 at different slots")
}

// A target without a rack still sends a site and any location, and NetBox
// refuses a device whose rack is in another, so one sharing a racked device
// must send that target's, or no location.
func TestUnrackedTargetsKeepARackedDeviceWhereItsRackIs(t *testing.T) {
	racked := "        - host: 192.0.2.10\n          netbox_id: 42\n          override_defaults:\n            asset_tag: A1\n" +
		"            rack: R12\n            location: Row 1"
	unracked := func(id, override string) string {
		out := "        - host: 192.0.2.11\n          netbox_id: " + id + "\n          override_defaults:\n            asset_tag: A1"
		if override != "" {
			out += "\n            " + override
		}
		return out
	}
	moved := "targets 192.0.2.10 and 192.0.2.11 send netbox_id 42 to different sites or locations, and 192.0.2.10 places it in rack R12"
	for name, tc := range map[string]struct {
		other, wantErr string
	}{
		"another location":                  {unracked("42", "location: Row 2"), moved},
		"another site":                      {unracked("42", "site: DC2"), moved},
		"no location":                       {unracked("42", ""), ""},
		"the same location":                 {unracked("42", "location: Row 1"), ""},
		"another netbox_id sharing the tag": {unracked("41", "location: Row 2"), ""},
	} {
		for _, rackedFirst := range []bool{true, false} {
			t.Run(name+"/racked first "+strconv.FormatBool(rackedFirst), func(t *testing.T) {
				targets := racked + "\n" + tc.other
				if !rackedFirst {
					targets = tc.other + "\n" + racked
				}
				_, err := newTestManager(t).ParsePolicies(rackPolicy("        site: DC1", targets))
				if tc.wantErr == "" {
					require.NoError(t, err)
					return
				}
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
			})
		}
	}
}

// A rack without a position is what a netbox_id target sends its device too.
func TestOneNetboxIDRackOnly(t *testing.T) {
	rackOnly := func(host, rack string) string {
		return "        - host: " + host + "\n          netbox_id: 42\n          override_defaults:\n            rack: " + rack
	}
	_, err := newTestManager(t).ParsePolicies(rackPolicy("        site: DC1",
		rackOnly("192.0.2.10", "R12")+"\n"+rackOnly("192.0.2.11", "R13")))
	require.Error(t, err)
	require.Contains(t, err.Error(), "place netbox_id 42 at different slots")

	_, err = newTestManager(t).ParsePolicies(rackPolicy("        site: DC1",
		rackOnly("192.0.2.10", "R12")+"\n"+rackOnly("192.0.2.11", "R12")))
	require.NoError(t, err, "one device in one rack, named twice")

	_, err = newTestManager(t).ParsePolicies(rackPolicy("        site: DC1",
		rackOnly("192.0.2.10", "R12")+"\n        - host: 192.0.2.11\n          netbox_id: 42"))
	require.NoError(t, err, "a target that sends no rack leaves the other's in place")
}
