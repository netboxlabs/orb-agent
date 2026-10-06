package policy

import (
	"context"
	"log/slog"
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

	t.Run("a numeric rack name is read as written", func(t *testing.T) {
		policies, err := newTestManager(t).ParsePolicies(rackPolicy("        rack: 12",
			"        - host: 192.0.2.10\n          override_defaults:\n            rack: 012\n            position: 40\n            face: front"))
		require.NoError(t, err)
		p := policies["p1"]
		require.Equal(t, "12", p.Config.Defaults.Rack)
		require.Equal(t, "012", p.Scope.Targets[0].OverrideDefaults.Rack)
	})
}
