package profiles

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestBundledProfilesLoadAndValidate(t *testing.T) {
	store, err := LoadProfiles("", quiet())
	require.NoError(t, err)
	for _, name := range []string{"_base", "nokia_srlinux", "arista_eos", "cisco", "juniper"} {
		p, ok := store.Get(name)
		require.True(t, ok, name)
		assert.NoError(t, p.Validate(), name)
	}
	base, _ := store.Get("_base")
	names := map[string]bool{}
	for _, s := range base.Subscriptions {
		for _, m := range s.Metrics {
			assert.False(t, names[m.Name], "duplicate metric name %s", m.Name)
			names[m.Name] = true
		}
	}
	for _, want := range []string{"if_in_octets", "if_oper_status", "if_admin_status", "cpu_utilization", "memory_physical", "temperature", "component_oper_status"} {
		assert.True(t, names[want], want)
	}
	for _, s := range base.Subscriptions {
		if s.Mode == "on_change" {
			require.Len(t, s.Metrics, 1, "an on_change subscription names one leaf: %s", s.Path)
			assert.Equal(t, ".", s.Metrics[0].Leaf, s.Path)
		}
	}
}

// A NOS is not a hardware manufacturer, so Capabilities never sets Vendor from
// one and an overlay written for a NOS is unreachable unless the matcher reads
// it. It carries no vendor criteria, so it must not answer a vendor either.
func TestMatchPrefersTheNOS(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme_nos.yaml"), []byte(`
extends: _base
match: {nos: sonic}
`), 0o644))
	store, err := LoadProfiles(dir, quiet())
	require.NoError(t, err)
	assert.Equal(t, "acme_nos", store.Match(MatchInput{NOS: "SONiC"}).Name, "the NOS selects its overlay, case-insensitively")
	assert.Equal(t, "_base", store.Match(MatchInput{Vendor: "acme"}).Name, "a NOS overlay names no vendor, so no vendor selects it")
}

func TestOverlayReplacesBySubscriptionPathAndAddsNewOnes(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(`
extends: _base
match: {vendor: acme}
subscriptions:
  - path: /interfaces/interface[name=*]/state/counters
    mode: sample
    attributes: {interface_name: name}
    metrics:
      - {leaf: in-octets, name: if_in_octets, type: counter, unit: By}
  - path: /acme/native/thing
    mode: sample
    origin: ""
    metrics:
      - {leaf: value, name: acme_value, type: gauge}
`), 0o644))
	store, err := LoadProfiles(dir, quiet())
	require.NoError(t, err)
	base, _ := store.Get("_base")
	acme, ok := store.Get("acme")
	require.True(t, ok)
	assert.Equal(t, len(base.Subscriptions)+1, len(acme.Subscriptions), "one replaced, one added")
	var counters, native *Subscription
	for i := range acme.Subscriptions {
		switch acme.Subscriptions[i].Path {
		case "/interfaces/interface[name=*]/state/counters":
			counters = &acme.Subscriptions[i]
		case "/acme/native/thing":
			native = &acme.Subscriptions[i]
		}
	}
	require.NotNil(t, counters)
	assert.Len(t, counters.Metrics, 1, "the overlay's subscription replaced the base one wholesale")
	require.NotNil(t, native)
	require.NotNil(t, native.Origin)
	assert.Equal(t, "", *native.Origin, "the added subscription keeps its own origin")
	assert.Equal(t, "acme", acme.Match.Vendor)
	assert.Equal(t, "acme", store.Match(MatchInput{Vendor: "ACME Corp"}).Name)
}

func TestBundledSrlOverlayAddsTheNativeMemorySubscription(t *testing.T) {
	store, err := LoadProfiles("", quiet())
	require.NoError(t, err)
	srl, _ := store.Get("nokia_srlinux")
	base, _ := store.Get("_base")
	assert.Equal(t, len(base.Subscriptions)+1, len(srl.Subscriptions))
	assert.Equal(t, "nokia", srl.Match.Vendor)
	assert.Equal(t, "nokia_srlinux", store.Match(MatchInput{Vendor: "Nokia"}).Name)
	assert.Equal(t, "_base", store.Match(MatchInput{Vendor: "Unknown Vendor"}).Name)
}

func TestOverrideDirReplacesTheBaseProfile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "_base.yaml"), []byte(`
match: {}
subscriptions:
  - path: /interfaces/interface[name=*]/state/counters
    mode: sample
    attributes: {interface_name: name}
    metrics:
      - {leaf: in-octets, name: if_in_octets, type: counter, unit: By}
`), 0o644))
	store, err := LoadProfiles(dir, quiet())
	require.NoError(t, err)
	base, _ := store.Get("_base")
	require.Len(t, base.Subscriptions, 1)
	assert.Len(t, base.Subscriptions[0].Metrics, 1)
}

func TestValidateRejectsBadProfiles(t *testing.T) {
	one := func(m ...Metric) []Subscription { return []Subscription{{Path: "/a", Mode: "sample", Metrics: m}} }
	cases := []struct {
		name string
		p    Profile
		want string
	}{
		{"unknown type", Profile{Name: "x", Subscriptions: one(Metric{Leaf: "l", Name: "n", Type: "histogram"})}, `metric "n": type "histogram" is not counter or gauge`},
		{"unknown mode", Profile{Name: "x", Subscriptions: []Subscription{{Path: "/a", Mode: "target_defined", Metrics: []Metric{{Leaf: "l", Name: "n", Type: "gauge"}}}}}, `subscription "/a": mode "target_defined" is not sample or on_change`},
		{"duplicate name", Profile{Name: "x", Subscriptions: one(Metric{Leaf: "l", Name: "n", Type: "gauge"}, Metric{Leaf: "m", Name: "n", Type: "gauge"})}, `metric "n" is declared twice`},
		{"bad name", Profile{Name: "x", Subscriptions: one(Metric{Leaf: "l", Name: "In Octets", Type: "gauge"})}, `metric "In Octets": name must be lower-case letters, digits and underscores`},
		{"enum on counter", Profile{Name: "x", Subscriptions: one(Metric{Leaf: "l", Name: "n", Type: "counter", Enum: map[string]int64{"UP": 1}})}, `metric "n": enum and bool apply to gauges only`},
		{"no metrics", Profile{Name: "x", Subscriptions: []Subscription{{Path: "/a", Mode: "sample"}}}, `subscription "/a": no metrics`},
		{"empty path", Profile{Name: "x", Subscriptions: []Subscription{{Path: "", Mode: "sample", Metrics: []Metric{{Leaf: "l", Name: "n", Type: "gauge"}}}}}, `subscription 1: path is required`},
		{"dot leaf with siblings", Profile{Name: "x", Subscriptions: one(Metric{Leaf: ".", Name: "a", Type: "gauge"}, Metric{Leaf: "l", Name: "b", Type: "gauge"})}, `subscription "/a": a "." leaf must be the only metric`},
		{"attribute_key_absent", Profile{Name: "x", Subscriptions: []Subscription{{
			Path: "/interfaces/interface[name=*]/state/counters", Mode: "sample",
			Attributes: map[string]string{"interface_name": "ifname"},
			Metrics:    []Metric{{Leaf: "in-octets", Name: "n", Type: "counter"}},
		}}}, `attribute interface_name names key ifname, which the path does not carry`},
		{"attribute_name_reserved", Profile{Name: "x", Subscriptions: []Subscription{{
			Path: "/interfaces/interface[name=*]/state/counters", Mode: "sample",
			Attributes: map[string]string{"device_ip": "name"},
			Metrics:    []Metric{{Leaf: "in-octets", Name: "n", Type: "counter"}},
		}}}, `attribute device_ip is set by the collector`},
		// Two nested lists keyed alike: a match reports one value per key name,
		// so the inner element's wins and both attributes carry the interface
		// name, collapsing every instance onto one series.
		{"attribute_key_ambiguous", Profile{Name: "x", Subscriptions: []Subscription{{
			Path: "/network-instances/network-instance[name=*]/interfaces/interface[name=*]", Mode: "sample",
			Attributes: map[string]string{"instance_name": "name", "interface_name": "name"},
			Metrics:    []Metric{{Leaf: "state/counters/in-octets", Name: "n", Type: "counter"}},
		}}}, `attribute instance_name names key name, which more than one element of the path carries; keys must be unique along the path`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
	empty := Profile{Name: "arista_eos", Extends: "_base", Match: Match{Vendor: "arista"}}
	assert.NoError(t, empty.Validate(), "a placeholder overlay with no subscriptions is valid")

	distinct := Profile{Name: "x", Subscriptions: []Subscription{{
		Path: "/network-instances/network-instance[name=*]/interfaces/interface[id=*]", Mode: "sample",
		Attributes: map[string]string{"instance_name": "name", "interface_id": "id"},
		Metrics:    []Metric{{Leaf: "state/counters/in-octets", Name: "n", Type: "counter"}},
	}}}
	assert.NoError(t, distinct.Validate(), "two nested lists keyed by different names are unambiguous")
}

func TestInvalidOverrideKeepsTheBundledProfile(t *testing.T) {
	dir := t.TempDir()
	// enum on a counter is invalid, so this override of a bundled profile is
	// skipped and the bundled nokia_srlinux, base included, survives.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nokia_srlinux.yaml"), []byte(`
extends: _base
match: {vendor: nokia}
subscriptions:
  - path: /platform/control[slot=*]/memory
    mode: sample
    origin: ""
    metrics:
      - {leaf: free, name: memory_free_native, type: counter, enum: {A: 1}}
`), 0o644))
	store, err := LoadProfiles(dir, quiet())
	require.NoError(t, err)
	srl, ok := store.Get("nokia_srlinux")
	require.True(t, ok)
	var counters, memory *Subscription
	for i := range srl.Subscriptions {
		switch srl.Subscriptions[i].Path {
		case "/interfaces/interface[name=*]/state/counters":
			counters = &srl.Subscriptions[i]
		case "/platform/control[slot=*]/memory":
			memory = &srl.Subscriptions[i]
		}
	}
	require.NotNil(t, counters, "the base's counters are inherited")
	require.NotNil(t, memory, "the bundled overlay's native subscription survives")
	var native *Metric
	for i := range memory.Metrics {
		if memory.Metrics[i].Name == "memory_free_native" {
			native = &memory.Metrics[i]
		}
	}
	require.NotNil(t, native, "the bundled overlay's metric survives")
	assert.Equal(t, "gauge", native.Type, "the bundled metric, not the invalid override's")
}

func TestInvalidNewOverrideIsSkipped(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(`
extends: _base
match: {vendor: acme}
subscriptions:
  - path: /acme/native/thing
    mode: sample
    metrics:
      - {leaf: value, name: acme_value, type: counter, enum: {A: 1}}
`), 0o644))
	store, err := LoadProfiles(dir, quiet())
	require.NoError(t, err, "an invalid new override is skipped, not fatal")
	assert.NotContains(t, store.Names(), "acme")
	_, ok := store.Get("_base")
	assert.True(t, ok)
}

func TestAnInvalidBaseOverrideFallsBackToTheBundledBase(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "_base.yaml"), []byte(`
match: {}
subscriptions:
  - path: /interfaces/interface[name=*]/state/counters
    mode: sample
    metrics:
      - {leaf: in-octets, name: if_in_octets, type: counter, enum: {A: 1}}
`), 0o644))
	store, err := LoadProfiles(dir, quiet())
	require.NoError(t, err, "a bad shared parent is skipped, not fatal")
	base, ok := store.Get("_base")
	require.True(t, ok)
	assert.Greater(t, len(base.Subscriptions), 1, "the bundled base, not the override")
	srl, ok := store.Get("nokia_srlinux")
	require.True(t, ok, "children of the bad parent survive")
	assert.NoError(t, srl.Validate())
}
