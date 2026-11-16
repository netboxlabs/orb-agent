package policy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
)

// attributePolicy is a policy body with a scope attribute block and two
// targets, the second carrying a block of its own.
func attributePolicy(scopeAttrs, targetAttrs string) string {
	return fmt.Sprintf(`
policies:
  edge-metrics:
    config:
      metrics_interval: 60
    scope:
      username: admin
      attributes:
%s
      targets:
        - host: 192.0.2.1
        - host: 192.0.2.2
          id: dev-2
          attributes:
%s
`, scopeAttrs, targetAttrs)
}

// Each target carries the scope's attributes beneath its own once parsed,
// merged key by key.
func TestParsePolicies_MergesTheScopesAttributesUnderEachTargetsOwn(t *testing.T) {
	m := newTestManager()
	got, err := m.ParsePolicies([]byte(attributePolicy(
		"        site: dc-west\n        tenant: tenant-a",
		"            site: dc-east\n            rack_units: 2",
	)))
	require.NoError(t, err)
	pol := got["edge-metrics"]
	assert.Equal(t, config.Attributes{"site": "dc-west", "tenant": "tenant-a"}, pol.Scope.Targets[0].Attributes, "scope only")
	assert.Equal(t, config.Attributes{"site": "dc-east", "tenant": "tenant-a", "rack_units": 2}, pol.Scope.Targets[1].Attributes)
}

// A refusal names the policy, where the attribute is and its key, so it can
// be found in a policy that sets many.
func TestParsePolicies_RefusesAnAttributeItCannotExport(t *testing.T) {
	cases := []struct {
		name, scope, target string
		want                []string
	}{
		{
			name:   "null in the scope",
			scope:  "        site: ~",
			target: "            role: edge",
			want:   []string{"edge-metrics: invalid policy", "scope:", `attribute "site" has no value`},
		},
		{
			name:   "map on a target",
			scope:  "        site: dc-west",
			target: "            site: {name: dc-east}",
			want:   []string{"edge-metrics: invalid policy", "target 192.0.2.2 (id dev-2):", `attribute "site" is a map`},
		},
		{
			name:   "list on a target",
			scope:  "        site: dc-west",
			target: "            tags: [a, b]",
			want:   []string{"target 192.0.2.2 (id dev-2):", `attribute "tags" is a list`},
		},
		{
			name:   "empty key",
			scope:  `        "": x`,
			target: "            role: edge",
			want:   []string{"scope:", "attribute key is empty"},
		},
		{
			name:   "invalid UTF-8 key",
			scope:  "        site: dc-west",
			target: "            ? !!binary /w==\n            : x",
			want:   []string{"target 192.0.2.2 (id dev-2):", "is not valid UTF-8"},
		},
		{
			name:   "empty string",
			scope:  `        site: ""`,
			target: "            role: edge",
			want:   []string{"scope:", `attribute "site" is an empty string`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTestManager().ParsePolicies([]byte(attributePolicy(tc.scope, tc.target)))
			require.Error(t, err)
			for _, want := range tc.want {
				assert.Contains(t, err.Error(), want)
			}
		})
	}
}

// Every key the collector sets itself is refused, in the scope and on a
// target: the device and its NetBox id, the scope's policy_name, and
// target_up's mode.
func TestParsePolicies_RefusesReservedAttributeKeys(t *testing.T) {
	for _, key := range []string{"device_ip", "netbox_id", "policy_name", "mode"} {
		_, err := newTestManager().ParsePolicies([]byte(attributePolicy("        "+key+": x", "            role: edge")))
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), fmt.Sprintf(`scope: attribute key %q is reserved`, key))

		_, err = newTestManager().ParsePolicies([]byte(attributePolicy("        site: dc-west", "            "+key+": x")))
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), fmt.Sprintf(`target 192.0.2.2 (id dev-2): attribute key %q is reserved`, key))
	}
}

// profileSpy is a collector whose profile set promotes the attribute keys it
// is given.
type profileSpy struct {
	spyCollector
	exported map[string]string
}

func (p *profileSpy) ProfileAttribute(key string) (name, profile string, ok bool) {
	if profile, ok := p.exported[key]; ok {
		return key, profile, true
	}
	for name, profile := range p.exported {
		if config.PrometheusName(name) == config.PrometheusName(key) {
			return name, profile, true
		}
	}
	return "", "", false
}

// A key that lands on a promoted attribute once translated to Prometheus is
// refused too, naming both.
func TestNewRunner_RefusesAKeyThatBecomesAProfileAttribute(t *testing.T) {
	spy := &profileSpy{exported: map[string]string{"interface_name": "_base"}}
	pol := minimalPolicy()
	pol.Scope.Attributes = config.Attributes{"interface.name": "x"}
	_, err := NewRunner(t.Context(), testLogger, "edge-metrics", pol, spy, testDialer())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `edge-metrics: invalid policy: scope: attribute key "interface.name" becomes "interface_name" in Prometheus, which the gNMI profile _base exports`)
}

// NewRunner checks the attributes again, as it does the interval and the
// expansion, so a direct caller cannot slip past ParsePolicies.
func TestNewRunner_ValidatesTheAttributes(t *testing.T) {
	pol := minimalPolicy()
	pol.Scope.Attributes = config.Attributes{"site": nil}
	_, err := NewRunner(t.Context(), testLogger, "edge-metrics", pol, &spyCollector{}, testDialer())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `edge-metrics: invalid policy: scope: attribute "site" has no value`)
}

// The limit on a target's attributes counts the scope's, and keys colliding
// in Prometheus collide across the scope and a target too.
func TestParsePolicies_ChecksATargetsAttributesWithTheScopes(t *testing.T) {
	var scope, target strings.Builder
	for i := range 20 {
		fmt.Fprintf(&scope, "        s%02d: x\n", i)
		fmt.Fprintf(&target, "            t%02d: x\n", i)
	}
	_, err := newTestManager().ParsePolicies([]byte(attributePolicy(strings.TrimSuffix(scope.String(), "\n"), strings.TrimSuffix(target.String(), "\n"))))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target 192.0.2.2 (id dev-2): carries 40 attributes, more than the limit of 32")

	_, err = newTestManager().ParsePolicies([]byte(attributePolicy("        netbox.site: dc-west", "            netbox_site: dc-east")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `target 192.0.2.2 (id dev-2): attribute keys "netbox.site" and "netbox_site" both become "netbox_site" in Prometheus`)

	_, err = newTestManager().ParsePolicies([]byte(attributePolicy("        device.ip: x", "            role: edge")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `scope: attribute key "device.ip" becomes "device_ip" in Prometheus`)
}

// rangePolicy is a body of range targets, each "host=role" with the role as
// its attribute.
func rangePolicy(entries ...string) string {
	var b strings.Builder
	b.WriteString("policies:\n  edge-metrics:\n    config:\n      metrics_interval: 60\n    scope:\n      username: admin\n      targets:\n")
	for _, e := range entries {
		host, role, _ := strings.Cut(e, "=")
		fmt.Fprintf(&b, "        - host: %s\n          attributes:\n            role: %s\n", host, role)
	}
	return b.String()
}

// Two ranges sharing an address give the device that address is one of two
// sets of attributes, and the sweep keeps whichever entry it expanded first.
// The overlap is arithmetic on the ranges, so it is refused at apply, as SNMP
// refuses two entries collapsing into one device.
func TestParsePolicies_RefusesOverlappingRangesWithDifferentAttributes(t *testing.T) {
	_, err := newTestManager().ParsePolicies([]byte(rangePolicy("10.0.0.10-20=edge", "10.0.0.15-30=core")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "edge-metrics: invalid policy: targets 10.0.0.10-20 and 10.0.0.15-30 both name 10.0.0.15 with different attributes; give them the same attributes, or split the ranges so they share no address")

	// Overlap is found across entries that do not touch each other directly:
	// the third shares addresses with the second alone.
	_, err = newTestManager().ParsePolicies([]byte(rangePolicy("10.0.0.10-20=edge", "10.0.0.18-30=edge", "10.0.0.25-40=core")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "targets 10.0.0.18-30 and 10.0.0.25-40 both name 10.0.0.25 with different attributes")

	// A range nested in a wider one ends first; the wider one is still open
	// when a later range starts, and that later range conflicts with it.
	_, err = newTestManager().ParsePolicies([]byte(rangePolicy("10.0.0.0/24=edge", "10.0.0.10-20=edge", "10.0.0.50-60=core")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "targets 10.0.0.0/24 and 10.0.0.50-60 both name 10.0.0.50 with different attributes")

	_, err = newTestManager().ParsePolicies([]byte(rangePolicy("10.0.0.0/24=edge", "10.0.0.20-40=core")))
	require.Error(t, err, "a prefix and a range overlap too")

	// Naming the shared address in a target of its own settles that address
	// and no other the two ranges share, so it does not clear the refusal.
	_, err = newTestManager().ParsePolicies([]byte(rangePolicy("10.0.0.10-20=edge", "10.0.0.20-30=core", "10.0.0.20=pin")))
	require.Error(t, err, "a pinned address does not excuse two overlapping ranges")

	for _, ok := range [][]string{
		{"10.0.0.10-20=edge", "10.0.0.15-30=edge"},
		{"10.0.0.10-20=edge", "10.0.0.21-30=core"},
		{"10.0.0.0/24=edge", "10.0.0.5=core"},
	} {
		_, err := newTestManager().ParsePolicies([]byte(rangePolicy(ok...)))
		require.NoError(t, err, ok)
	}
}

// A key the profile set promotes is refused when the policy starts, naming
// the profile, since on a target that profile serves the two would claim one
// attribute.
func TestNewRunner_RefusesAnAttributeTheProfilesPromote(t *testing.T) {
	spy := &profileSpy{exported: map[string]string{"interface_name": "_base", "slot": "vendor-b"}}

	pol := minimalPolicy()
	pol.Scope.Attributes = config.Attributes{"interface_name": "x"}
	_, err := NewRunner(t.Context(), testLogger, "edge-metrics", pol, spy, testDialer())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `edge-metrics: invalid policy: scope: attribute key "interface_name" is exported by the gNMI profile _base`)

	pol = minimalPolicy()
	pol.Scope.Targets[0].ID = "dev-1"
	pol.Scope.Targets[0].Attributes = config.Attributes{"slot": "x"}
	_, err = NewRunner(t.Context(), testLogger, "edge-metrics", pol, spy, testDialer())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `edge-metrics: invalid policy: target 192.168.1.1 (id dev-1): attribute key "slot" is exported by the gNMI profile vendor-b`)

	pol = minimalPolicy()
	pol.Scope.Attributes = config.Attributes{"site": "dc-west"}
	_, err = NewRunner(t.Context(), testLogger, "edge-metrics", pol, spy, testDialer())
	require.NoError(t, err)
}

// Against the bundled profile set, a key one of its profiles promotes is
// refused before anything subscribes. The README names these.
func TestStartPolicy_RefusesABundledProfileAttribute(t *testing.T) {
	m := newTestManager()
	t.Cleanup(func() { _ = m.Stop() })
	for _, key := range []string{"interface_name", "component_name"} {
		pol := minimalPolicy()
		pol.Scope.Attributes = config.Attributes{key: "x"}
		err := m.StartPolicy("edge-metrics", pol)
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), fmt.Sprintf(`scope: attribute key %q is exported by the gNMI profile _base`, key))
		assert.False(t, m.HasPolicy("edge-metrics"))
	}

	pol := minimalPolicy()
	pol.Scope.Attributes = config.Attributes{"netbox.site": "dc-west"}
	require.NoError(t, m.StartPolicy("edge-metrics", pol))
}

// A device pinned inside a range keeps its own attributes over the range's,
// as it keeps its own port and credentials.
func TestExpandTargets_APinnedTargetKeepsItsOwnAttributes(t *testing.T) {
	scope := config.Scope{Attributes: config.Attributes{"site": "dc-west"}}
	pol := minimalPolicy()
	pol.Scope.Targets = []config.Target{
		config.EffectiveTarget(scope, config.Target{Host: "10.0.0.0/30", Attributes: config.Attributes{"role": "access"}}),
		config.EffectiveTarget(scope, config.Target{Host: "10.0.0.2", Attributes: config.Attributes{"role": "edge"}}),
	}
	r := &Runner{policy: pol, logger: testLogger}
	got, err := r.expandTargets()
	require.NoError(t, err)
	byHost := map[string]config.Attributes{}
	for _, c := range got {
		byHost[c.target.Host] = c.target.Attributes
	}
	assert.Equal(t, config.Attributes{"site": "dc-west", "role": "access"}, byHost["10.0.0.1"])
	assert.Equal(t, config.Attributes{"site": "dc-west", "role": "edge"}, byHost["10.0.0.2"])
}
