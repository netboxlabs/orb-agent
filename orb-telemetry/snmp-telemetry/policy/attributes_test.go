package policy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
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
      authentication:
        protocol_version: v2c
        community: public
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

func TestParsePolicies_AcceptsScopeAndTargetAttributes(t *testing.T) {
	m := newTestManager()
	got, err := m.ParsePolicies([]byte(attributePolicy(
		"        site: dc-west\n        rack_units: 2",
		"            site: dc-east\n            monitored: true",
	)))
	require.NoError(t, err)
	pol := got["edge-metrics"]
	assert.Equal(t, config.Attributes{"site": "dc-west", "rack_units": 2}, pol.Scope.Attributes)
	assert.Equal(t, config.Attributes{"site": "dc-east", "monitored": true}, pol.Scope.Targets[1].Attributes)
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

// Every key the backend sets itself is refused, in the scope and on a target:
// a polled series' identity and row index, the scope's policy_name, and a
// received trap series' own dimensions.
func TestParsePolicies_RefusesReservedAttributeKeys(t *testing.T) {
	for _, key := range []string{"device_ip", "device_port", "netbox_id", "snmp_context", "row_index", "policy_name", "trap_name", "version"} {
		_, err := newTestManager().ParsePolicies([]byte(attributePolicy("        "+key+": x", "            role: edge")))
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), fmt.Sprintf(`scope: attribute key %q is reserved`, key))

		_, err = newTestManager().ParsePolicies([]byte(attributePolicy("        site: dc-west", "            "+key+": x")))
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), fmt.Sprintf(`target 192.0.2.2 (id dev-2): attribute key %q is reserved`, key))
	}
}

// profileSpy is a collector whose profile set exports the attribute keys it
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

// A key that lands on a profile's attribute once translated to Prometheus is
// refused too, naming both.
func TestNewRunner_RefusesAKeyThatBecomesAProfileAttribute(t *testing.T) {
	spy := &profileSpy{exported: map[string]string{"chassis_model": "vendor-a.yml"}}
	pol := minimalPolicy(v2cAuth())
	pol.Scope.Attributes = config.Attributes{"chassis.model": "x"}
	_, err := NewRunner(t.Context(), testLogger, "edge-metrics", pol, spy, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `edge-metrics: invalid policy: scope: attribute key "chassis.model" becomes "chassis_model" in Prometheus, which the SNMP profile vendor-a.yml exports`)
}

// NewRunner checks the attributes again, as it does the interval and the
// expansion, so a direct caller cannot slip past ParsePolicies.
func TestNewRunner_ValidatesTheAttributes(t *testing.T) {
	pol := minimalPolicy(v2cAuth())
	pol.Scope.Attributes = config.Attributes{"site": nil}
	_, err := NewRunner(t.Context(), testLogger, "edge-metrics", pol, &spyCollector{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `edge-metrics: invalid policy: scope: attribute "site" has no value`)

	pol = minimalPolicy(v2cAuth())
	pol.Scope.Targets[0].Attributes = config.Attributes{"device_ip": "x"}
	_, err = NewRunner(t.Context(), testLogger, "edge-metrics", pol, &spyCollector{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `target 192.168.1.1: attribute key "device_ip" is reserved`)
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

// An entry's attributes are rendered once and shared by every device it
// expands to, the collection and the trap claims alike.
func TestExpandTargets_RendersAnEntrysAttributesOnce(t *testing.T) {
	scope := policyWithTargetEntries(config.Target{Host: "10.0.0.0/30", Attributes: config.Attributes{"role": "edge"}}).Scope
	scope.Attributes = config.Attributes{"site": "dc-west"}
	r := &Runner{name: "p1", scope: scope}
	expanded, _, err := r.expandTargets()
	require.NoError(t, err)
	require.Len(t, expanded, 2)
	want := []attribute.KeyValue{attribute.String("role", "edge"), attribute.String("site", "dc-west")}
	assert.Equal(t, want, expanded[0].RenderedAttributes)
	assert.Same(t, &expanded[0].RenderedAttributes[0], &expanded[1].RenderedAttributes[0], "one rendering per entry")

	devices := trapDevices(r, expanded)
	require.Len(t, devices, 2)
	assert.Same(t, &devices[0].Attributes[0], &devices[1].Attributes[0], "the trap claims share it")
}

// A key the profile set exports is refused when the policy starts, naming the
// profile, since on a device that profile matches the two would claim one
// attribute.
func TestNewRunner_RefusesAnAttributeTheProfilesExport(t *testing.T) {
	spy := &profileSpy{exported: map[string]string{"model": "vendor-a.yml", "ifOperStatus_status": "vendor-b.yml"}}

	pol := minimalPolicy(v2cAuth())
	pol.Scope.Attributes = config.Attributes{"model": "x"}
	_, err := NewRunner(t.Context(), testLogger, "edge-metrics", pol, spy, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `edge-metrics: invalid policy: scope: attribute key "model" is exported by the SNMP profile vendor-a.yml`)

	pol = minimalPolicy(v2cAuth())
	pol.Scope.Targets[0].ID = "dev-1"
	pol.Scope.Targets[0].Attributes = config.Attributes{"ifOperStatus_status": "x"}
	_, err = NewRunner(t.Context(), testLogger, "edge-metrics", pol, spy, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `edge-metrics: invalid policy: target 192.168.1.1 (id dev-1): attribute key "ifOperStatus_status" is exported by the SNMP profile vendor-b.yml`)

	pol = minimalPolicy(v2cAuth())
	pol.Scope.Attributes = config.Attributes{"site": "dc-west"}
	r, err := NewRunner(t.Context(), testLogger, "edge-metrics", pol, spy, nil)
	require.NoError(t, err)
	require.NoError(t, r.Stop())
}

// Against the bundled profile set, a key one of its profiles tags with is
// refused before anything is scheduled. The README names these two.
func TestStartPolicy_RefusesABundledProfileTag(t *testing.T) {
	m := newTestManager()
	t.Cleanup(func() { _ = m.Stop() })
	for _, key := range []string{"model", "serial_number"} {
		pol := minimalPolicy(v2cAuth())
		pol.Scope.Attributes = config.Attributes{key: "x"}
		err := m.StartPolicy("edge-metrics", pol)
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), fmt.Sprintf(`scope: attribute key %q is exported by the SNMP profile`, key))
		assert.False(t, m.HasPolicy("edge-metrics"))
	}

	pol := minimalPolicy(v2cAuth())
	pol.Scope.Attributes = config.Attributes{"netbox.site": "dc-west"}
	require.NoError(t, m.StartPolicy("edge-metrics", pol))
}

// Each expanded device carries its entry's attributes laid over the scope's.
func TestExpandTargets_MergesTheScopesAttributesUnderEachTargets(t *testing.T) {
	scope := policyWithTargetEntries(
		config.Target{Host: "10.0.0.0/30", Attributes: config.Attributes{"site": "dc-east", "role": "edge"}},
		config.Target{Host: "10.0.0.9"},
	).Scope
	scope.Attributes = config.Attributes{"site": "dc-west", "tenant": "tenant-a"}
	r := &Runner{scope: scope}
	expanded, _, err := r.expandTargets()
	require.NoError(t, err)
	require.Len(t, expanded, 3)
	for _, target := range expanded[:2] {
		assert.Equal(t, config.Attributes{"site": "dc-east", "role": "edge", "tenant": "tenant-a"}, target.Attributes, target.Host)
	}
	assert.Equal(t, config.Attributes{"site": "dc-west", "tenant": "tenant-a"}, expanded[2].Attributes, "scope only")

	r = &Runner{scope: policyWithTargetEntries(config.Target{Host: "10.0.0.9", Attributes: config.Attributes{"role": "edge"}}).Scope}
	expanded, _, err = r.expandTargets()
	require.NoError(t, err)
	assert.Equal(t, config.Attributes{"role": "edge"}, expanded[0].Attributes, "target only")
}

// Two entries collapsing into one device have to agree on its attributes:
// keeping either would drop what the other says about the device.
func TestExpandTargets_RefusesOneDeviceGivenTwoSetsOfAttributes(t *testing.T) {
	r := &Runner{name: "edge-metrics", scope: policyWithTargetEntries(
		config.Target{Host: "10.0.0.0/30", Attributes: config.Attributes{"site": "dc-west"}},
		config.Target{Host: "10.0.0.2", Attributes: config.Attributes{"site": "dc-east"}},
	).Scope}
	_, _, err := r.expandTargets()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "edge-metrics: invalid policy: targets 10.0.0.0/30 and 10.0.0.2 both name 10.0.0.2:161 with different attributes")

	r = &Runner{name: "edge-metrics", scope: policyWithTargetEntries(
		config.Target{Host: "10.0.0.0/30", Attributes: config.Attributes{"site": "dc-west"}},
		config.Target{Host: "10.0.0.2", Attributes: config.Attributes{"site": "dc-west"}},
	).Scope}
	expanded, collapsed, err := r.expandTargets()
	require.NoError(t, err, "agreeing entries collapse as before")
	assert.Len(t, expanded, 2)
	assert.Equal(t, 1, collapsed)
}

// A policy receiving traps hands the pool each device's merged attributes,
// so its received series carry them too.
func TestRunner_TrapDevicesCarryTheirTargetsAttributes(t *testing.T) {
	pool := newSpyPool()
	pol := withTraps(policyWithTargetEntries(
		config.Target{Host: "10.0.0.1", Attributes: config.Attributes{"role": "edge"}},
		config.Target{Host: "10.0.0.2"},
	), ":1162")
	pol.Scope.Attributes = config.Attributes{"site": "dc-west"}
	r, err := NewRunner(t.Context(), testLogger, "p1", pol, &spyCollector{}, pool)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Stop() })

	devices := pool.devices["p1"]
	require.Len(t, devices, 2)
	assert.Equal(t, []attribute.KeyValue{attribute.String("role", "edge"), attribute.String("site", "dc-west")}, devices[0].Attributes)
	assert.Equal(t, []attribute.KeyValue{attribute.String("site", "dc-west")}, devices[1].Attributes)
}
