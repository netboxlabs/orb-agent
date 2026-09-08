package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// addressablePolicyNames survive DELETE /policies/:policy. The server package
// puts every one of them through the real router, so this list is a claim about
// routing rather than a taste in names.
var addressablePolicyNames = []string{
	"gnmi_metrics_1",
	"policy-a",
	"a b",
	"café",
	"a.b",
	"...",
	// A percent sequence is escaped again by the client and comes back
	// unchanged, so a name that merely looks like an encoded slash is fine.
	"a%2Fb",
	"a?b",
	"a#b",
	"a:b",
	"a&b",
	"a+b",
	"a=b",
	" padded ",
}

// unaddressablePolicyNames cannot be reached by DELETE /policies/:policy, so a
// policy started under one of them can only be removed by restarting.
var unaddressablePolicyNames = []string{
	"",
	" ",
	"\t\n",
	"a/b",
	"/a",
	"a/",
	"a//b",
	".",
	"..",
}

func TestValidatePolicyName_AcceptsEveryAddressableName(t *testing.T) {
	for _, name := range addressablePolicyNames {
		assert.NoError(t, ValidatePolicyName(name), "name %q is addressable", name)
	}
}

func TestValidatePolicyName_RejectsEveryUnaddressableName(t *testing.T) {
	for _, name := range unaddressablePolicyNames {
		assert.Error(t, ValidatePolicyName(name), "name %q cannot be addressed", name)
	}
}

func namedPolicyBody(name string) []byte {
	return fmt.Appendf(nil, `
policies:
  %q:
    config:
      metrics_interval: 30
    scope:
      targets:
        - host: 192.0.2.1
`, name)
}

// The YAML map key becomes the policy name with no check of its own, so a name
// no route can address started successfully and then could not be deleted or
// replaced without restarting the backend.
func TestParsePolicies_RejectsANameNoRouteCanAddress(t *testing.T) {
	m := newTestManager()
	for _, name := range unaddressablePolicyNames {
		_, err := m.ParsePolicies(namedPolicyBody(name))
		require.Error(t, err, "name %q was accepted", name)
		assert.ErrorContains(t, err, "policy name", "name %q: %v", name, err)
	}
}

func TestParsePolicies_AcceptsAnAddressableName(t *testing.T) {
	m := newTestManager()
	for _, name := range addressablePolicyNames {
		policies, err := m.ParsePolicies(namedPolicyBody(name))
		require.NoError(t, err, "name %q was rejected", name)
		assert.Contains(t, policies, name)
	}
}

// StartPolicy is the call that inserts the name into the manager's map, so it
// carries the check as well: a caller that does not go through ParsePolicies
// cannot slip an unaddressable name past it.
func TestStartPolicy_RejectsANameNoRouteCanAddress(t *testing.T) {
	pol := minimalPolicy()
	for _, name := range unaddressablePolicyNames {
		m := newTestManager()
		require.ErrorContains(t, m.StartPolicy(name, pol), "policy name", "name %q was started", name)
		assert.Empty(t, m.policies)
	}
}
