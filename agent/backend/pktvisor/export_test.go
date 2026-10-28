package pktvisor

import (
	"testing"

	"github.com/netboxlabs/orb-agent/agent/backend"
)

// KeepTap marks a managed tap as one cleanup must leave alone.
func KeepTap(be backend.Backend, tap string) {
	be.(*pktvisorBackend).keepTap(tap)
}

// SetApplyPolicyTimeout overrides the policy POST timeout for one test.
func SetApplyPolicyTimeout(t *testing.T, seconds int32) {
	t.Helper()
	old := applyPolicyTimeout
	applyPolicyTimeout = seconds
	t.Cleanup(func() { applyPolicyTimeout = old })
}
