package policy

import (
	"fmt"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/targets"
)

// maxPolicyAddresses bounds how many addresses one policy may expand to across
// every target it names. Expansion materialises every address before a single
// poll job exists, and each address then becomes a permanent recurring job, so
// a prefix such as a /8 costs roughly a gigabyte of strings up front and 16
// million jobs after that.
//
// The budget spans the policy rather than one entry. A per-target ceiling
// bounds a single target and nothing else: sixteen /16 entries each sit under
// it while the policy expands to 1048544 addresses, and the request body limit
// does not help because sixteen prefixes are a few hundred bytes. There is one
// number rather than a per-target ceiling and a larger policy-wide one, so
// there is one thing to reason about, and a policy needing more than 65536
// polled devices is already past what this backend should schedule.
//
// 65536 is a guard against the pathological cases, not a recommended size.
const maxPolicyAddresses = 65536

// checkPolicyExpansion rejects a policy whose targets together expand past
// maxPolicyAddresses, counting without expanding.
//
// Each count comes from targets.Count, which reads a target the way
// targets.Expand does rather than parsing the notation a second time, so no
// target shape can mean one thing to the guard and another to the expander.
// A target Count refuses is left to Expand, which says what is wrong with it.
// A blank host counts as the one address Expand returns for it and is refused
// by name in validatePolicy, which reads a target after normalizeTargetHosts
// has trimmed it, so all three read the same value.
//
// Every count is at most 2^32, so the slice would need 2^32 entries to
// overflow the uint64 total, far more than the process could hold.
func checkPolicyExpansion(entries []config.Target) error {
	var total uint64
	for _, entry := range entries {
		count, err := targets.Count(entry.Host)
		if err != nil {
			continue
		}
		total += count
	}
	if total > maxPolicyAddresses {
		return fmt.Errorf("policy targets expand to %d addresses in total, more than the limit of %d", total, maxPolicyAddresses)
	}
	return nil
}
