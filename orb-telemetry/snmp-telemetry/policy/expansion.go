package policy

import (
	"fmt"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/targets"
)

// maxTargetAddresses bounds how many addresses one policy target may expand to.
// Expansion materialises every address before a single poll job exists, and
// each address then becomes a permanent recurring job, so a prefix such as a /8
// costs roughly a gigabyte of strings up front and 16 million jobs after that.
// A /16 is far beyond any reasonable polling policy; the limit is a guard
// against the pathological cases, not a recommended size.
const maxTargetAddresses = 65536

// checkTargetExpansion rejects a target that expands past maxTargetAddresses.
// The count comes from targets.Count, which reads a target the way
// targets.Expand does rather than parsing the notation a second time, so no
// target shape can mean one thing to the guard and another to the expander.
// A target Count refuses is left to Expand, which says what is wrong with it.
func checkTargetExpansion(target string) error {
	count, err := targets.Count(target)
	if err != nil {
		return nil
	}
	if count > maxTargetAddresses {
		return fmt.Errorf("target %s expands to %d addresses, more than the limit of %d", target, count, maxTargetAddresses)
	}
	return nil
}
