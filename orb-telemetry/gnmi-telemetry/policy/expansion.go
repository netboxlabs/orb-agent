package policy

import (
	"fmt"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/targets"
)

// maxPolicyAddresses bounds how many addresses one policy may expand to across
// every target it names. Expansion materialises every address before a single
// stream exists, and each address then becomes a permanent subscription, so a
// prefix such as a /8 costs roughly a gigabyte of strings up front and 16
// million subscriptions after that.
//
// This is the policy-wide bound on top of the per-target one. targets.Expand
// caps a single target at targets.MaxExpand, which bounds one entry and
// nothing else: sixty-five entries each sitting under that cap already expand
// the policy past this, and the request body limit does not help because
// sixty-five prefixes are a few hundred bytes. A policy needing more than
// 65536 subscribed devices is already past what this backend should run.
//
// 65536 is a guard against the pathological cases, not a recommended size.
const maxPolicyAddresses = 65536

// maxScanWork bounds how many addresses a policy's targets enumerate in total,
// as opposed to how many distinct ones they describe. The two differ when
// ranges overlap, because expandTargets expands every entry before it
// deduplicates the results, and the sweep repeats that on every rescan tick.
//
// A policy may overlap its ranges up to twice its address budget before the
// per-tick expansion cost is refused, which leaves room for a subnet plus the
// hosts pinned inside it, or for nested prefixes carrying different
// credentials, while refusing the degenerate case: thirty thousand overlapping
// sub-/16 ranges describe fewer than 65536 distinct addresses and materialise
// tens of millions of strings per sweep.
const maxScanWork = 2 * maxPolicyAddresses

// checkPolicyExpansion rejects a policy whose targets together cover more than
// maxPolicyAddresses distinct addresses, or whose entries enumerate more than
// maxScanWork of them per sweep, both counted without expanding.
//
// The union, not the sum. Pinning a host inside a subnet to give it its own
// credentials is the documented way to write that, and expandTargets collapses
// the pin onto the address the subnet already produced, so summing every
// entry's size double-counted each overlap: 64 disjoint /22 prefixes and 129
// pins inside them were refused as 65537 addresses that expansion resolves to
// 65408.
//
// Spans merge across ports, where the discovery copy of this guard groups by
// port first. A policy subscribes to a device once here, and dedupeKey is the
// canonical host alone, so one address named at two ports is one subscription
// rather than two endpoints.
//
// Each span comes from targets.Span, which reads a target the way targets.Expand
// does rather than parsing the notation a second time, so no target shape can
// mean one thing to the guard and another to the expander. A target Span
// refuses is left to Expand, which says what is wrong with it. A hostname or an
// IPv6 literal is not comparable to an address range, so it counts as the one
// endpoint Expand returns for it. A blank host counts the same and is refused by
// name in validatePolicy, which reads a target after normalizeTargetHosts has
// trimmed it, so all three read the same value.
//
// The union is at most 2^32, and one entry adds at most one to it, so the slice
// would need 2^32 entries to overflow the uint64 total.
func checkPolicyExpansion(entries []config.Target) error {
	spans := make([][2]uint32, 0, len(entries))
	var total, work uint64
	for _, entry := range entries {
		// The bare host, so a pinned target written "10.0.0.5:6030" merges into
		// the subnet holding it instead of counting as an endpoint of its own.
		bare, _, _ := splitEffectivePort(entry.Host, entry.Port)
		start, end, enumerable, err := targets.Span(bare)
		if err != nil {
			continue
		}
		if !enumerable {
			total++
			work++
			continue
		}
		spans = append(spans, [2]uint32{start, end})
		work += uint64(end-start) + 1
	}
	total += targets.UnionSize(spans)
	// The address cap is charged first: it is the bound an operator sizes a
	// policy against, so a policy over both budgets is told the number that
	// matters rather than the cost of getting there.
	if total > maxPolicyAddresses {
		return fmt.Errorf("policy targets expand to %d addresses in total, more than the limit of %d", total, maxPolicyAddresses)
	}
	if work > maxScanWork {
		return fmt.Errorf(
			"policy would enumerate %d addresses per sweep, more than the %d allowed; reduce overlapping ranges",
			work, maxScanWork,
		)
	}
	return nil
}
