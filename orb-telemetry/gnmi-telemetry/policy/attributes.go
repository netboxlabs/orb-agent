package policy

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/targets"
)

// targetLabel names a target in a refusal: its host, and its ID when it has
// one.
func targetLabel(t config.Target) string {
	if t.ID != "" {
		return fmt.Sprintf("target %s (id %s)", t.Host, t.ID)
	}
	return "target " + t.Host
}

// validateAttributes checks the scope's attributes, then each target's merged
// with the scope's, which is the set the target exports: the limits count
// both, and two keys can collide across them. ParsePolicies has merged them
// already, and merging again changes nothing. The scope is checked first, so
// a refusal names the target only for what the target adds.
func validateAttributes(scope config.Scope) error {
	if err := scope.Attributes.Validate(collector.ReservedAttributeName); err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	for _, target := range scope.Targets {
		merged := config.MergeAttributes(scope.Attributes, target.Attributes)
		if err := merged.Validate(collector.ReservedAttributeName); err != nil {
			return fmt.Errorf("%s: %w", targetLabel(target), err)
		}
	}
	return nil
}

// checkProfileAttributes refuses a policy attribute whose key a profile of
// the collector's set promotes, as written or once translated to Prometheus.
// Which profile serves a target is only known once it answers, so a key any
// profile promotes would meet that profile's attribute on some target, and
// one of the two would be lost there.
func checkProfileAttributes(policyName string, scope config.Scope, c Collector) error {
	if c == nil {
		return nil
	}
	check := func(where string, attrs config.Attributes) error {
		for _, key := range slices.Sorted(maps.Keys(attrs)) {
			name, profile, ok := c.ProfileAttribute(key)
			switch {
			case !ok:
				continue
			case name == key:
				return fmt.Errorf("%s: invalid policy: %s: attribute key %q is exported by the gNMI profile %s; choose another key",
					policyName, where, key, profile)
			case config.PrometheusName(key) == name:
				return fmt.Errorf("%s: invalid policy: %s: attribute key %q becomes %q in Prometheus, which the gNMI profile %s exports; choose another key",
					policyName, where, key, name, profile)
			default:
				return fmt.Errorf("%s: invalid policy: %s: attribute key %q and %q, which the gNMI profile %s exports, both become %q in Prometheus; choose another key",
					policyName, where, key, name, profile, config.PrometheusName(key))
			}
		}
		return nil
	}
	if err := check("scope", scope.Attributes); err != nil {
		return err
	}
	for _, target := range scope.Targets {
		if err := check(targetLabel(target), target.Attributes); err != nil {
			return err
		}
	}
	return nil
}

// checkOverlappingAttributes refuses two range targets that share an address
// and give it different attributes. The sweep keeps whichever entry expanded
// to the address first, so the device would carry one entry's attributes and
// drop the other's. A single address is not a range: one inside a range beats
// the range's candidate for its address, attributes included, and neither
// conflicts with the range nor excuses two ranges that conflict. Every range
// form is IPv4 arithmetic, so the overlap is known without probing anything.
func checkOverlappingAttributes(entries []config.Target) error {
	type span struct {
		start, end uint32
		entry      int
	}
	var spans []span
	for i, t := range entries {
		bare, _, _ := splitEffectivePort(t.Host, t.Port)
		if targets.IsSingleEndpoint(bare) {
			continue
		}
		start, end, enumerable, err := targets.Span(bare)
		if err != nil || !enumerable {
			continue
		}
		spans = append(spans, span{start: start, end: end, entry: i})
	}
	slices.SortStableFunc(spans, func(a, b span) int { return cmp.Compare(a.start, b.start) })
	// Every earlier span still open at a span's start contains that start, so
	// those spans share an address and, with nothing refused so far, agree.
	// Comparing the span with the open one reaching furthest compares it with
	// all of them.
	reach := -1
	for j, s := range spans {
		if reach >= 0 && s.start <= spans[reach].end {
			a, b := entries[spans[reach].entry], entries[s.entry]
			if !a.Attributes.Equal(b.Attributes) {
				return fmt.Errorf("targets %s and %s both name %s with different attributes; give them the same attributes, or split the ranges so they share no address",
					a.Host, b.Host, addrFrom(s.start))
			}
		}
		if reach < 0 || s.end > spans[reach].end {
			reach = j
		}
	}
	return nil
}

// addrFrom renders a span bound as the IPv4 address it is.
func addrFrom(v uint32) string {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String()
}
