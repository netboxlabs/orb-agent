package policy

import (
	"fmt"
	"maps"
	"slices"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/traps"
)

// reservedAttributeKey reports whether a policy attribute would take the key
// of a dimension the backend sets itself: a polled series' identity and row
// index, the scope's policy name, or a received trap series' own dimensions.
func reservedAttributeKey(key string) bool {
	return collector.ReservedAttributeName(key) || traps.ReservedAttributeName(key)
}

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
// both, and two keys can collide across them. The scope is checked first, so
// a refusal names the target only for what the target adds.
func validateAttributes(scope config.Scope) error {
	if err := scope.Attributes.Validate(reservedAttributeKey); err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	for _, target := range scope.Targets {
		merged := config.MergeAttributes(scope.Attributes, target.Attributes)
		if err := merged.Validate(reservedAttributeKey); err != nil {
			return fmt.Errorf("%s: %w", targetLabel(target), err)
		}
	}
	return nil
}

// checkProfileAttributes refuses a policy attribute whose key a profile of
// the collector's set exports, as written or once translated to Prometheus.
// Which profile a device matches is only known once it answers, so a key any
// profile of the set exports would meet that profile's attribute on some
// device, and one of the two would be lost there.
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
				return fmt.Errorf("%s: invalid policy: %s: attribute key %q is exported by the SNMP profile %s; choose another key",
					policyName, where, key, profile)
			case config.PrometheusName(key) == name:
				return fmt.Errorf("%s: invalid policy: %s: attribute key %q becomes %q in Prometheus, which the SNMP profile %s exports; choose another key",
					policyName, where, key, name, profile)
			default:
				return fmt.Errorf("%s: invalid policy: %s: attribute key %q and %q, which the SNMP profile %s exports, both become %q in Prometheus; choose another key",
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
