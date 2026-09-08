package metrics

import (
	"go.opentelemetry.io/otel/metric"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
)

var noopMeter = noopmetric.NewMeterProvider().Meter("gnmi-telemetry-noop")

// The names of the instruments the backend registers for its own health,
// without the "gnmi." prefix the exporter puts in front of every metric it
// writes. Each accessor below is built from its constant, and healthNames
// lists them all, so an instrument added here is reserved by the same edit
// that registers it.
//
// TargetUp is exported because the collector registers that gauge itself, over
// its own target loops, and names it from here rather than from a literal of
// its own.
const (
	targetsActive = "targets_active"
	// TargetUp is the name, without the prefix, of the gauge the collector
	// registers for a target's liveness.
	TargetUp         = "target_up"
	reconnects       = "subscription_reconnects_total"
	notifications    = "notifications_total"
	updatesDropped   = "updates_dropped_total"
	modeFallbacks    = "mode_fallback_total"
	profileFallbacks = "profile_fallback_total"
)

// healthNames is every health metric name, the list HealthNames hands out.
var healthNames = []string{
	targetsActive,
	TargetUp,
	reconnects,
	notifications,
	updatesDropped,
	modeFallbacks,
	profileFallbacks,
}

// HealthNames returns the metric names the backend owns for its own health,
// without the "gnmi." prefix. Profile validation reserves them: one instrument
// serves a metric name however many writers it has, so a profile metric named
// after one of these would have the exporter register a second instrument, of
// whatever kind the profile declared, under a name the backend already writes.
func HealthNames() []string {
	return append([]string(nil), healthNames...)
}

// prefixed is a health metric name as the exporter writes it.
func prefixed(suffix string) string { return "gnmi." + suffix }

func counter(name, desc string) metric.Int64Counter {
	if c := GetCounter(name, desc); c != nil {
		return c
	}
	c, _ := noopMeter.Int64Counter(name)
	return c
}

func upDown(name, desc string) metric.Int64UpDownCounter {
	if c := GetUpDownCounter(name, desc); c != nil {
		return c
	}
	c, _ := noopMeter.Int64UpDownCounter(name)
	return c
}

// GetTargetsActive counts targets with a running loop.
func GetTargetsActive() metric.Int64UpDownCounter {
	return upDown(prefixed(targetsActive), "Number of active gNMI targets")
}

// GetReconnects counts stream reconnects.
func GetReconnects() metric.Int64Counter {
	return counter(prefixed(reconnects), "Total gNMI subscription reconnects")
}

// GetNotifications counts notifications received.
func GetNotifications() metric.Int64Counter {
	return counter(prefixed(notifications), "Total gNMI notifications received")
}

// GetUpdatesDropped counts updates that produced no series, by reason.
func GetUpdatesDropped() metric.Int64Counter {
	return counter(prefixed(updatesDropped), "Total gNMI updates dropped before export, by reason")
}

// GetModeFallbacks counts delivery-mode downgrades.
func GetModeFallbacks() metric.Int64Counter {
	return counter(prefixed(modeFallbacks), "Total delivery-mode fallbacks")
}

// GetProfileFallbacks counts targets that used the _base profile.
func GetProfileFallbacks() metric.Int64Counter {
	return counter(prefixed(profileFallbacks), "Times the _base profile was used")
}
