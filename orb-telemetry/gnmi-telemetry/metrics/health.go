package metrics

import (
	"go.opentelemetry.io/otel/metric"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
)

var noopMeter = noopmetric.NewMeterProvider().Meter("gnmi-telemetry-noop")

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
	return upDown("gnmi.targets_active", "Number of active gNMI targets")
}

// GetReconnects counts stream reconnects.
func GetReconnects() metric.Int64Counter {
	return counter("gnmi.subscription_reconnects_total", "Total gNMI subscription reconnects")
}

// GetNotifications counts notifications received.
func GetNotifications() metric.Int64Counter {
	return counter("gnmi.notifications_total", "Total gNMI notifications received")
}

// GetUpdatesDropped counts updates that produced no series, by reason.
func GetUpdatesDropped() metric.Int64Counter {
	return counter("gnmi.updates_dropped_total", "Total gNMI updates dropped before export, by reason")
}

// GetModeFallbacks counts delivery-mode downgrades.
func GetModeFallbacks() metric.Int64Counter {
	return counter("gnmi.mode_fallback_total", "Total delivery-mode fallbacks")
}

// GetProfileFallbacks counts targets that used the _base profile.
func GetProfileFallbacks() metric.Int64Counter {
	return counter("gnmi.profile_fallback_total", "Times the _base profile was used")
}
