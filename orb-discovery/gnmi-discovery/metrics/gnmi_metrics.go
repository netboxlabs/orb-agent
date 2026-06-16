package metrics

import (
	"go.opentelemetry.io/otel/metric"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
)

// BLOCKER fix: the generic GetCounter/GetUpDownCounter return nil when no OTEL
// meter is configured (the default no-export path). Calling .Add on nil panics.
// These accessors therefore fall back to a noop instrument so every call site is
// safe WITHOUT a nil check. A single shared noop meter backs the fallbacks.
var noopMeter = noopmetric.NewMeterProvider().Meter("gnmi-discovery-noop")

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

// GetTargetsActive returns the active-targets gauge (one per running target).
func GetTargetsActive() metric.Int64UpDownCounter {
	return upDown("gnmi.targets_active", "Number of active gNMI targets")
}

// GetSubscriptionsActive returns the active-subscriptions gauge.
func GetSubscriptionsActive() metric.Int64UpDownCounter {
	return upDown("gnmi.subscriptions_active", "Number of active gNMI subscriptions")
}

// GetReconnects returns the reconnect counter.
func GetReconnects() metric.Int64Counter {
	return counter("gnmi.subscription_reconnects_total", "Total gNMI subscription reconnects")
}

// GetNotifications returns the inbound-notification counter.
func GetNotifications() metric.Int64Counter {
	return counter("gnmi.notifications_total", "Total gNMI notifications received")
}

// GetNotificationsDropped returns the filtered-out-update counter.
func GetNotificationsDropped() metric.Int64Counter {
	return counter("gnmi.notifications_dropped_total", "Total non-curated updates/deletes dropped before reconcile")
}

// GetCapabilityErrors returns the Capabilities-RPC error counter.
func GetCapabilityErrors() metric.Int64Counter {
	return counter("gnmi.capability_errors_total", "Total gNMI Capabilities RPC failures")
}

// GetFlushes returns the successful-ingest counter.
func GetFlushes() metric.Int64Counter {
	return counter("gnmi.flushes_total", "Total reconciled snapshots ingested")
}

// GetIngestErrors returns the ingest-error counter.
func GetIngestErrors() metric.Int64Counter {
	return counter("gnmi.ingest_errors_total", "Total Diode ingest errors")
}

// GetModeFallbacks returns the delivery-mode fallback counter.
func GetModeFallbacks() metric.Int64Counter {
	return counter("gnmi.mode_fallback_total", "Total delivery-mode fallbacks")
}

// GetProfileFallbacks returns the _base fallback counter.
func GetProfileFallbacks() metric.Int64Counter {
	return counter("gnmi.profile_fallback_total", "Times the _base profile was used")
}

// GetRemovalsBlocked returns the blocked-removal counter. NOTE: this mixes units
// — it counts gNMI delete PATHS observed (one path may drop a whole subtree) plus
// TTL-pruned LEAVES. It is an informational signal of "data that left the model
// but was not propagated to NetBox (Diode delete unavailable)", not a ledger.
func GetRemovalsBlocked() metric.Int64Counter {
	return counter("gnmi.removals_blocked_total", "Local removals not propagated (Diode delete unavailable)")
}

// GetFlushSkippedNoIdentity returns the counter for flushes skipped because the
// model had no device identity (no hostname leaf and no netbox_id). A steadily
// rising value on a connected target signals a hostname-path mismatch for that
// vendor — write a profile override (MED-1).
func GetFlushSkippedNoIdentity() metric.Int64Counter {
	return counter("gnmi.flush_skipped_no_identity_total", "Flushes skipped due to missing device identity")
}
