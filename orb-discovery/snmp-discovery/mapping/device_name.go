// Package mapping - device_name.go: the emit_device_name post-map
// transform.
package mapping

import (
	"log/slog"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

// ApplyDeviceNameEmission suppresses the discovered device's name across
// every representation of it when name emission is disabled
// (emit_device_name: false) and the device is matchable by a stub-carried
// field (source_match or asset_tag). Intended for use with netbox_id /
// metadata.source_match so continual discovery under Assurance stops
// proposing a hostname rename when sysName differs from the NetBox name.
//
// dev is the master device to guard (the caller passes
// CurrentDeviceFrom(entities), threaded in so the batch is scanned once).
// entities is scanned to also clear the name on the shared
// VirtualChassis.Master matcher ref so suppression is consistent on
// stacks. host and logger are for log context only.
//
// No-op when emission is enabled (the default), dev is nil, dev is a
// virtual-chassis member, or the name is already unset. When disabled but
// the device carries no alternative matcher, the name is kept and a
// warning is logged — Name is a primary device matcher, so dropping it
// without a source_match / asset_tag would emit an unmatchable device.
func ApplyDeviceNameEmission(entities []diode.Entity, dev *diode.Device, emit bool, host string, logger *slog.Logger) {
	if emit || dev == nil || dev.VcPosition != nil || dev.Name == nil {
		return
	}
	if !deviceHasAlternativeMatcher(dev) {
		if logger != nil {
			logger.Warn("emit_device_name disabled but device has no alternative matcher (netbox_id/source_match, asset_tag); keeping name to avoid an unmatchable device",
				"host", host, "name", *dev.Name)
		}
		return
	}
	if logger != nil {
		logger.Debug("emit_device_name: suppressing Device.name from sysName",
			"host", host, "name", *dev.Name)
	}
	dev.Name = nil
	clearVirtualChassisMasterName(entities)
}

// clearVirtualChassisMasterName clears Name on the shared
// VirtualChassis.Master matcher ref. buildMasterRef pointer-copies the
// master's name into a separate field, so clearing the master device does
// not reach it; leaving it would recreate the name divergence buildMasterRef
// forbids. The ref still carries source_match / asset_tag, so it stays
// matchable. Called only after the master's name has been suppressed. The
// ref is shared across the top-level VirtualChassis entity and every
// member's VirtualChassis.Master, so clearing via any path clears it
// everywhere; iterating both shapes is idempotent and defensive.
//
// snmp-discovery emits exactly one master (and one shared master ref) per
// walk, so clearing every ref in the batch unconditionally is correct: the
// only master ref present is the one for the master the guard just cleared.
func clearVirtualChassisMasterName(entities []diode.Entity) {
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.VirtualChassis:
			if v != nil && v.Master != nil {
				v.Master.Name = nil
			}
		case *diode.Device:
			if v != nil && v.VirtualChassis != nil && v.VirtualChassis.Master != nil {
				v.VirtualChassis.Master.Name = nil
			}
		}
	}
}

// deviceHasAlternativeMatcher reports whether dev can be matched without
// its name by a matcher that also survives onto the nested device stubs
// built by newDeviceStub: a source_match annotation (e.g. netbox_id) or a
// non-empty asset_tag.
//
// serial is excluded because NetBox Device.serial is not unique and
// generates no matcher at all. primary_ip is excluded because, although
// unique_primary_ip4/ip6 match a top-level device, newDeviceStub drops
// primary_ip (setting it on a nested stub fails ingest), so clearing the
// name would leave every nested device stub unmatchable.
func deviceHasAlternativeMatcher(dev *diode.Device) bool {
	if _, ok := dev.Metadata["source_match"]; ok {
		return true
	}
	if dev.AssetTag != nil && strings.TrimSpace(*dev.AssetTag) != "" {
		return true
	}
	return false
}
