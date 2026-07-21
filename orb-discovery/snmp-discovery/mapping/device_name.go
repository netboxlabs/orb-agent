// Package mapping - device_name.go: the emit_device_name post-map
// transform.
package mapping

import (
	"log/slog"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

// ApplyDeviceNameEmission suppresses dev.Name when name emission is
// disabled (emit_device_name: false) and the device is matchable another
// way. Intended for use with netbox_id / metadata.source_match so
// continual discovery under Assurance stops proposing a hostname rename
// when sysName differs from the NetBox name.
//
// No-op when emission is enabled (the default), dev is nil, dev is a
// virtual-chassis member, or the name is already unset. When disabled but
// the device carries no alternative matcher, the name is kept and a
// warning is logged — Name is a primary device matcher, so dropping it
// without a source_match / asset_tag would emit an unmatchable device.
// host and logger are for log context only.
func ApplyDeviceNameEmission(dev *diode.Device, emit bool, host string, logger *slog.Logger) {
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
