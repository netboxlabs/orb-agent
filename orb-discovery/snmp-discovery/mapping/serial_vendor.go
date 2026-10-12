package mapping

import (
	"log/slog"

	"github.com/netboxlabs/diode-sdk-go/diode"
)

// vendorSerialSource names one enterprise scalar that carries the chassis
// serial of a whole device. Each is walked only when the target's
// sysObjectID resolves to its vendor (see policy/vendor.go and the
// vendor-scoped entries in policy/mapping.yaml), so a value present in the
// walk already implies the vendor matched.
type vendorSerialSource struct {
	vendor string
	name   string
	oid    string
}

// vendorSerialSources lists the chassis-serial scalars, in the order they
// are consulted. A platform never answers more than one of these, since each
// sits under its own enterprise arc; the order only makes the outcome
// deterministic if a walk ever carried two.
var vendorSerialSources = []vendorSerialSource{
	{vendor: "juniper", name: "JUNIPER-MIB jnxBoxSerialNo", oid: ".1.3.6.1.4.1.2636.3.1.3.0"},
	{vendor: "mikrotik", name: "MIKROTIK-MIB mtxrSerialNumber", oid: ".1.3.6.1.4.1.14988.1.1.7.3.0"},
}

// vendorSerial returns the first non-empty enterprise chassis serial in the
// walk, with the name of the object it came from, or ("", "") when no source
// answered.
func vendorSerial(oids ObjectIDValueMap) (serial, source string) {
	for _, src := range vendorSerialSources {
		v, ok := oids[src.oid]
		if !ok {
			continue
		}
		if s := trimSNMPString(v.Value); s != "" {
			return s, src.name
		}
	}
	return "", ""
}

// applyVendorSerialFallback fills master.Serial from an enterprise
// chassis-serial scalar when ENTITY-MIB gave the device none.
//
// ENTITY-MIB keeps priority: this runs only on the path where
// extractInventory found no usable chassis row, so a populated
// entPhysicalSerialNum on a chassis(3) row is never displaced by the vendor
// value. The two shapes that reach here are a device that implements no
// entPhysicalTable at all, and one whose chassis row carries an empty
// serial while the serials it does publish belong to contained components
// (USB controllers, fans), which extractInventory never considers for the
// device because they are not chassis-class rows at the root.
//
// Reports whether a serial was set.
func applyVendorSerialFallback(master *diode.Device, oids ObjectIDValueMap, logger *slog.Logger) bool {
	if master == nil || master.Serial != nil {
		return false
	}
	s, source := vendorSerial(oids)
	if s == "" {
		return false
	}
	master.Serial = &s
	logger.Info("device serial taken from vendor scalar: no usable ENTITY-MIB chassis serial",
		"source", source)
	return true
}
