// Copyright 2026 NetBox Labs, Inc.

package mapping

// fixtureRow is one synthetic entPhysical row used by module_*_test.go.
// Mirrors the way chassis_fixtures_test.go builds its own rows.
type fixtureRow struct {
	EntIndex    string // entPhysicalIndex (string form, used in OID suffix)
	ContainedIn string // entPhysicalContainedIn (parent's index, "0" for chassis)
	Class       string // entPhysicalClass: "3"=chassis "5"=container "9"=module
	ParentRel   string // entPhysicalParentRelPos
	Name        string // entPhysicalName
	Serial      string // entPhysicalSerialNum
	Model       string // entPhysicalModelName
	Descr       string // entPhysicalDescr
	VendorType  string // entPhysicalVendorType
}

// buildOIDs converts a list of fixtureRows into the ObjectIDValueMap
// shape extractModuleInventory expects. Keyed by full OID string;
// holds Value by value (NOT *ObjectIDValue) — see mapping.go:271.
func buildOIDs(rows []fixtureRow) ObjectIDValueMap {
	oids := make(ObjectIDValueMap)
	set := func(prefix, idx, val string) {
		oid := prefix + idx
		oids[oid] = Value{Value: val}
	}
	for _, r := range rows {
		set(".1.3.6.1.2.1.47.1.1.1.1.2.", r.EntIndex, r.Descr)
		set(".1.3.6.1.2.1.47.1.1.1.1.3.", r.EntIndex, r.VendorType)
		set(".1.3.6.1.2.1.47.1.1.1.1.4.", r.EntIndex, r.ContainedIn)
		set(".1.3.6.1.2.1.47.1.1.1.1.5.", r.EntIndex, r.Class)
		set(".1.3.6.1.2.1.47.1.1.1.1.6.", r.EntIndex, r.ParentRel)
		set(".1.3.6.1.2.1.47.1.1.1.1.7.", r.EntIndex, r.Name)
		set(".1.3.6.1.2.1.47.1.1.1.1.11.", r.EntIndex, r.Serial)
		set(".1.3.6.1.2.1.47.1.1.1.1.13.", r.EntIndex, r.Model)
	}
	return oids
}

// chassis9404RWithTransceiversFixture builds a minimal Cat 9404R-shape
// fixture: chassis + 1 supervisor + 1 linecard with 1 transceiver under it.
func chassis9404RWithTransceiversFixture() []fixtureRow {
	return []fixtureRow{
		{"1", "0", "3", "1", "Catalyst 9404R Chassis", "FCW2401L0K0", "C9404R", "Catalyst 9404R 4-slot Chassis", ""},
		// Slot 1 container
		{"100", "1", "5", "1", "Slot 1", "", "", "Slot 1", ""},
		// Supervisor installed in slot 1
		{"101", "100", "9", "1", "Supervisor 1", "JAE24010ABC", "C9400-SUP-1", "Cisco Catalyst 9400 Series Supervisor 1 Module", ""},
		// Slot 2 container
		{"200", "1", "5", "2", "Slot 2", "", "", "Slot 2", ""},
		// Linecard installed in slot 2
		{"201", "200", "9", "1", "Linecard 2", "JAE24010LC2", "C9400-LC-48U", "Cisco Catalyst 9400 48-port UPOE+ linecard", ""},
		// Port container under linecard
		{"202", "201", "5", "1", "TenGigabitEthernet2/0/1", "", "", "", ""},
		// Transceiver installed in port container
		{"203", "202", "9", "1", "TenGigabitEthernet2/0/1 Transceiver", "FNS24010TR1", "SFP-10G-LR", "SFP-10GBase-LR", ""},
	}
}
