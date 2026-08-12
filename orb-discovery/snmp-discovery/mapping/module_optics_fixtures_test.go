// Copyright 2026 NetBox Labs, Inc.

package mapping

// Optic fixtures transcribed from SNMP simulator recordings. Row class,
// parentage, relPos and which fields are empty all mirror the capture —
// those are the values the logic reads. Optic counts are reduced to three
// per fixture for readability.

// fixedPortLaneShapeFixture mirrors a fixed-port switch where each optic is a
// class-5 row carrying the PID and serial with an EMPTY Name, sitting in a
// per-port class-5 cage. Beneath each optic sit two DOM sensors and one
// class-9 lane row with no model, no serial and vendorType "0.0". Every
// class-9 row on this platform is a lane.
func fixedPortLaneShapeFixture() []fixtureRow {
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "JPE14030001", "DCS-7050SX-64", "64-port switch chassis", ""},
		{"1100300000", "1", "5", "3", "", "", "", "Xcvr Slot Container", ""},
	}
	for _, p := range []struct{ n, cage, optic, lane, sensor1, sensor2, serial string }{
		{"1", "100301000", "100301100", "100301210", "100301201", "100301202", "G1904016438"},
		{"2", "100302000", "100302100", "100302210", "100302201", "100302202", "G1904016436"},
		{"3", "100303000", "100303100", "100303210", "100303201", "100303202", "G1904016445"},
	} {
		rows = append(rows,
			// Cage: class 5, no PID, empty Name, relPos is the port number.
			fixtureRow{p.cage, "1100300000", "5", p.n, "", "", "", "Xcvr Slot " + p.n, ""},
			// Optic: class 5, PID and serial present, Name EMPTY, relPos 1.
			fixtureRow{p.optic, p.cage, "5", "1", "", p.serial, "SFP-10GLR-31", "Xcvr for Ethernet" + p.n, ""},
			// DOM sensors: class 8, never gathered.
			fixtureRow{p.sensor1, p.optic, "8", "1", "", "", "", "DOM Temperature Sensor for Ethernet" + p.n, "0.0"},
			fixtureRow{p.sensor2, p.optic, "8", "2", "", "", "", "DOM Voltage Sensor for Ethernet" + p.n, "0.0"},
			// Lane: class 9, no model, no serial, vendorType "0.0".
			fixtureRow{p.lane, p.optic, "9", "0", "", "", "", "Lane 0 for Xcvr for Ethernet" + p.n, "0.0"},
		)
	}
	return rows
}

// fixedPortHarvestShapeFixture mirrors the same vendor's other capture, where
// most optics have NO lane child. Such a row has neither a class-9 nor a
// class-10 child, so it reaches the empty-bay harvest today.
func fixedPortHarvestShapeFixture() []fixtureRow {
	rows := []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "JPE14030002", "DCS-7050SX-64", "64-port switch chassis", ""},
		{"1100300000", "1", "5", "3", "", "", "", "Xcvr Slot Container", ""},
	}
	for _, p := range []struct{ n, cage, optic, serial string }{
		{"1", "100301000", "100301100", "XMD1447522PK"},
		{"2", "100302000", "100302100", "XMD14475233E"},
		{"3", "100303000", "100303100", "XMD14475233F"},
	} {
		rows = append(rows,
			fixtureRow{p.cage, "1100300000", "5", p.n, "", "", "", "Xcvr Slot " + p.n, ""},
			fixtureRow{p.optic, p.cage, "5", "1", "", p.serial, "SFP-1G-T", "Xcvr for Ethernet" + p.n, ""},
		)
	}
	return rows
}

// modularPortOpticFixture mirrors a modular chassis where the optic is a
// class-10 row inside a class-5 port cage inside a class-9 linecard. The
// second optic's PID is a real transceiver the prefix list does not match,
// pinning that documented gap.
func modularPortOpticFixture() []fixtureRow {
	return []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "FXS2130Q0MZ", "C9404R", "4-slot chassis", ""},
		{"6", "1", "5", "2", "Slot 2", "", "", "Slot 2 Container", ""},
		{"2000", "6", "9", "2", "Slot 2 Linecard", "JAE23140BJH", "C9400-LC-48UX", "48-port line card", ""},
		{"2061", "2000", "5", "1", "Te2/0/1 Container", "", "", "TenGigabitEthernet2/0/1 Container", "1.3.6.1.4.1.9.12.3.1.5.115"},
		{"2072", "2061", "10", "0", "TenGigabitEthernet2/0/1", "A1111111111-A", "SFP-10G-AOC2M", "10G AOC2M", ""},
		{"2062", "2000", "5", "2", "Te2/0/2 Container", "", "", "TenGigabitEthernet2/0/2 Container", "1.3.6.1.4.1.9.12.3.1.5.115"},
		{"2078", "2062", "10", "0", "TenGigabitEthernet2/0/2", "AGM11111111", "ABCU-5710RZ-CS5", "GE T", ""},
	}
}

// stackedPortOpticFixture mirrors a two-member stack whose optics are
// class-10 rows named with the literal token "port", under a class-9 member
// module. Both members report relPos 25 and 26, so both synthesize bays
// "Slot 25" and "Slot 26" — distinct objects only because each carries its
// own Device.
func stackedPortOpticFixture() []fixtureRow {
	return []fixtureRow{
		{"569", "0", "3", "1", "Chassis", "K3080012", "OS6350-P24", "24-port stackable chassis", ""},
		{"570", "0", "3", "2", "Chassis", "K3080013", "OS6450-24", "24-port stackable chassis", ""},
		{"1", "569", "9", "1", "NI-1", "K3080012", "OS6350-P24", "Network interface module 1", ""},
		{"2", "570", "9", "2", "NI-2", "K3080013", "OS6450-24", "Network interface module 2", ""},
		{"156", "1", "10", "25", "port", "19480134", "SFP-10G-T", "SFP-10G-T", ""},
		{"157", "1", "10", "26", "port", "C1404140546", "SFP-10G-C3M", "SFP-10G-C3M", ""},
		{"211", "2", "10", "25", "port", "19480215", "SFP-10G-T", "SFP-10G-T", ""},
		{"212", "2", "10", "26", "port", "GC22007671", "SFP-10G-LR", "SFP-10G-LR", ""},
	}
}

// serialFreeCagedOpticFixture is synthetic, not transcribed from a capture —
// no captured device has shown this exact shape. It exists to pin an
// invariant: a class-5 optic with no serial must be dropped as a module, and
// the class-5 cage it sits in must still be harvested into EmptyBays rather
// than vanishing along with it, the same way a duplicate-serial drop already
// leaves its cage harvestable.
func serialFreeCagedOpticFixture() []fixtureRow {
	return []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "SYN0001", "SYN-CHASSIS", "Synthetic chassis", ""},
		// Cage: class 5, no PID, no serial, directly under the chassis.
		{"100", "1", "5", "1", "Cage 1", "", "", "Cage Slot 1", ""},
		// Optic: class 5, PID present, serial ABSENT.
		{"101", "100", "5", "1", "", "", "SFP-10GLR-31", "Xcvr for Ethernet1", ""},
	}
}

// serialFreePortOpticFixture mirrors a platform publishing class-10 optics
// directly under the chassis with NO serial and relPos -1 on every row.
// Absent the serial requirement all three would synthesize one bay named
// "Slot -1" and merge into a single object.
func serialFreePortOpticFixture() []fixtureRow {
	return []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "EC2140004", "DCS203", "Fixed-port switch chassis", ""},
		{"1000000100", "1", "10", "-1", "Ethernet0", "", "SFP-10GSR-85", "SFP/SFP+/SFP28 for Eth6/1(Port1)", ""},
		{"1000000200", "1", "10", "-1", "Ethernet1", "", "SFP-10GSR-85", "SFP/SFP+/SFP28 for Eth6/2(Port1)", ""},
		{"1000000300", "1", "10", "-1", "Ethernet2", "", "SFP-10GSR-85", "SFP/SFP+/SFP28 for Eth6/3(Port1)", ""},
	}
}
