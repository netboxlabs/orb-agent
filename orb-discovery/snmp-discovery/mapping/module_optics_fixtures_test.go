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

// serialFreeCagedPortOpticFixture mirrors the class-10-in-a-cage topology
// real captures actually show (the same cage+port nesting as
// modularPortOpticFixture) with the serial field blank. Unlike the class-5
// shape above, the cage here has a class-10 child of its own, so
// containerHasPortChild marks it before the missing-serial drop ever runs —
// the cage is suppressed outright and produces no bay, empty or otherwise.
func serialFreeCagedPortOpticFixture() []fixtureRow {
	return []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "SYN0005", "SYN-CHASSIS5", "Synthetic chassis", ""},
		// Cage: class 5, no PID, no serial, directly under the chassis.
		{"110", "1", "5", "1", "Te1/0/1 Container", "", "", "TenGigabitEthernet1/0/1 Container", ""},
		// Optic: class 10, PID present, serial ABSENT.
		{"111", "110", "10", "0", "TenGigabitEthernet1/0/1", "", "SFP-10G-LR", "SFP-10GBase-LR", ""},
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

// duplicateBayNameOpticFixture is synthetic, not transcribed from a
// capture — no captured device in the corpus has shown two fixed-port
// transceivers collide on the same bay name. It exists to exercise the
// duplicate-bay-name guard: two class-10 optics sit directly under the
// chassis, each with a blank Name, a Descr that names no interface, and
// a blank relPos, so both fall all the way through servedInterface and
// emitModuleBay's fallback chain to the literal placeholder "Unknown" —
// the same effective bay name, on the same member. Each carries its own
// serial so neither is dropped by the missing- or duplicate-serial
// guards before reaching the bay-name check.
func duplicateBayNameOpticFixture() []fixtureRow {
	return []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "SYN0004", "SYN-CHASSIS4", "Synthetic chassis", ""},
		{"10", "1", "10", "", "", "SYNSER0001A", "SFP-10G-LR", "", ""},
		{"11", "1", "10", "", "", "SYNSER0001B", "SFP-10G-LR", "", ""},
	}
}

// duplicateModularBayNameOpticFixture is synthetic, not transcribed from a
// capture — no captured device in the corpus has shown two modular optics
// resolve to the same cage-derived bay name. It exercises the
// duplicate-bay-name guard's submodule-loop coverage: two linecards under
// one chassis each carry a port cage that happens to be named identically
// ("Te1/0/1 Container"), each holding its own class-10 optic. Both optics
// land in inv.SubModules — keyed by their own linecard's EntIndex, never
// in inv.Modules — so this collision is unreachable through the top-level
// loop alone and would go uncaught without the guard's submodule coverage.
func duplicateModularBayNameOpticFixture() []fixtureRow {
	return []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "SYN0006", "SYN-CHASSIS6", "Synthetic chassis", ""},
		// Linecard A in slot 1, with a port cage "Te1/0/1 Container".
		{"10", "1", "5", "1", "Slot 1", "", "", "", ""},
		{"100", "10", "9", "1", "Linecard A", "SYNLCA0001", "C9400-LC-48U", "", ""},
		{"101", "100", "5", "1", "Te1/0/1 Container", "", "", "", ""},
		{"102", "101", "10", "0", "", "SYNSERBAYA", "SFP-10G-LR", "", ""},
		// Linecard B in slot 2 — its port cage collides on the exact same
		// name as Linecard A's, even though the two optics sit under
		// different parent linecards.
		{"20", "1", "5", "2", "Slot 2", "", "", "", ""},
		{"200", "20", "9", "2", "Linecard B", "SYNLCB0001", "C9400-LC-48U", "", ""},
		{"201", "200", "5", "1", "Te1/0/1 Container", "", "", "", ""},
		{"202", "201", "10", "0", "", "SYNSERBAYB", "SFP-10G-LR", "", ""},
	}
}

// crossTierDuplicateBayNameOpticFixture is synthetic, not transcribed from
// a capture — no captured device in the corpus has shown a top-level
// fixed-port optic collide with a modular optic on the same device. It
// exists to prove the duplicate-bay-name guard's design point: the
// top-level loop and the submodule loop must share ONE seenTransceiverBays
// map. A fixed-port optic's bay resolves to "Ethernet1" via servedInterface
// (same shape as fixedPortLaneShapeFixture); a modular optic under a
// separate linecard sits in a port cage that is itself literally named
// "Ethernet1". The two are the same effective (device, bay name) pair even
// though one is device-rooted at the top level and the other nests under
// a linecard — a second, per-loop map would miss this case entirely.
func crossTierDuplicateBayNameOpticFixture() []fixtureRow {
	return []fixtureRow{
		{"1", "0", "3", "1", "Chassis", "SYN0007", "SYN-CHASSIS7", "Synthetic chassis", ""},
		// Top-level fixed-port optic: class-5 cage directly under the
		// chassis, optic names its interface via Descr.
		{"10", "1", "5", "1", "Xcvr Slot 1", "", "", "", ""},
		{"11", "10", "5", "1", "", "SYNSERTOP1", "SFP-10G-LR", "Xcvr for Ethernet1", ""},
		// Modular optic under a linecard: the port cage is itself literally
		// named "Ethernet1" — the same effective bay name the fixed-port
		// optic above resolves to via servedInterface.
		{"20", "1", "5", "2", "Slot 2", "", "", "", ""},
		{"200", "20", "9", "2", "Linecard", "SYNLC00001", "C9400-LC-48U", "", ""},
		{"201", "200", "5", "1", "Ethernet1", "", "", "", ""},
		{"202", "201", "10", "0", "", "SYNSERSUB1", "SFP-10G-LR", "", ""},
	}
}
