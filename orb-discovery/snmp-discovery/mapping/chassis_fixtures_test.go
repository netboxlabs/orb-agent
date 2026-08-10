package mapping

import "fmt"

// fixtureCisco3850TwoMemberStack returns an ObjectIDValueMap shaped like
// a 2-member Cisco 3850 stack:
//   - sysName "3850-stack.example"
//   - entPhysical row index 1 (Switch 1, FCW2147L0K3, WS-C3850-48P)
//   - entPhysical row index 1000 (Switch 2, FCW2147L0K4, WS-C3850-48P)
//   - both entPhysicalClass=3, entPhysicalContainedIn=0
//   - entPhysicalParentRelPos populated (1, 2)
//
// Used by extractInventory + TranslateAsStack tests.
func fixtureCisco3850TwoMemberStack() ObjectIDValueMap {
	return ObjectIDValueMap{
		".1.3.6.1.2.1.1.5.0": {Value: "3850-stack.example"},
		".1.3.6.1.2.1.1.2.0": {Value: ".1.3.6.1.4.1.9.1.2134"},
		// Member 1 (index 1).
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.7.1":  {Value: "Switch 1"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "FCW2147L0K3"},
		".1.3.6.1.2.1.47.1.1.1.1.13.1": {Value: "WS-C3850-48P"},
		// Member 2 (index 1000).
		".1.3.6.1.2.1.47.1.1.1.1.4.1000":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1000":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1000":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.7.1000":  {Value: "Switch 2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1000": {Value: "FCW2147L0K4"},
		".1.3.6.1.2.1.47.1.1.1.1.13.1000": {Value: "WS-C3850-48P"},
	}
}

// fixtureIndistinctChassisRowsStack returns an ObjectIDValueMap for a stack
// whose chassis rows are mutually indistinguishable, transcribed from a real
// 4-member walk and reduced to the smallest failing case, two members:
//
//   - class=11 stack container at index 1, name "Stack", containedIn=0
//   - class=3 chassis at 101001 and 201001, both containedIn=1
//   - parentRelPos = 1 on BOTH rows, so the position column is ambiguous
//   - entPhysicalName = "Chassis" on BOTH rows, with no trailing number, so
//     the name column carries nothing either
//   - distinct serials per chassis
//
// Neither position nor name can number these members. What can is the
// containment tree: each chassis owns a class=9 module whose ports are named
// "N/1/x". Note the ports are NOT direct children of the chassis — the real
// chain is port(10) -> module(9) -> chassis(3) -> stack(11) — which is why
// the descendant walk must traverse every class and filter only on collection.
//
// Sensor rows carrying a decorated number ("RPM sensor for fan Tray-2/1/1")
// are included deliberately: they must NOT be collected, both because the
// leading-number anchor rejects them and because they are not ports.
//
// entAliasMappingTable rows are present so member-owned interfaces route by
// containment rather than by ifName parsing.
func fixtureIndistinctChassisRowsStack() ObjectIDValueMap {
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.1.5.0": {Value: "stack-indistinct.example"},
		// Stack container (class=11) — never a member.
		".1.3.6.1.2.1.47.1.1.1.1.4.1": {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1": {Value: "11"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1": {Value: "-1"},
		".1.3.6.1.2.1.47.1.1.1.1.7.1": {Value: "Stack"},
	}
	serials := []string{"SN0000000101", "SN0000000201"}
	for member := 1; member <= 2; member++ {
		var (
			chassis = fmt.Sprintf("%d01001", member)
			module  = fmt.Sprintf("%d12001", member)
			sensor  = fmt.Sprintf("%d07101", member)
		)
		set := func(col int, idx, val string) {
			oids[fmt.Sprintf(".1.3.6.1.2.1.47.1.1.1.1.%d.%s", col, idx)] = Value{Value: val}
		}
		// Chassis row: ambiguous position, uninformative name.
		set(4, chassis, "1")
		set(5, chassis, "3")
		set(6, chassis, "1")
		set(7, chassis, "Chassis")
		set(11, chassis, serials[member-1])
		set(13, chassis, "SWITCH-48G-4SFP")
		// Line module under the chassis — the hop the ports hang off.
		set(4, module, chassis)
		set(5, module, "9")
		set(7, module, fmt.Sprintf("%d/1", member))
		set(11, module, serials[member-1])
		// Fan sensor whose name merely CONTAINS a slash-number.
		set(4, sensor, chassis)
		set(5, sensor, "8")
		set(7, sensor, fmt.Sprintf("RPM sensor for fan Tray-%d/1/1", member))
		// Two ports under the module, named in the ifName namespace.
		//
		// Port indexes use the real "12{member-1}{port}0" encoding, so
		// member 2's ports are 1210x0 — NOT 2xxxxx. Every port on every
		// member therefore divides to 1 at the 100000 scale that the chassis
		// rows do encode, which is exactly why this tier reads containment
		// instead of doing arithmetic on the index.
		for port := 1; port <= 2; port++ {
			idx := fmt.Sprintf("12%d%03d", member-1, port*10)
			set(4, idx, module)
			set(5, idx, "10")
			set(7, idx, fmt.Sprintf("%d/1/%d", member, port))
			// entAliasMappingTable: entPhysicalIndex -> ifIndex.
			ifIndex := (member-1)*100 + port
			aliasOID := fmt.Sprintf(".1.3.6.1.2.1.47.1.3.2.1.2.%s.0", idx)
			oids[aliasOID] = Value{Value: fmt.Sprintf(".1.3.6.1.2.1.2.2.1.1.%d", ifIndex)}
		}
	}
	return oids
}

// fixtureSingleMemberWrappedStack returns an ObjectIDValueMap transcribed
// from a real single-member VSF capture: a class=11 "Stack" container at
// index 1 wrapping exactly ONE class=3 "Chassis" at 101001 with
// parentRelPos=1. The wrapper is present even with one member, so this is
// the standalone path reached through the wrapped topology — and the shape
// that must NOT be renumbered by the descendant tier, since a lone member
// trivially satisfies its predicate.
func fixtureSingleMemberWrappedStack() ObjectIDValueMap {
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.1.5.0": {Value: "single-member.example"},
		// Stack container (class=11).
		".1.3.6.1.2.1.47.1.1.1.1.4.1": {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1": {Value: "11"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1": {Value: "-1"},
		".1.3.6.1.2.1.47.1.1.1.1.7.1": {Value: "Stack"},
		// The only chassis.
		".1.3.6.1.2.1.47.1.1.1.1.4.101001":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.5.101001":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.101001":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.7.101001":  {Value: "Chassis"},
		".1.3.6.1.2.1.47.1.1.1.1.11.101001": {Value: "SN0000000101"},
		".1.3.6.1.2.1.47.1.1.1.1.13.101001": {Value: "SWITCH-48G-4SFP"},
	}
	// A module and two ports, so a descendant signal exists and the
	// single-member gate is the only thing suppressing it.
	oids[".1.3.6.1.2.1.47.1.1.1.1.4.112001"] = Value{Value: "101001"}
	oids[".1.3.6.1.2.1.47.1.1.1.1.5.112001"] = Value{Value: "9"}
	oids[".1.3.6.1.2.1.47.1.1.1.1.7.112001"] = Value{Value: "1/1"}
	for port := 1; port <= 2; port++ {
		idx := fmt.Sprintf("120%03d", port*10)
		oids[".1.3.6.1.2.1.47.1.1.1.1.4."+idx] = Value{Value: "112001"}
		oids[".1.3.6.1.2.1.47.1.1.1.1.5."+idx] = Value{Value: "10"}
		oids[".1.3.6.1.2.1.47.1.1.1.1.7."+idx] = Value{Value: fmt.Sprintf("1/1/%d", port)}
	}
	return oids
}

// fixtureIndistinctChassisRowsStackN returns the same shape with `members`
// chassis rows, all reporting parentRelPos=1 and all named "Chassis".
//
// serialedMembers bounds how many of them report a serial: the six-member
// capture this is derived from serials only its first chassis, and a row with
// no serial is dropped before id derivation, so passing 1 reproduces a real
// six-member stack silently ingesting as a single standalone Device.
func fixtureIndistinctChassisRowsStackN(members, serialedMembers int) ObjectIDValueMap {
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.1.5.0":          {Value: "stack-indistinct-n.example"},
		".1.3.6.1.2.1.47.1.1.1.1.4.1": {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1": {Value: "11"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1": {Value: "-1"},
		".1.3.6.1.2.1.47.1.1.1.1.7.1": {Value: "Stack"},
	}
	for member := 1; member <= members; member++ {
		var (
			chassis = fmt.Sprintf("%d01001", member)
			module  = fmt.Sprintf("%d12001", member)
		)
		set := func(col int, idx, val string) {
			oids[fmt.Sprintf(".1.3.6.1.2.1.47.1.1.1.1.%d.%s", col, idx)] = Value{Value: val}
		}
		set(4, chassis, "1")
		set(5, chassis, "3")
		set(6, chassis, "1")
		set(7, chassis, "Chassis")
		set(13, chassis, "SWITCH-48G-4SFP")
		if member <= serialedMembers {
			set(11, chassis, fmt.Sprintf("SN00000%05d", member*101))
		}
		set(4, module, chassis)
		set(5, module, "9")
		set(7, module, fmt.Sprintf("%d/1", member))
		for port := 1; port <= 2; port++ {
			idx := fmt.Sprintf("12%d%03d", member-1, port*10)
			set(4, idx, module)
			set(5, idx, "10")
			set(7, idx, fmt.Sprintf("%d/1/%d", member, port))
		}
	}
	return oids
}

// fixtureJunosQFX4MemberVC builds a Junos QFX5100 4-member VC scenario:
//   - sysName "vc-edge-01"
//   - 4 entPhysical chassis rows at indices 1..4
//   - parentRelPos = 0 on all rows (Junos doesn't populate it)
//   - entPhysicalName = "FPC 0" .. "FPC 3" -> ids 0..3
//   - 4 distinct serials, model "EX4300-48T"
func fixtureJunosQFX4MemberVC() ObjectIDValueMap {
	out := ObjectIDValueMap{
		".1.3.6.1.2.1.1.5.0": {Value: "vc-edge-01"},
	}
	for _, member := range []struct {
		idx, fpc int
		serial   string
	}{
		{1, 0, "BR0000000001"},
		{2, 1, "BR0000000002"},
		{3, 2, "BR0000000003"},
		{4, 3, "BR0000000004"},
	} {
		prefix := func(col int) string {
			return fmt.Sprintf(".1.3.6.1.2.1.47.1.1.1.1.%d.%d", col, member.idx)
		}
		out[prefix(4)] = Value{Value: "0"}
		out[prefix(5)] = Value{Value: "3"}
		out[prefix(6)] = Value{Value: "0"} // parentRelPos unused on Junos
		out[prefix(7)] = Value{Value: fmt.Sprintf("FPC %d", member.fpc)}
		out[prefix(11)] = Value{Value: member.serial}
		out[prefix(13)] = Value{Value: "EX4300-48T"}
	}
	return out
}

// fixtureCiscoCat9400xStackWiseVirtual returns an ObjectIDValueMap shaped
// like a Cisco Catalyst 9400X-SVL pair (real recording, anonymized):
//   - sysName "c9400x-svl.example"
//   - entPhysical row 1: class=11 (stack), containedIn=0, name="Virtual Stack" — the parent container
//   - entPhysical row 2:   class=3 (chassis), containedIn=1, parentRelPos=1, name="Switch 1 Chassis", serial FXS2238Q0WZ, model C9407R
//   - entPhysical row 500: class=3 (chassis), containedIn=1, parentRelPos=2, name="Switch 2 Chassis", serial FXS2238Q0WG, model C9407R
//
// This is the "wrapped" topology: physical chassis are nested under a
// class=11 (stack) parent rather than at the ENTITY-MIB root. Cisco
// StackWise Virtual on the 9400/9500/9600 series uses this layout.
func fixtureCiscoCat9400xStackWiseVirtual() ObjectIDValueMap {
	return ObjectIDValueMap{
		".1.3.6.1.2.1.1.5.0": {Value: "c9400x-svl.example"},
		".1.3.6.1.2.1.1.2.0": {Value: ".1.3.6.1.4.1.9.1.2839"},
		// Parent stack container (index 1).
		".1.3.6.1.2.1.47.1.1.1.1.4.1": {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1": {Value: "11"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1": {Value: "-1"},
		".1.3.6.1.2.1.47.1.1.1.1.7.1": {Value: "Virtual Stack"},
		// Switch 1 chassis (index 2).
		".1.3.6.1.2.1.47.1.1.1.1.4.2":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.5.2":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.2":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.7.2":  {Value: "Switch 1 Chassis"},
		".1.3.6.1.2.1.47.1.1.1.1.11.2": {Value: "FXS2238Q0WZ"},
		".1.3.6.1.2.1.47.1.1.1.1.13.2": {Value: "C9407R"},
		// Switch 2 chassis (index 500).
		".1.3.6.1.2.1.47.1.1.1.1.4.500":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.5.500":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.500":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.7.500":  {Value: "Switch 2 Chassis"},
		".1.3.6.1.2.1.47.1.1.1.1.11.500": {Value: "FXS2238Q0WG"},
		".1.3.6.1.2.1.47.1.1.1.1.13.500": {Value: "C9407R"},
	}
}

// fixtureZeroBasedParentRelWrappedStack returns an ObjectIDValueMap shaped
// like a 4-member stack (issue #458): a class=11 stack container at index 1
// that shares member 1's serial, wrapping four class=3 chassis rows whose
// entPhysicalParentRelPos is ZERO-BASED (0,1,2,3) while entPhysicalName
// carries the true member numbers 1, 2, 4, 5 — non-sequential, as after a
// member replacement — so tests can distinguish name-derived ids from a
// broken ordinal assignment that would coincide with sequential names.
func fixtureZeroBasedParentRelWrappedStack() ObjectIDValueMap {
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.1.5.0": {Value: "stack.example"},
		// Stack container (class=11) — shares member 1's serial; never a member.
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "11"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":  {Value: "-1"},
		".1.3.6.1.2.1.47.1.1.1.1.7.1":  {Value: "Stack"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "SN0000000001"},
	}
	serials := []string{"SN0000000001", "SN0000000013", "SN0000000023", "SN0000000027"}
	memberNums := []int{1, 2, 4, 5}
	for i := 0; i < 4; i++ {
		idx := fmt.Sprintf("%d", (i+1)*1000)
		oids[".1.3.6.1.2.1.47.1.1.1.1.4."+idx] = Value{Value: "1"}
		oids[".1.3.6.1.2.1.47.1.1.1.1.5."+idx] = Value{Value: "3"}
		oids[".1.3.6.1.2.1.47.1.1.1.1.6."+idx] = Value{Value: fmt.Sprintf("%d", i)} // ZERO-BASED
		oids[".1.3.6.1.2.1.47.1.1.1.1.7."+idx] = Value{Value: fmt.Sprintf("Switch %d", memberNums[i])}
		oids[".1.3.6.1.2.1.47.1.1.1.1.11."+idx] = Value{Value: serials[i]}
	}
	return oids
}
