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

// fixtureArubaCX2MemberVSF returns an ObjectIDValueMap shaped like a
// 2-member Aruba CX VSF stack:
//   - sysName "aruba-cx-stack"
//   - entPhysical rows at indices 1 and 2
//   - both entPhysicalClass=3, entPhysicalContainedIn=0
//   - parentRelPos = 1 and 2 (numeric VSF member IDs)
//   - model "Aruba-6300M-48G" on both members
func fixtureArubaCX2MemberVSF() ObjectIDValueMap {
	return ObjectIDValueMap{
		".1.3.6.1.2.1.1.5.0":           {Value: "aruba-cx-stack"},
		".1.3.6.1.2.1.47.1.1.1.1.4.1":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.1":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.1":  {Value: "1"},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "SG12345"},
		".1.3.6.1.2.1.47.1.1.1.1.13.1": {Value: "Aruba-6300M-48G"},
		".1.3.6.1.2.1.47.1.1.1.1.4.2":  {Value: "0"},
		".1.3.6.1.2.1.47.1.1.1.1.5.2":  {Value: "3"},
		".1.3.6.1.2.1.47.1.1.1.1.6.2":  {Value: "2"},
		".1.3.6.1.2.1.47.1.1.1.1.11.2": {Value: "SG12346"},
		".1.3.6.1.2.1.47.1.1.1.1.13.2": {Value: "Aruba-6300M-48G"},
	}
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
