package profiles

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The bundled tree carries ten trap definition files. They are loaded as
// profiles today with their traps: key dropped by the permissive decode, so
// the first thing to pin is that the field is read at all.
func TestTrapNames_BundledDefinitionsAreRead(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)

	names := TrapNames(all)
	assert.GreaterOrEqual(t, len(names), 185, "ten bundled files carry about 190 definitions")
	assert.Equal(t, "linkDown", names["1.3.6.1.6.3.1.1.5.3"])
	assert.Equal(t, "bigipTrafficGroupStandby", names["1.3.6.1.4.1.3375.2.4.0.141"],
		"f5 carries the bulk of the definitions")
}

// The bundled cisco file maps both .5.5 and .5.6 to authenticationFailure.
// TrapNames reports what the files say; the RFC 1215 override lives in the
// traps package, so this pins that the loader does not silently correct it.
func TestTrapNames_ReportsTheBundledFilesAsWritten(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)

	names := TrapNames(all)
	assert.Equal(t, "authenticationFailure", names["1.3.6.1.6.3.1.1.5.6"],
		"the vendored cisco file is wrong here and must stay byte identical")
}

// A trap OID written with a leading dot in a definition file must land on the
// same key as one written without, or a lookup misses depending on spelling.
func TestTrapNames_NormalisesTheLeadingDot(t *testing.T) {
	names := TrapNames([]*Profile{{
		FileName: "x.yml",
		Traps:    []TrapDef{{OID: ".1.3.6.1.4.1.9.9.41.2.0.1", Name: "clogMessageGenerated"}},
	}})
	assert.Equal(t, "clogMessageGenerated", names["1.3.6.1.4.1.9.9.41.2.0.1"])
}

// When two profiles declare the same OID under different names, the profile
// resolved later wins. TrapNames reports what the files say rather than
// picking a winner itself, so this pins the iteration order rather than some
// preference for one profile over another.
func TestTrapNames_LaterProfileWinsOnACollidingOID(t *testing.T) {
	names := TrapNames([]*Profile{
		{FileName: "a.yml", Traps: []TrapDef{{OID: "1.2.3", Name: "firstName"}}},
		{FileName: "b.yml", Traps: []TrapDef{{OID: "1.2.3", Name: "secondName"}}},
	})
	assert.Equal(t, "secondName", names["1.2.3"])
}

// Traps follow matches and matches_list: the declaring file's own, never
// merged through extends.
func TestResolve_TrapsAreNotInheritedThroughExtends(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "parent.yml", "traps:\n  - trap_oid: 1.2.3\n    trap_name: parentTrap\n")
	writeYAML(t, dir, "child.yml", "extends:\n  - parent.yml\nsysobjectid: 1.3.6.1.4.1.9.1.1\nmetrics: []\n")

	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)
	child, err := l.Resolve("child.yml")
	require.NoError(t, err)
	assert.Empty(t, child.Traps, "a child does not inherit its parent's trap definitions")

	parent, err := l.Resolve("parent.yml")
	require.NoError(t, err)
	require.Len(t, parent.Traps, 1)
	assert.Equal(t, "parentTrap", parent.Traps[0].Name)
}

// One bundled file, ruckus/Ruckus_Contoller_SNMP.yml, declares its three
// traps as flat metric entries with `type: trap` rather than under `traps:`.
// The loader keeps such entries unfolded, since nothing polls them, and the
// name map reads them so those traps are named rather than labelled other.
func TestTrapNames_ReadsFlatTrapEntries(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)

	names := TrapNames(all)
	assert.Equal(t, "ruckusSCGAPDisconnectedTrap", names["1.3.6.1.4.1.25053.2.10.1.23"])
	assert.Equal(t, "ruckusSCGAPRebootTrap", names["1.3.6.1.4.1.25053.2.10.1.25"], "written with a leading dot in the file")
	assert.Equal(t, "ruckusSCGAPLostHeartbeatTrap", names["1.3.6.1.4.1.25053.2.10.1.24"])
	assert.NotContains(t, names, "1.3.6.1.4.1.25053.1.8.1.1.1.1.2.1.11", "a flat gauge entry is not a trap")
}
