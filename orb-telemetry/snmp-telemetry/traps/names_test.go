package traps

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The RFC 1215 table wins over the bundled definitions. The bundled cisco file
// maps 1.3.6.1.6.3.1.1.5.6 to authenticationFailure; per RFC 3584 section
// 3.1(3) it is egpNeighborLoss, and the vendored tree cannot be edited.
func TestBuildNames_RFC1215WinsOverTheBundledFiles(t *testing.T) {
	names := BuildNames(map[string]string{
		"1.3.6.1.6.3.1.1.5.6":        "authenticationFailure",
		"1.3.6.1.4.1.3375.2.4.0.144": "bigipTrafficGroupStandby",
	})
	assert.Equal(t, "egpNeighborLoss", names["1.3.6.1.6.3.1.1.5.6"])
	assert.Equal(t, "bigipTrafficGroupStandby", names["1.3.6.1.4.1.3375.2.4.0.144"],
		"a bundled name with no RFC counterpart is kept")
}

func TestBuildNames_CarriesAllSixGenericTraps(t *testing.T) {
	names := BuildNames(nil)
	want := map[string]string{
		"1.3.6.1.6.3.1.1.5.1": "coldStart",
		"1.3.6.1.6.3.1.1.5.2": "warmStart",
		"1.3.6.1.6.3.1.1.5.3": "linkDown",
		"1.3.6.1.6.3.1.1.5.4": "linkUp",
		"1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
		"1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
	}
	for oid, name := range want {
		assert.Equal(t, name, names[oid], oid)
	}
}

// A raw OID never becomes a label. Anything outside the closed set is "other".
func TestNameFor_UnknownIsOther(t *testing.T) {
	names := BuildNames(nil)
	assert.Equal(t, OtherName, NameFor(names, "1.3.6.1.4.1.99999.0.7"))
	assert.Equal(t, "linkDown", NameFor(names, "1.3.6.1.6.3.1.1.5.3"))
}
