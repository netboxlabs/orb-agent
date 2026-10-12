package mapping

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

func newTestDeviceMapper() *DeviceMapper {
	return &DeviceMapper{logger: slog.Default()}
}

func TestDeviceMapper_applyDefaults_LocationLiteral(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{Location: "DC1-Building-A", Site: "dc1"}
	m.applyDefaults(entity, defaults, nil)
	require.NotNil(t, entity.Location)
	require.NotNil(t, entity.Location.Name)
	assert.Equal(t, "DC1-Building-A", *entity.Location.Name)
	require.NotNil(t, entity.Location.Site)
	require.NotNil(t, entity.Location.Site.Name)
	assert.Equal(t, "dc1", *entity.Location.Site.Name)
}

func TestDeviceMapper_applyDefaults_LocationNonSNMPDecimalIsLiteral(t *testing.T) {
	// "3.14.159" is a literal (room number), not an OID — must not be
	// re-classified even if a walked map is present.
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{Location: "3.14.159", Site: "dc1"}
	walked := map[string]string{".1.3.6.1.2.1.1.6.0": "Data Center 01"}
	m.applyDefaults(entity, defaults, walked)
	require.NotNil(t, entity.Location)
	require.NotNil(t, entity.Location.Name)
	assert.Equal(t, "3.14.159", *entity.Location.Name)
}

func TestDeviceMapper_applyDefaults_LocationOIDReferenceResolves(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{Location: ".1.3.6.1.2.1.1.6.0", Site: "dc1"}
	walked := map[string]string{".1.3.6.1.2.1.1.6.0": "Data Center 01"}
	m.applyDefaults(entity, defaults, walked)
	require.NotNil(t, entity.Location)
	require.NotNil(t, entity.Location.Name)
	assert.Equal(t, "Data Center 01", *entity.Location.Name)
	require.NotNil(t, entity.Location.Site)
	assert.Equal(t, "dc1", *entity.Location.Site.Name)
}

func TestDeviceMapper_applyDefaults_LocationOIDReferenceMissingSkips(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{Location: ".1.3.6.1.2.1.1.6.0", Site: "dc1"}
	m.applyDefaults(entity, defaults, map[string]string{})
	assert.Nil(t, entity.Location)
}

func TestDeviceMapper_applyDefaults_LocationOIDReferenceEmptySkips(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{Location: ".1.3.6.1.2.1.1.6.0", Site: "dc1"}
	walked := map[string]string{".1.3.6.1.2.1.1.6.0": "   "}
	m.applyDefaults(entity, defaults, walked)
	assert.Nil(t, entity.Location)
}

func TestDeviceMapper_applyDefaults_LocationOverridesPreSetValue(t *testing.T) {
	m := newTestDeviceMapper()
	existing := "pre-existing"
	entity := &diode.Device{Location: &diode.Location{Name: &existing}}
	defaults := &config.Defaults{Location: "DC1-Building-A", Site: "dc1"}
	m.applyDefaults(entity, defaults, nil)
	require.NotNil(t, entity.Location)
	require.NotNil(t, entity.Location.Name)
	assert.Equal(t, "DC1-Building-A", *entity.Location.Name)
}

func TestDeviceMapper_applyDefaults_AssetTagLiteral(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{AssetTag: "ASSET-007"}
	m.applyDefaults(entity, defaults, nil)
	require.NotNil(t, entity.AssetTag)
	assert.Equal(t, "ASSET-007", *entity.AssetTag)
}

func TestDeviceMapper_applyDefaults_AssetTagOIDReferenceResolves(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{AssetTag: ".1.3.6.1.2.1.1.4.0"}
	walked := map[string]string{".1.3.6.1.2.1.1.4.0": "asset-12345"}
	m.applyDefaults(entity, defaults, walked)
	require.NotNil(t, entity.AssetTag)
	assert.Equal(t, "asset-12345", *entity.AssetTag)
}

func TestDeviceMapper_applyDefaults_AssetTagOIDReferenceMissingSkips(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{AssetTag: ".1.3.6.1.2.1.1.4.0"}
	m.applyDefaults(entity, defaults, map[string]string{})
	assert.Nil(t, entity.AssetTag)
}

func TestDeviceMapper_applyDefaults_AssetTagOverridesPreSetValue(t *testing.T) {
	m := newTestDeviceMapper()
	existing := "PRE-EXISTING"
	entity := &diode.Device{AssetTag: &existing}
	defaults := &config.Defaults{AssetTag: "FROM-CONFIG"}
	m.applyDefaults(entity, defaults, nil)
	require.NotNil(t, entity.AssetTag)
	assert.Equal(t, "FROM-CONFIG", *entity.AssetTag)
}

func TestDeviceMapper_applyDefaults_AssetTagEmptyConfigIsNoop(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{}
	m.applyDefaults(entity, defaults, nil)
	assert.Nil(t, entity.AssetTag)
}

func TestDeviceMapper_applyDefaults_AssetTagExceedsMaxLengthSkips(t *testing.T) {
	// NetBox asset_tag is CharField(max_length=50). The diode SDK does
	// not validate; we warn-skip rather than truncate to avoid silent
	// uniqueness collisions. Start with a non-nil AssetTag so the test
	// observes "skipped" as "did not overwrite" rather than the trivial
	// "stayed nil because no path writes it" assertion.
	m := newTestDeviceMapper()
	preset := "ORIGINAL"
	entity := &diode.Device{AssetTag: &preset}
	tooLong := strings.Repeat("x", 51)
	defaults := &config.Defaults{AssetTag: tooLong}
	m.applyDefaults(entity, defaults, nil)
	require.NotNil(t, entity.AssetTag)
	assert.Equal(t, "ORIGINAL", *entity.AssetTag)
}

func TestDeviceMapper_applyDefaults_AssetTagExactlyMaxLengthSet(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	exact := strings.Repeat("x", 50)
	defaults := &config.Defaults{AssetTag: exact}
	m.applyDefaults(entity, defaults, nil)
	require.NotNil(t, entity.AssetTag)
	assert.Equal(t, exact, *entity.AssetTag)
}

func TestDeviceMapper_applyDefaults_AssetTagFiftyRunesNonASCIISet(t *testing.T) {
	// NetBox CharField(max_length=N) counts characters. A string of 50
	// non-ASCII runes is exactly 50 characters (and 100 bytes in UTF-8)
	// and must be accepted, not rejected on byte length.
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	exact := strings.Repeat("é", 50) // 50 runes, 100 bytes
	defaults := &config.Defaults{AssetTag: exact}
	m.applyDefaults(entity, defaults, nil)
	require.NotNil(t, entity.AssetTag)
	assert.Equal(t, exact, *entity.AssetTag)
}

func TestDeviceMapper_applyDefaults_AssetTagFiftyOneRunesNonASCIISkips(t *testing.T) {
	m := newTestDeviceMapper()
	preset := "ORIGINAL"
	entity := &diode.Device{AssetTag: &preset}
	tooLong := strings.Repeat("é", 51) // 51 runes
	defaults := &config.Defaults{AssetTag: tooLong}
	m.applyDefaults(entity, defaults, nil)
	require.NotNil(t, entity.AssetTag)
	assert.Equal(t, "ORIGINAL", *entity.AssetTag)
}

// TestDeviceMapper_applyDefaults_AssetTagPlaceholderViaOIDSkips guards the
// Fix 1 finding: a defaults.asset_tag that is an OID reference which resolves
// to a well-known placeholder ("UNKNOWN", "N/A", etc.) must be rejected just
// like a directly-configured placeholder. Before the fix, the resolved value
// bypassed vetAssetTag and was ingested into NetBox as-is, poisoning the
// highest-precedence device matcher.
func TestDeviceMapper_applyDefaults_AssetTagPlaceholderViaOIDSkips(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{AssetTag: ".1.3.6.1.2.1.1.4.0"}
	walked := map[string]string{".1.3.6.1.2.1.1.4.0": "UNKNOWN"}
	m.applyDefaults(entity, defaults, walked)
	assert.Nil(t, entity.AssetTag,
		"OID reference resolving to a placeholder must be rejected")
}

// TestDeviceMapper_applyDefaults_AssetTagGarbageViaOIDSkips guards the Fix 1
// finding: a defaults.asset_tag OID reference that resolves to a value
// containing embedded NUL or control bytes must be rejected; those bytes make
// the asset_tag unsafe as a NetBox unique identifier.
func TestDeviceMapper_applyDefaults_AssetTagGarbageViaOIDSkips(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{AssetTag: ".1.3.6.1.2.1.1.4.0"}
	walked := map[string]string{".1.3.6.1.2.1.1.4.0": "TAG\x00\x01"}
	m.applyDefaults(entity, defaults, walked)
	assert.Nil(t, entity.AssetTag,
		"OID reference resolving to a value with control bytes must be rejected")
}

func TestDeviceMapper_applyDefaults_RackCarriesDeviceSiteAndLocation(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	m.applyDefaults(entity, &config.Defaults{Site: "DC1", Location: "Hall 1", Rack: "R12"}, nil)
	require.NotNil(t, entity.Rack)
	require.NotNil(t, entity.Rack.Name)
	assert.Equal(t, "R12", *entity.Rack.Name)
	require.NotNil(t, entity.Site)
	assert.Same(t, entity.Site, entity.Rack.Site, "the rack is in the device's site")
	require.NotNil(t, entity.Location)
	assert.Same(t, entity.Location, entity.Rack.Location, "the rack is in the device's location")
	assert.Nil(t, entity.Position)
	assert.Nil(t, entity.Face)
}

func TestDeviceMapper_applyDefaults_RackWithoutLocation(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	m.applyDefaults(entity, &config.Defaults{Site: "DC1", Rack: "R12"}, nil)
	require.NotNil(t, entity.Rack)
	assert.Equal(t, "R12", *entity.Rack.Name)
	assert.Same(t, entity.Site, entity.Rack.Site)
	assert.Nil(t, entity.Rack.Location)
}

func TestDeviceMapper_applyDefaults_RackTakesOIDResolvedLocation(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{Site: "DC1", Location: ".1.3.6.1.2.1.1.6.0", Rack: "R12"}
	m.applyDefaults(entity, defaults, map[string]string{".1.3.6.1.2.1.1.6.0": "Hall 1"})
	require.NotNil(t, entity.Rack)
	require.NotNil(t, entity.Rack.Location)
	assert.Same(t, entity.Location, entity.Rack.Location)
	assert.Equal(t, "Hall 1", *entity.Rack.Location.Name)
}

func TestDeviceMapper_applyDefaults_RackWithoutUnresolvedLocation(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{Site: "DC1", Location: ".1.3.6.1.2.1.1.6.0", Rack: "R12"}
	m.applyDefaults(entity, defaults, map[string]string{})
	require.NotNil(t, entity.Rack)
	assert.Nil(t, entity.Location)
	assert.Nil(t, entity.Rack.Location, "a location the device did not get is not sent on the rack")
}

func TestDeviceMapper_applyDefaults_RackNameIsLiteral(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	defaults := &config.Defaults{Site: "DC1", Rack: ".1.3.6.1.2.1.1.6.0"}
	m.applyDefaults(entity, defaults, map[string]string{".1.3.6.1.2.1.1.6.0": "Hall 1"})
	require.NotNil(t, entity.Rack)
	assert.Equal(t, ".1.3.6.1.2.1.1.6.0", *entity.Rack.Name, "a rack name is never resolved from a walked OID")
}

func TestDeviceMapper_applyDefaults_RackNameTrimmed(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	m.applyDefaults(entity, &config.Defaults{Site: "DC1", Rack: "  R12 "}, nil)
	require.NotNil(t, entity.Rack)
	assert.Equal(t, "R12", *entity.Rack.Name)

	blank := &diode.Device{}
	m.applyDefaults(blank, &config.Defaults{Site: "DC1", Rack: "   "}, nil)
	assert.Nil(t, blank.Rack, "a blank rack is unset")
}

func TestDeviceMapper_applyDefaults_PositionAndFace(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	pos := 40.5
	m.applyDefaults(entity, &config.Defaults{Site: "DC1", Rack: "R12", Position: &pos, Face: "Front"}, nil)
	require.NotNil(t, entity.Rack)
	require.NotNil(t, entity.Position)
	assert.InDelta(t, 40.5, *entity.Position, 0)
	require.NotNil(t, entity.Face)
	assert.Equal(t, "front", *entity.Face, "face is emitted lowercase")
}

func TestDeviceMapper_applyDefaults_NoRackPlacementWhenUnset(t *testing.T) {
	m := newTestDeviceMapper()
	entity := &diode.Device{}
	m.applyDefaults(entity, &config.Defaults{Site: "DC1", Location: "Hall 1"}, nil)
	assert.Nil(t, entity.Rack)
	assert.Nil(t, entity.Position)
	assert.Nil(t, entity.Face)
}

func TestDeviceMapper_applyDefaults_PositionNeedsRackAndFace(t *testing.T) {
	m := newTestDeviceMapper()
	pos := 10.0

	noRack := &diode.Device{}
	m.applyDefaults(noRack, &config.Defaults{Site: "DC1", Position: &pos, Face: "front"}, nil)
	assert.Nil(t, noRack.Position, "NetBox refuses a position without a rack")
	assert.Nil(t, noRack.Face)

	noFace := &diode.Device{}
	m.applyDefaults(noFace, &config.Defaults{Site: "DC1", Rack: "R12", Position: &pos}, nil)
	require.NotNil(t, noFace.Rack)
	assert.Nil(t, noFace.Position, "NetBox refuses a position without a face")
	assert.Nil(t, noFace.Face)
}

// Without a sysObjectID the mapper looks nothing up, so a model and
// manufacturer pinned in defaults are the device type. Either alone is not:
// NetBox needs both.
func TestDeviceMapper_applyDefaults_DeviceTypeFromDefaults(t *testing.T) {
	m := newTestDeviceMapper()
	for name, tc := range map[string]struct {
		device    config.DeviceDefaults
		wantModel string
	}{
		"model and manufacturer": {config.DeviceDefaults{Model: "Operator Model", Manufacturer: "VendorA"}, "Operator Model"},
		"model only":             {config.DeviceDefaults{Model: "Operator Model"}, ""},
		"manufacturer only":      {config.DeviceDefaults{Manufacturer: "VendorA"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			entity := &diode.Device{}
			m.applyDefaults(entity, &config.Defaults{Device: tc.device}, nil)
			if tc.wantModel == "" {
				assert.Nil(t, entity.DeviceType)
				return
			}
			require.NotNil(t, entity.DeviceType)
			assert.Equal(t, tc.wantModel, entity.DeviceType.GetModel())
			assert.Equal(t, "VendorA", entity.DeviceType.GetManufacturer().GetName())
		})
	}
}

// A device type the sysObjectID lookup built, with the defaults already
// applied, is left as it is.
func TestDeviceMapper_applyDefaults_KeepsALookedUpDeviceType(t *testing.T) {
	m := newTestDeviceMapper()
	looked := &diode.DeviceType{Model: strPtr("vendorProductName48"), Manufacturer: &diode.Manufacturer{Name: strPtr("VendorB")}}
	entity := &diode.Device{DeviceType: looked}
	m.applyDefaults(entity, &config.Defaults{Device: config.DeviceDefaults{Model: "Operator Model", Manufacturer: "VendorA"}}, nil)
	assert.Same(t, looked, entity.DeviceType)
}
