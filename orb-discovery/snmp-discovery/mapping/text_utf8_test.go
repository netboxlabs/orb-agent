package mapping

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestTruncateText(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  string
		runes int
	}{
		{"empty", "", "", 0},
		{"short ASCII is unchanged", "Uplink", "Uplink", 6},
		{
			// 400 bytes but 200 characters: NetBox accepts it, so it must not be cut.
			"200 two-byte characters fit", strings.Repeat("é", 200), strings.Repeat("é", 200), 200,
		},
		{"one character over is cut to the limit", strings.Repeat("a", 201), strings.Repeat("a", 197) + "...", 200},
		{
			// A cut by byte at 197 lands inside the é and leaves invalid UTF-8.
			"multi-byte character at the cut stays whole",
			strings.Repeat("a", 196) + "é suite de la description",
			strings.Repeat("a", 196) + "é" + "...",
			200,
		},
		{"three-byte characters", strings.Repeat("中", 250), strings.Repeat("中", 197) + "...", 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateText(tt.in, descriptionMaxLen)
			assert.Equal(t, tt.want, got)
			assert.True(t, utf8.ValidString(got), "result must be valid UTF-8")
			assert.Equal(t, tt.runes, utf8.RuneCountInString(got))
		})
	}
}

// marshalErr is the operation gRPC runs on every entity before sending it, and
// the one that fails with "string field contains invalid UTF-8".
func marshalErr(e diode.Entity) error {
	_, err := proto.Marshal(e.ConvertToProtoEntity())
	return err
}

func TestRepairInvalidUTF8RepairsWhatProtobufRejects(t *testing.T) {
	iface := &diode.Interface{Name: strPtr("GE0/0/1"), Description: strPtr("B\xe2timent A")}
	require.Error(t, marshalErr(iface), "control: the raw entity must fail to marshal")

	repaired, refused := RepairInvalidUTF8([]diode.Entity{iface})

	require.NoError(t, marshalErr(iface))
	assert.Equal(t, "B\uFFFDtiment A", *iface.Description)
	assert.Equal(t, []Repair{{Entity: "Interface", Field: "Description", Count: 1, Example: `B\xe2timent A`}}, repaired)
	assert.Empty(t, refused)
}

func TestRepairInvalidUTF8LeavesValidTextUntouched(t *testing.T) {
	iface := &diode.Interface{Name: strPtr("GE0/0/1"), Description: strPtr("Bâtiment A, 中文")}
	before := *iface.Description

	repaired, refused := RepairInvalidUTF8([]diode.Entity{iface})

	assert.Empty(t, repaired)
	assert.Empty(t, refused)
	assert.Equal(t, before, *iface.Description, "valid UTF-8 must be byte-for-byte unchanged")
}

func TestRepairInvalidUTF8ReachesNestedAndSharedValues(t *testing.T) {
	// One VLAN referenced from two interfaces and emitted on its own, as the
	// mapper does: it must be repaired, and reported, once.
	vlan := &diode.VLAN{Vid: int64Ptr(10), Name: strPtr("Voice"), Description: strPtr("Salle r\xe9union")}
	first := &diode.Interface{Name: strPtr("GE0/0/1"), UntaggedVlan: vlan}
	second := &diode.Interface{Name: strPtr("GE0/0/2"), TaggedVlans: []*diode.VLAN{vlan}}

	repaired, _ := RepairInvalidUTF8([]diode.Entity{first, second, vlan})

	assert.Equal(t, "Salle r\uFFFDunion", *vlan.Description)
	assert.Equal(t, []Repair{{Entity: "VLAN", Field: "Description", Count: 1, Example: `Salle r\xe9union`}}, repaired)
	for _, e := range []diode.Entity{first, second, vlan} {
		require.NoError(t, marshalErr(e))
	}
}

func TestRepairInvalidUTF8ReachesInterfaceTypedFields(t *testing.T) {
	iface := &diode.Interface{Name: strPtr("GE0/0/1"), Description: strPtr("c\xe2ble")}
	ip := &diode.IPAddress{Address: strPtr("192.0.2.1/24"), AssignedObject: iface}

	repaired, _ := RepairInvalidUTF8([]diode.Entity{ip})

	assert.Equal(t, "c\uFFFDble", *iface.Description)
	assert.Equal(t, []Repair{{Entity: "Interface", Field: "Description", Count: 1, Example: `c\xe2ble`}}, repaired)
	require.NoError(t, marshalErr(ip))
}

func TestRepairInvalidUTF8RefusesMatchedFields(t *testing.T) {
	// GBK names whose bytes are all invalid UTF-8: both would repair to "\uFFFD",
	// and Diode would then match the second device to the first.
	first := &diode.Device{Name: strPtr("\xb2\xc6\xce\xf1\xcd\xf8")}
	second := &diode.Device{Name: strPtr("\xbc\xe0\xbf\xd8\xcd\xf8")}
	vlan := &diode.VLAN{Vid: int64Ptr(10), Name: strPtr("r\xe9seau")}

	repaired, refused := RepairInvalidUTF8([]diode.Entity{first, second, vlan})

	assert.Empty(t, repaired)
	assert.Equal(t, []Repair{
		{Entity: "Device", Field: "Name", Count: 2, Example: `\xb2\xc6\xce\xf1\xcd\xf8`},
		{Entity: "VLAN", Field: "Name", Count: 1, Example: `r\xe9seau`},
	}, refused)
	assert.Equal(t, "\xb2\xc6\xce\xf1\xcd\xf8", *first.Name, "a refused value is left as it was")
}

func TestRepairInvalidUTF8RefusesValuesOutsideStructFields(t *testing.T) {
	// Metadata, string slices, map keys and custom field values held in an
	// interface are not free text either.
	device := &diode.Device{
		Name:     strPtr("sw1"),
		Metadata: diode.Metadata{"note": diode.Metadata{"k\xe9y": "caf\xe9"}},
		Tags:     []*diode.Tag{{Name: strPtr("core"), ObjectTypes: []string{"dcim.device", "b\xe2d"}}},
		CustomFields: map[string]*diode.CustomFieldValue{
			"room": {Value: diode.CustomFieldValueText("salle de r\xe9union")},
		},
	}

	repaired, refused := RepairInvalidUTF8([]diode.Entity{device})

	assert.Empty(t, repaired)
	assert.ElementsMatch(t, []Repair{
		{Entity: "Device", Field: "Metadata", Count: 2, Example: `k\xe9y`},
		{Entity: "Tag", Field: "ObjectTypes", Count: 1, Example: `b\xe2d`},
		{Entity: "CustomFieldValue", Field: "Value", Count: 1, Example: `salle de r\xe9union`},
	}, refused)
}

func TestRepairInvalidUTF8GroupsRepeatedFields(t *testing.T) {
	// Many interfaces with the same encoding fault must not produce one log
	// line each: one Repair per (entity, field), counted, with the first value.
	first := &diode.Interface{Name: strPtr("GE0/0/1"), Description: strPtr("r\xe9seau")}
	second := &diode.Interface{Name: strPtr("GE0/0/2"), Description: strPtr("t\xe9l\xe9phonie")}

	repaired, _ := RepairInvalidUTF8([]diode.Entity{first, second})

	assert.Equal(t, []Repair{{Entity: "Interface", Field: "Description", Count: 2, Example: `r\xe9seau`}}, repaired)
	assert.Equal(t, "t\uFFFDl\uFFFDphonie", *second.Description)
}

func TestRepairInvalidUTF8EndsOnReferenceCycles(t *testing.T) {
	device := &diode.Device{Name: strPtr("sw1"), Description: strPtr("c\xe2ble")}
	iface := &diode.Interface{Name: strPtr("GE0/0/1"), Device: device}
	device.PrimaryIp4 = &diode.IPAddress{Address: strPtr("192.0.2.1/24"), AssignedObject: iface}

	repaired, _ := RepairInvalidUTF8([]diode.Entity{device})

	assert.Equal(t, []Repair{{Entity: "Device", Field: "Description", Count: 1, Example: `c\xe2ble`}}, repaired)
}

func TestRepairInvalidUTF8ToleratesEmptyValues(t *testing.T) {
	ip := &diode.IPAddress{}      // nil pointers, nil interface
	device := &diode.Device{}     // nil map, nil slices
	var nilIface *diode.Interface // a typed nil inside the slice
	assert.NotPanics(t, func() {
		repaired, refused := RepairInvalidUTF8([]diode.Entity{ip, device, nilIface, nil})
		assert.Empty(t, repaired)
		assert.Empty(t, refused)
	})
}
