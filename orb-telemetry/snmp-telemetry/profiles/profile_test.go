package profiles

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestIndexTransform_DeserializedFromBundledJuniperProfile(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("juniper/juniper-srx-firewalls.yml")
	require.NoError(t, err)

	// The DCU and SCU tables index on ifIndex first, then on fields of their
	// own, so ifName in ifXTable is found by the first component alone.
	byTable := make(map[string]IndexTransform)
	for _, entry := range p.Metrics {
		if entry.Table == nil {
			continue
		}
		for _, mt := range entry.MetricTags {
			if mt.Tag == "if_interface_name" && mt.Table == "ifXTable" {
				byTable[entry.Table.Name] = mt.IndexTransform
			}
		}
	}
	assert.Equal(t, map[string]IndexTransform{
		"jnxDcuStatsTable": {{Start: 0, End: 0}},
		"jnxScuStatsTable": {{Start: 0, End: 0}},
	}, byTable)
}

func TestIndexTransform_Apply(t *testing.T) {
	tests := []struct {
		name      string
		transform IndexTransform
		rowIndex  string
		want      string
		wantOK    bool
	}{
		// The only shape the bundled profiles use: the first component alone.
		{"first component", IndexTransform{{Start: 0, End: 0}}, "548.1.4.103.111.108.100", "548", true},
		{"single component index", IndexTransform{{Start: 0, End: 0}}, "7", "7", true},
		{"inclusive range", IndexTransform{{Start: 0, End: 1}}, "10.20.30", "10.20", true},
		{"interior range", IndexTransform{{Start: 1, End: 2}}, "10.20.30.40", "20.30", true},
		{"ranges concatenate in order", IndexTransform{{Start: 2, End: 2}, {Start: 0, End: 0}}, "10.20.30", "30.10", true},
		{"empty transform passes the index through", nil, "10.20", "10.20", true},
		{"range past the end", IndexTransform{{Start: 0, End: 3}}, "10.20", "", false},
		{"start past the end", IndexTransform{{Start: 4, End: 4}}, "10.20", "", false},
		{"negative start", IndexTransform{{Start: -1, End: 0}}, "10.20", "", false},
		{"end before start", IndexTransform{{Start: 1, End: 0}}, "10.20", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.transform.Apply(tt.rowIndex)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// A `conversion:` may sit on the metric-tag object rather than inside its
// `column:`. One bundled profile writes it that way, and a struct that does not
// deserialize it there exports the raw octets as the attribute value.
func TestMetricTag_ConversionOnTheTagIsDeserialized(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("cisco/cisco-csr.yml")
	require.NoError(t, err)

	var found *MetricTag
	for _, entry := range p.Metrics {
		for i := range entry.MetricTags {
			if entry.MetricTags[i].Tag == "rtt_echo_source_address" {
				found = &entry.MetricTags[i]
			}
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, "hextoip", found.Conversion)
	require.NotNil(t, found.Column)
	assert.Empty(t, found.Column.Conversion, "the column declares none, so the tag's is the only one")
}

// A `script:` on a symbol is a ktranslate transform of the polled value. The
// collector runs none, so it has to be able to see that one was declared: the
// untransformed number carries the name of the transformed one. Both bundled
// uses rescale a CPU reading.
func TestSymbol_ScriptIsDeserialized(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)

	scripted := func(t *testing.T, relPath, symbolName string) {
		t.Helper()
		p, err := l.Resolve(relPath)
		require.NoError(t, err)
		for _, entry := range p.Metrics {
			for i := range entry.Symbols {
				if entry.Symbols[i].Name == symbolName {
					assert.NotEmpty(t, entry.Symbols[i].Script)
					return
				}
			}
		}
		t.Fatalf("symbol %s not found in %s", symbolName, relPath)
	}

	scripted(t, "ubiquiti/unifi-access-point.yml", "loadValue")
	scripted(t, "isilon/isilon.yml", "clusterCPUIdlePct")
}

// A `match_attributes:` on a tag column filters the rows of the entry it
// belongs to. Both bundled uses list one pattern; a struct that does not
// deserialize it emits every row of the table the entry names.
func TestTagColumn_MatchAttributesAreDeserialized(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)

	filters := func(t *testing.T, relPath string) map[string][]string {
		t.Helper()
		p, err := l.Resolve(relPath)
		require.NoError(t, err)
		got := make(map[string][]string)
		for _, entry := range p.Metrics {
			for i := range entry.MetricTags {
				for _, col := range []*TagColumn{entry.MetricTags[i].Column, entry.MetricTags[i].Symbol} {
					if col != nil && len(col.MatchAttributes) > 0 {
						got[col.Name] = col.MatchAttributes
					}
				}
			}
		}
		return got
	}

	assert.Equal(t, map[string][]string{"entPhysicalName": {"Board"}}, filters(t, "hp/hp-h3c-switch.yml"))
	assert.Equal(t, map[string][]string{"loadDescr": {"1 Minute Average"}}, filters(t, "ubiquiti/unifi-access-point.yml"))
}

// ---------------------------------------------------------------------------
// no_use_bulkwalkall
// ---------------------------------------------------------------------------

// A profile that disables bulk walking says so with `no_use_bulkwalkall`, and
// the field has to survive both parsing and the extends merge. A profile whose
// flag is dropped is bulk walked against an agent that was declared unable to
// answer a GETBULK.
func TestProfile_NoUseBulkWalkAllDeserializes(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)

	all, err := l.AllResolved()
	require.NoError(t, err)

	var disabled []string
	for _, p := range all {
		if p.NoUseBulkWalkAll {
			disabled = append(disabled, p.RelPath)
		}
	}
	// The bundled set declares the field five times, at profile level only:
	// true in these three, false in nutanix/nutanix.yml and
	// vmware/vmware-nsx.yml, where false is also the zero value.
	assert.Equal(t, []string{
		"_general/net-snmp.yml",
		"elemental/elemental-device.yml",
		"sunbird/power-iq.yml",
	}, disabled)

	nutanix, err := l.Resolve("nutanix/nutanix.yml")
	require.NoError(t, err)
	assert.False(t, nutanix.NoUseBulkWalkAll)
}

// The flag describes the agent, so a profile that inherits from one carrying it
// inherits the restriction. Merging the other way would bulk walk a device a
// profile in its own chain said not to.
func TestResolve_NoUseBulkWalkAllInheritsFromParent(t *testing.T) {
	dir := t.TempDir()
	writeYAML(t, dir, "base.yml", `
no_use_bulkwalkall: true
metrics:
  - symbol:
      name: sysUpTime
      OID: 1.3.6.1.2.1.1.3.0
`)
	writeYAML(t, dir, "child.yml", `
extends:
  - base.yml
sysobjectid: 1.3.6.1.4.1.8072.3.2.10
`)
	writeYAML(t, dir, "own.yml", `
no_use_bulkwalkall: true
sysobjectid: 1.3.6.1.4.1.8072.3.2.11
`)
	writeYAML(t, dir, "plain.yml", `
sysobjectid: 1.3.6.1.4.1.8072.3.2.12
`)
	l, err := NewLoader(dir, silentLogger)
	require.NoError(t, err)

	for name, want := range map[string]bool{
		"base.yml":  true,
		"child.yml": true,
		"own.yml":   true,
		"plain.yml": false,
	} {
		p, err := l.Resolve(name)
		require.NoError(t, err)
		assert.Equal(t, want, p.NoUseBulkWalkAll, "profile %q", name)
	}
}

// ---------------------------------------------------------------------------
// A metric tag that carries its OID directly
// ---------------------------------------------------------------------------

// A metric tag may write `column:` empty and put the OID and name on the tag
// object itself. A struct that does not deserialize them there discards the
// OID, and the rows of the entry are exported without the tag.
func TestMetricTag_DirectOIDIsDeserialized(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)

	p, err := l.Resolve("raritan/dominion.yml")
	require.NoError(t, err)

	got := make(map[string]string)
	for _, entry := range p.Metrics {
		for i := range entry.MetricTags {
			mt := &entry.MetricTags[i]
			if mt.Column != nil || mt.Symbol != nil || mt.OID == "" {
				continue
			}
			got[mt.Name] = mt.OID
		}
	}
	assert.Equal(t, map[string]string{
		"portDataName": "1.3.6.1.4.1.13742.3.1.4.1.3",
		"portDataType": "1.3.6.1.4.1.13742.3.1.4.1.4",
	}, got)
}

// An enum member written with no value decodes to integer 0 under a plain map,
// which invents a mapping the profile never wrote. It has to stay out of the
// usable mappings, and it has to stay visible so it can be reported.
func TestEnum_MemberWithNoValueIsNotAMapping(t *testing.T) {
	const doc = `
metrics:
  - MIB: TEST-MIB
    table:
      OID: 1.2.3
      name: envTable
    symbols:
      - name: envState
        OID: 1.2.3.1.1
        enum:
          off: 0
          chassis: 2
          battery:
    metric_tags:
      - column:
          name: envType
          OID: 1.2.3.1.2
          enum:
            fan: 4
            voltage:
`
	var p Profile
	require.NoError(t, yaml.Unmarshal([]byte(doc), &p))
	require.Len(t, p.Metrics, 1)

	sym := p.Metrics[0].Symbols[0]
	assert.Equal(t, map[string]int{"off": 0, "chassis": 2}, sym.Enum.Values)
	assert.Equal(t, []string{"battery"}, sym.Enum.Unset)
	assert.Equal(t, "off", sym.Enum.Name(0), "the member the profile gave 0 keeps it")
	assert.Empty(t, sym.Enum.Name(7), "the member with no value maps nothing")

	col := p.Metrics[0].MetricTags[0].Column
	require.NotNil(t, col)
	assert.Equal(t, map[string]int{"fan": 4}, col.Enum.Values)
	assert.Equal(t, []string{"voltage"}, col.Enum.Unset)
	assert.Empty(t, col.Enum.Name(0), "no member carries 0, so 0 names nothing")
}

// An absent enum leaves no members and no report, and an enum written with
// nothing under it is the same thing said differently.
func TestEnum_AbsentAndEmptyDeclarationsAreQuiet(t *testing.T) {
	const doc = `
metrics:
  - MIB: TEST-MIB
    symbols:
      - name: plain
        OID: 1.2.3.1.1
      - name: emptyEnum
        OID: 1.2.3.1.2
        enum:
`
	var p Profile
	require.NoError(t, yaml.Unmarshal([]byte(doc), &p))
	require.Len(t, p.Metrics[0].Symbols, 2)
	for _, sym := range p.Metrics[0].Symbols {
		assert.Equal(t, 0, sym.Enum.Len(), sym.Name)
		assert.Empty(t, sym.Enum.Unset, sym.Name)
	}
}

// yaml.v3 resolves a null value before it reaches an Unmarshaler, so the
// guard is reached only by a caller handing over the node itself. It is here
// because an enum written with nothing under it is an empty enum, not a
// profile to skip.
func TestEnum_NullNodeYieldsNoMembers(t *testing.T) {
	var e Enum
	require.NoError(t, e.UnmarshalYAML(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null"}))
	assert.Equal(t, 0, e.Len())
	assert.Empty(t, e.Unset)
}

// A profile whose enum names a value this collector cannot read is still
// invalid, so the loader keeps skipping it rather than silently dropping the
// member.
func TestEnum_NonIntegerValueIsAnError(t *testing.T) {
	const doc = `
metrics:
  - MIB: TEST-MIB
    symbols:
      - name: envState
        OID: 1.2.3.1.1
        enum:
          chassis: two
`
	var p Profile
	assert.Error(t, yaml.Unmarshal([]byte(doc), &p))
}

// The bundled set carries three enum members written with no value. Each one
// would otherwise take 0: two of them label a state the device really reports,
// and the fortinet enum already gives 0 to `none`, so the two collide and the
// name a lookup returns varies with map order.
func TestEnum_BundledMembersWithNoValue(t *testing.T) {
	l, err := LoadProfiles("", silentLogger)
	require.NoError(t, err)
	all, err := l.AllResolved()
	require.NoError(t, err)

	found := make(map[string][]string)
	for _, p := range all {
		add := func(owner string, e Enum) {
			for _, member := range e.Unset {
				found[p.RelPath] = append(found[p.RelPath], owner+"."+member)
			}
		}
		for _, entry := range p.Metrics {
			if entry.Symbol != nil {
				add(entry.Symbol.Name, entry.Symbol.Enum)
			}
			for _, sym := range entry.Symbols {
				add(sym.Name, sym.Enum)
			}
			for i := range entry.MetricTags {
				if col := entry.MetricTags[i].Column; col != nil {
					add(col.Name, col.Enum)
				}
			}
		}
	}
	assert.Equal(t, map[string][]string{
		"cisco/cisco-wlc.yml":             {"bsnAPIfOperStatus.metric_tags"},
		"fortinet/fortinet-appliance.yml": {"fmDeviceEntState.canceled"},
		"vmware/esx.yml":                  {"vmwSubsystemType.battery"},
	}, found)
}
