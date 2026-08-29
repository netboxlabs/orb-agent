package profiles

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
