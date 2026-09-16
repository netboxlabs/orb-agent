package backend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The hop that was broken: Kind was set on PolicyStatusRun and convertToRunData
// mapped eight fields, not including it.
func TestConvertToRunDataCarriesKind(t *testing.T) {
	runs := convertToRunData([]PolicyStatusRun{
		{ID: "s1", Status: "completed", Kind: "sweep", Targets: []string{"10.0.0.0/24"}},
		{ID: "f1", Status: "completed", Kind: "flush", Targets: []string{"10.0.0.1:9339"}},
		{ID: "x1", Status: "completed"},
	})

	require.Len(t, runs, 3)
	require.Equal(t, "sweep", runs[0].Kind)
	require.Equal(t, "flush", runs[1].Kind)
	require.Empty(t, runs[2].Kind)
}

// The legacy metadata path still works: network-discovery v1.x encodes targets as
// a JSON array string in metadata, and adding Kind must not disturb that.
func TestMetadataTargetsFallbackStillWorks(t *testing.T) {
	runs := convertToRunData([]PolicyStatusRun{
		{ID: "n1", Status: "completed", Metadata: map[string]string{"targets": `["10.0.0.1"]`}},
	})
	require.Equal(t, []string{"10.0.0.1"}, runs[0].Targets)
}
