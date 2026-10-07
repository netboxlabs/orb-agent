package policy

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/require"
)

func unscopedEntities() []diode.Entity {
	vid := int64(101)
	name := "Voice"
	return []diode.Entity{&diode.VLAN{Vid: &vid, Name: &name}}
}

// This backend flushes on a debouncer and a GET interval, so without the gate a
// misconfigured policy repeats the warning for as long as it stays connected.
func TestUnscopedVLANWarnerLogsOncePerConnection(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	var w unscopedVLANWarner
	for range 3 {
		w.warn(logger, unscopedEntities(), "p1", "h1")
	}

	require.Equal(t, 1, strings.Count(buf.String(), "level=WARN"),
		"a flush-driven backend must not repeat a config warning on every update")
	require.Contains(t, buf.String(), "vlans=1")
}

func TestUnscopedVLANWarnerStaysSilentWithNothingToReport(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	var w unscopedVLANWarner
	w.warn(logger, nil, "p1", "h1")
	require.Empty(t, buf.String())

	// The empty flush must not have consumed the one warning.
	w.warn(logger, unscopedEntities(), "p1", "h1")
	require.Contains(t, buf.String(), "level=WARN")
	require.Contains(t, buf.String(), "set BOTH defaults.site and defaults.vlan.group")
}
