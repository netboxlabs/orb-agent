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

// One runner is one policy, and its targets are scheduled concurrently, so
// without the gate every target repeats the same config warning every cycle.
func TestWarnUnscopedVLANsLogsOncePerRunner(t *testing.T) {
	var buf bytes.Buffer
	r := &Runner{logger: slog.New(slog.NewTextHandler(&buf, nil))}

	for range 3 {
		r.warnUnscopedVLANs(unscopedEntities(), "p1", "h1")
	}

	require.Equal(t, 1, strings.Count(buf.String(), "level=WARN"),
		"every target of a policy would otherwise repeat it every cycle")
	require.Contains(t, buf.String(), "vlans=1")
}

func TestWarnUnscopedVLANsStaysSilentWithNothingToReport(t *testing.T) {
	var buf bytes.Buffer
	r := &Runner{logger: slog.New(slog.NewTextHandler(&buf, nil))}

	r.warnUnscopedVLANs(nil, "p1", "h1")
	require.Empty(t, buf.String(), "a target with nothing to report must not burn the Once")

	r.warnUnscopedVLANs(unscopedEntities(), "p1", "h1")
	require.Contains(t, buf.String(), "level=WARN")
	require.Contains(t, buf.String(), "set BOTH defaults.site and defaults.vlan.group")
}
