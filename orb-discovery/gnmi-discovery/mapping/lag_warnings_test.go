package mapping

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
)

func countLines(out, msg, member, aggregate string) int {
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, msg) && strings.Contains(l, "member="+member+" ") && strings.Contains(l, "aggregate="+aggregate) {
			n++
		}
	}
	return n
}

const (
	notDiscovered = "lag: aggregate interface not discovered"
	notTypedLag   = "lag: aggregate interface is not typed lag"
)

// Each skipped membership is logged once per LagWarnings, keyed by member,
// aggregate and reason: a single flag would hide every pair but the first.
func TestLagWarningsLogEachMembershipOnce(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	snap := lagSnap(map[string]any{
		"/interfaces/interface[name=Port-Channel1]/state/type":              nil,
		"/interfaces/interface[name=Ethernet2]/state/type":                  "iana-if-type:ethernetCsmacd",
		"/interfaces/interface[name=Ethernet2]/ethernet/state/aggregate-id": "Port-Channel2",
	})
	var warned LagWarnings
	for range 3 {
		TranslateWithOptions(base, snap, nil, "", nil, logger, &warned)
	}
	out := buf.String()
	require.Equal(t, 1, countLines(out, notDiscovered, "Ethernet1", "Port-Channel1"))
	require.Equal(t, 1, countLines(out, notDiscovered, "Ethernet2", "Port-Channel2"),
		"a different pair is still logged")

	// The same pair skipped for another reason is a new warning.
	snap["/interfaces/interface[name=Port-Channel1]/state/type"] = "iana-if-type:ieee8023adLag"
	virtual := &config.Defaults{InterfacePatterns: []config.InterfacePattern{{Match: "^Port-Channel1$", Type: "virtual"}}}
	TranslateWithOptions(base, snap, virtual, "", nil, logger, &warned)
	TranslateWithOptions(base, snap, virtual, "", nil, logger, &warned)
	require.Equal(t, 1, countLines(buf.String(), notTypedLag, "Ethernet1", "Port-Channel1"))
}

// Without a LagWarnings every translation logs, as Translate always has.
func TestLagWarningsNilLogsEveryTime(t *testing.T) {
	store, err := LoadProfiles("")
	require.NoError(t, err)
	base, _ := store.Get("_base")
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	snap := lagSnap(map[string]any{"/interfaces/interface[name=Port-Channel1]/state/type": nil})
	for range 2 {
		TranslateWithOptions(base, snap, &config.Defaults{}, "", nil, logger, nil)
	}
	require.Equal(t, 2, countLines(buf.String(), notDiscovered, "Ethernet1", "Port-Channel1"))
}
