package policy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
)

// logRecords parses the JSON log records in out, failing the test on a key a
// record carries twice, which a reader of standalone JSON cannot decode.
func logRecords(t *testing.T, out string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(line))
		_, err := dec.Token()
		require.NoError(t, err, line)
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			require.NoError(t, err, line)
			assert.False(t, seen[key.(string)], "key %q twice in %s", key, line)
			seen[key.(string)] = true
			var value json.RawMessage
			require.NoError(t, dec.Decode(&value), line)
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		records = append(records, record)
	}
	return records
}

func jsonLogger(w *lockedBuffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// failingWalker fails every walk, as a target that stops answering does.
type failingWalker struct{}

func (failingWalker) Connect() error { return nil }
func (failingWalker) Close() error   { return nil }
func (failingWalker) Walk(context.Context, string, int) (map[string]snmp.PDU, error) {
	return nil, errors.New("request timeout (after 0 retries)")
}

// Every line from INFO up that a crawl logs names its policy and host, once
// each, warnings and errors included.
func TestCrawlLogLinesNamePolicyAndHost(t *testing.T) {
	// Each entity is sent in a request of its own.
	withChunkLimit(t, 1)
	logs := &lockedBuffer{}
	factory := func(host string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		if host == "192.0.2.2" {
			return failingWalker{}, nil
		}
		rows := agentRows(host)
		// A type the walk does not handle, and a value the mapper cannot
		// read, are each logged and skipped.
		rows[".1.3.6.1.2.1.2.2.1.4.1"] = snmp.PDU{Type: gosnmp.Opaque, Value: []byte{0x9f, 0x78}}
		rows[".1.3.6.1.2.1.2.2.1.5.1"] = snmp.PDU{Type: gosnmp.OctetString, Value: "fast"}
		// A subinterface, whose parent the mapper resolves and reports.
		rows[".1.3.6.1.2.1.2.2.1.2.2"] = snmp.PDU{Type: gosnmp.OctetString, Value: "eth0.100"}
		rows[".1.3.6.1.2.1.2.2.1.3.2"] = snmp.PDU{Type: gosnmp.Integer, Value: 135}
		return &rowWalker{rows: rows}, nil
	}
	r, _ := newPolicyRunner(t, `
policies:
  p1:
    config:
      timeout: 10
      snmp_timeout: 3
      snmp_probe_timeout: 1
      options:
        emit_device_name: false
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: example-community
      targets:
        - host: 192.0.2.1
        - host: 192.0.2.2
`, factory, &recordingClient{}, jsonLogger(logs))
	logs.Reset()

	r.runWithMetadata(config.Target{Host: "192.0.2.1", Port: 161}, "")
	r.runWithMetadata(config.Target{Host: "192.0.2.2", Port: 161}, "")

	warned := map[string]bool{}
	for _, record := range logRecords(t, logs.String()) {
		if record["level"] == "DEBUG" {
			continue
		}
		warned[record["msg"].(string)] = true
		assert.Equal(t, "p1", record["policy"], "%v", record)
		assert.Contains(t, []any{"192.0.2.1", "192.0.2.2"}, record["host"], "%v", record)
	}
	// The lines this proves, so a change that stops logging them is noticed.
	for _, msg := range []string{
		"sending the target in several requests to stay under Diode's message size limit",
		"error converting speed to int",
		"resolved subinterface parents",
		"error mapping PDU",
		"emit_device_name disabled but device has no alternative matcher (netbox_id/source_match, asset_tag); keeping name to avoid an unmatchable device",
		"error walking object ID",
		"error crawling host",
		"error querying target",
	} {
		assert.True(t, warned[msg], "expected a line %q", msg)
	}
}

// Every line a scan logs names its policy, and from INFO up the range it
// scans, once each.
func TestScanLogLinesNamePolicyAndTarget(t *testing.T) {
	logs := &lockedBuffer{}
	factory := func(string, uint16, int, time.Duration, *config.Authentication, *slog.Logger) (snmp.Walker, error) {
		return failingWalker{}, nil
	}
	r, _ := newPolicyRunner(t, `
policies:
  p1:
    config:
      timeout: 10
      snmp_timeout: 3
      snmp_probe_timeout: 1
    scope:
      authentication:
        protocol_version: SNMPv2c
        community: example-community
      targets:
        - host: 192.0.2.0/30
`, factory, &recordingClient{}, jsonLogger(logs))
	logs.Reset()

	r.runScanWithOriginal([]config.Target{{Host: "192.0.2.1", Port: 161}, {Host: "192.0.2.2", Port: 161}}, "192.0.2.0/30")

	records := logRecords(t, logs.String())
	require.NotEmpty(t, records)
	infos := 0
	for _, record := range records {
		assert.Equal(t, "p1", record["policy"], "%v", record)
		if record["level"] != "DEBUG" {
			infos++
			assert.Equal(t, "192.0.2.0/30", record["target"], "%v", record)
		}
	}
	assert.Equal(t, 2, infos, "the scan's start and its no-answer warning")
}
