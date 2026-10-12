package policy_test

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/policy"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
)

const rawTextHost = "192.0.2.10"

// rawTextWalker answers like a device that stores text in a legacy encoding:
// octets are passed through exactly as they arrive. It always serves one
// interface carrying the target's address, so the device has a primary IP.
type rawTextWalker struct {
	sysName, ifAlias string
}

func (rawTextWalker) Connect() error { return nil }
func (rawTextWalker) Close() error   { return nil }

func (w rawTextWalker) Walk(_ context.Context, oid string, _ int) (map[string]snmp.PDU, error) {
	octets := func(suffix, value string) map[string]snmp.PDU {
		return map[string]snmp.PDU{oid + suffix: {Value: []byte(value), Type: gosnmp.OctetString, IdentifierSize: 1}}
	}
	switch oid {
	case "1.3.6.1.2.1.1.5":
		return octets(".0", w.sysName), nil
	case "1.3.6.1.2.1.2.2.1.2":
		return octets(".1", "GigabitEthernet0/0/1"), nil
	case "1.3.6.1.2.1.31.1.1.1.18":
		if w.ifAlias != "" {
			return octets(".1", w.ifAlias), nil
		}
	case "1.3.6.1.2.1.4.20.1.1":
		return map[string]snmp.PDU{oid + "." + rawTextHost: {Value: rawTextHost, Type: gosnmp.IPAddress, IdentifierSize: 4}}, nil
	case "1.3.6.1.2.1.4.20.1.2":
		return map[string]snmp.PDU{oid + "." + rawTextHost: {Value: 1, Type: gosnmp.Integer, IdentifierSize: 4}}, nil
	}
	return map[string]snmp.PDU{}, nil
}

// syncBuffer lets the test read what the runner's goroutines logged.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runRawText runs one target through the runner and returns what reached
// Ingest (nil if nothing did), the run, and the log.
func runRawText(t *testing.T, walker rawTextWalker, policyConfig config.Policy) ([]diode.Entity, *policy.Run, string) {
	t.Helper()
	setupTestMetrics(t)
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	mockClient := new(MockDiodeClient)
	runStore := policy.NewRunStore()

	mappingConfig := config.Mapping{
		Entries: []config.MappingEntry{
			{
				OID: "1.3.6.1.2.1.1", Entity: "device", Field: "_id", IdentifierSize: 1,
				MappingEntries: []config.MappingEntry{
					{OID: "1.3.6.1.2.1.1.5", Entity: "device", Field: "name"},
				},
			},
			{
				OID: "1.3.6.1.2.1.2.2.1", Entity: "interface", Field: "_id", IdentifierSize: 1,
				MappingEntries: []config.MappingEntry{
					{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
					{OID: "1.3.6.1.2.1.31.1.1.1.18", Entity: "interface", Field: "description"},
				},
			},
			{
				OID: "1.3.6.1.2.1.4.20.1", Entity: "ipAddress", Field: "_id", IdentifierSize: 4,
				MappingEntries: []config.MappingEntry{
					{OID: "1.3.6.1.2.1.4.20.1.1", Entity: "ipAddress", Field: "address"},
					{
						OID: "1.3.6.1.2.1.4.20.1.2", Entity: "ipAddress", Field: "assignedObject",
						Relationship: config.Relationship{Type: "interface"},
					},
				},
			},
		},
	}
	factory := func(string, uint16, int, time.Duration, *config.Authentication, *slog.Logger) (snmp.Walker, error) {
		return walker, nil
	}

	runner, err := policy.NewRunner(context.Background(), logger, "test-policy", policyConfig, mockClient, factory, &mappingConfig, nil, nil, runStore)
	require.NoError(t, err)

	ingested := make(chan []diode.Entity, 1)
	mockClient.On("Ingest", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		ingested <- args.Get(1).([]diode.Entity)
	}).Return(&diodepb.IngestResponse{}, nil)

	runner.Start()
	var runs []*policy.Run
	require.Eventually(t, func() bool {
		runs = runStore.GetRunsForPolicy("test-policy")
		return len(runs) == 1 && runs[0].Status != policy.RunStatusRunning
	}, 10*time.Second, 10*time.Millisecond)
	require.NoError(t, runner.Stop())

	select {
	case entities := <-ingested:
		return entities, runs[0], logs.String()
	default:
		return nil, runs[0], logs.String()
	}
}

func targetPolicy(target config.Target) config.Policy {
	return config.Policy{Scope: config.Scope{Targets: []config.Target{target}}}
}

// requireMarshals runs what gRPC runs first on every entity it sends.
func requireMarshals(t *testing.T, entities []diode.Entity) {
	t.Helper()
	for _, e := range entities {
		_, err := proto.Marshal(e.ConvertToProtoEntity())
		require.NoError(t, err)
	}
}

// One badly encoded description must not cost the target its whole batch.
func TestRunnerRepairsInvalidUTF8InFreeText(t *testing.T) {
	entities, run, logs := runRawText(t, rawTextWalker{
		sysName: "sw1",
		ifAlias: "B\xe2timent A", // "Bâtiment A" in Latin-1
	}, targetPolicy(config.Target{Host: rawTextHost}))

	require.NotNil(t, entities, "the target must be ingested")
	assert.Equal(t, policy.RunStatusCompleted, run.Status)
	requireMarshals(t, entities)
	// The interface is sent as the IP's assigned object.
	var description string
	for _, e := range entities {
		if ip, ok := e.(*diode.IPAddress); ok {
			iface, ok := ip.AssignedObject.(*diode.Interface)
			require.True(t, ok)
			require.NotNil(t, iface.Description)
			description = *iface.Description
		}
	}
	assert.Equal(t, "B\uFFFDtiment A", description)
	assert.Contains(t, logs, mapping.InvalidUTF8Warning)
	assert.Contains(t, logs, "entity=Interface field=Description count=1")
}

// A name Diode matches on is refused rather than repaired: two GBK names
// would both repair to "\uFFFD" and land on one NetBox record.
func TestRunnerRefusesInvalidUTF8InMatchedField(t *testing.T) {
	entities, run, logs := runRawText(t, rawTextWalker{
		sysName: "\xb2\xc6\xce\xf1\xcd\xf8", // GBK
		ifAlias: "B\xe2timent A",
	}, targetPolicy(config.Target{Host: rawTextHost}))

	assert.Nil(t, entities, "nothing may reach Ingest")
	assert.Equal(t, policy.RunStatusFailed, run.Status)
	assert.Contains(t, run.Reason, "Device.Name")
	assert.Contains(t, logs, mapping.InvalidUTF8Refusal)
	assert.Contains(t, logs, "entity=Device field=Name")
	assert.NotContains(t, logs, mapping.InvalidUTF8Warning, "nothing was repaired for ingest, so nothing may claim it was")
}

// With emit_device_name off the sysName never reaches the wire, so it must
// not refuse the target, even though copies made during mapping held it.
func TestRunnerIgnoresInvalidUTF8ThatIsNotSent(t *testing.T) {
	netboxID := 42
	off := false
	policyConfig := targetPolicy(config.Target{Host: rawTextHost, NetboxID: &netboxID})
	policyConfig.Config.Options.EmitDeviceName = &off

	entities, run, _ := runRawText(t, rawTextWalker{sysName: "\xb2\xc6\xce\xf1\xcd\xf8"}, policyConfig)

	require.NotNil(t, entities, "the target must be ingested")
	assert.Equal(t, policy.RunStatusCompleted, run.Status, run.Reason)
	requireMarshals(t, entities)
}
