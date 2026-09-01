package policy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
)

// slowWalker blocks in Connect until done is closed, simulating a long-running SNMP operation.
type slowWalker struct {
	done <-chan struct{}
}

func (s *slowWalker) Connect() error {
	<-s.done
	return errors.New("unblocked")
}

func (s *slowWalker) Walk(_ string, _ int) (map[string]snmp.PDU, error) {
	return nil, nil
}

func (s *slowWalker) Close() error { return nil }

type testWalker struct {
	connectErr     error
	walkErr        error
	connectCalled  bool
	walkCalled     bool
	closeCalled    bool
	walkOID        string
	walkIdentifier int
}

func (t *testWalker) Connect() error {
	t.connectCalled = true
	return t.connectErr
}

func (t *testWalker) Walk(objectID string, identifierSize int) (map[string]snmp.PDU, error) {
	t.walkCalled = true
	t.walkOID = objectID
	t.walkIdentifier = identifierSize
	return nil, t.walkErr
}

func (t *testWalker) Close() error {
	t.closeCalled = true
	return nil
}

func TestExpandTargetRangesGroupsTargets(t *testing.T) {
	runner := &Runner{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	configuredTargets := []config.Target{
		{Host: "192.168.1.1-2", Port: 161},
		{Host: "example.com", Port: 162},
	}

	expanded := runner.expandTargetRanges(configuredTargets)
	require.Len(t, expanded, 2)

	// Check first group (192.168.1.1-2 expands to 2 targets)
	assert.Equal(t, "192.168.1.1-2", expanded[0].originalTarget)
	require.Len(t, expanded[0].targets, 2)
	assert.Equal(t, "192.168.1.1", expanded[0].targets[0].Host)
	assert.Equal(t, uint16(161), expanded[0].targets[0].Port)
	assert.Equal(t, "192.168.1.2", expanded[0].targets[1].Host)
	assert.Equal(t, uint16(161), expanded[0].targets[1].Port)

	// Check second group (example.com expands to 1 target)
	assert.Equal(t, "example.com", expanded[1].originalTarget)
	require.Len(t, expanded[1].targets, 1)
	assert.Equal(t, "example.com", expanded[1].targets[0].Host)
	assert.Equal(t, uint16(162), expanded[1].targets[0].Port)
}

func TestExpandTargetRanges_NetboxID_propagation(t *testing.T) {
	netboxID := 42
	runner := &Runner{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	tests := []struct {
		name         string
		host         string
		wantNetboxID bool
	}{
		{"plain IP carries netbox_id", "192.168.1.1", true},
		{"CIDR /32 clears netbox_id", "192.168.1.1/32", false},
		{"single-IP range clears netbox_id", "192.168.1.1-192.168.1.1", false},
		{"multi-IP range clears netbox_id", "192.168.1.1-192.168.1.2", false},
		{"subnet clears netbox_id", "192.168.1.0/30", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			targets := []config.Target{{Host: tc.host, Port: 161, NetboxID: &netboxID}}
			expanded := runner.expandTargetRanges(targets)
			require.NotEmpty(t, expanded)
			for _, target := range expanded[0].targets {
				if tc.wantNetboxID {
					require.NotNil(t, target.NetboxID)
					assert.Equal(t, netboxID, *target.NetboxID)
				} else {
					assert.Nil(t, target.NetboxID)
				}
			}
		})
	}
}

func TestProbeTargetCanceledContextSkipsClientFactory(t *testing.T) {
	var factoryCalls int32
	runner := &Runner{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ClientFactory: func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
			atomic.AddInt32(&factoryCalls, 1)
			return &testWalker{}, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ok := runner.probeTarget(ctx, config.Target{Host: "127.0.0.1", Port: 161})
	assert.False(t, ok)
	assert.Equal(t, int32(0), atomic.LoadInt32(&factoryCalls))
}

func TestProbeTargetSuccess(t *testing.T) {
	walker := &testWalker{}
	var gotHost string
	var gotPort uint16
	var gotTimeout time.Duration

	runner := &Runner{
		logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		scope:            config.Scope{Authentication: config.Authentication{Community: "public"}},
		snmpProbeTimeout: 2 * time.Second,
		ClientFactory: func(host string, port uint16, _ int, timeout time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
			gotHost = host
			gotPort = port
			gotTimeout = timeout
			return walker, nil
		},
	}

	ok := runner.probeTarget(context.Background(), config.Target{Host: "127.0.0.1", Port: 161})
	require.True(t, ok)
	assert.True(t, walker.connectCalled)
	assert.True(t, walker.walkCalled)
	assert.True(t, walker.closeCalled)
	assert.Equal(t, defaultSNMPProbeOID, walker.walkOID)
	assert.Equal(t, 0, walker.walkIdentifier)
	assert.Equal(t, "127.0.0.1", gotHost)
	assert.Equal(t, uint16(161), gotPort)
	assert.Equal(t, 2*time.Second, gotTimeout)
}

func TestProbeTargetFailurePaths(t *testing.T) {
	tests := []struct {
		name       string
		factoryErr error
		connectErr error
		walkErr    error
		expectWalk bool
	}{
		{
			name:       "factory error",
			factoryErr: errors.New("factory error"),
		},
		{
			name:       "connect error",
			connectErr: errors.New("connect error"),
		},
		{
			name:       "walk error",
			walkErr:    errors.New("walk error"),
			expectWalk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			walker := &testWalker{
				connectErr: tt.connectErr,
				walkErr:    tt.walkErr,
			}

			runner := &Runner{
				logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
				ClientFactory: func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
					if tt.factoryErr != nil {
						return nil, tt.factoryErr
					}
					return walker, nil
				},
			}

			ok := runner.probeTarget(context.Background(), config.Target{Host: "127.0.0.1", Port: 161})
			assert.False(t, ok)
			if tt.factoryErr == nil {
				assert.True(t, walker.connectCalled)
				assert.Equal(t, tt.expectWalk, walker.walkCalled)
				assert.True(t, walker.closeCalled)
			}
		})
	}
}

func TestRunScanSchedulesResponsiveTargets(t *testing.T) {
	scheduler, err := gocron.NewScheduler()
	require.NoError(t, err)

	runStore := NewRunStore()

	runner := &Runner{
		scheduler:      scheduler,
		ctx:            context.WithValue(context.Background(), policyKey, "test-policy"),
		timeout:        5 * time.Second,
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		runStore:       runStore,
		activeHostJobs: make(map[string]uuid.UUID),
	}

	runner.ClientFactory = func(host string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		if host == "good-1" || host == "good-2" {
			return &testWalker{}, nil
		}
		return &testWalker{walkErr: errors.New("no response")}, nil
	}

	runner.runScanWithOriginal([]config.Target{
		{Host: "good-1", Port: 161},
		{Host: "bad-1", Port: 161},
		{Host: "good-2", Port: 161},
	}, "192.168.1.0/24")

	assert.Len(t, runner.scheduler.Jobs(), 2)

	// Verify scan run was created
	runs := runStore.GetRunsForTarget("test-policy", "192.168.1.0/24", 161)
	require.Len(t, runs, 1, "Scan run should be created")
	assert.Equal(t, `["192.168.1.0/24"]`, runs[0].Metadata["targets"])
	assert.Equal(t, RunStatusCompleted, runs[0].Status)
}

func queryTargetRunner(clientFactory snmp.ClientFactory, mappingEntries []config.MappingEntry) *Runner {
	return &Runner{
		ctx:           context.WithValue(context.Background(), policyKey, "test-policy"),
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		mappingConfig: &config.Mapping{Entries: mappingEntries},
		scope:         config.Scope{Authentication: config.Authentication{}},
		config:        config.PolicyConfig{Retries: 0, Defaults: config.Defaults{}},
		snmpTimeout:   time.Second,
		ClientFactory: clientFactory,
	}
}

func TestQueryTargetContextAlreadyCanceled(t *testing.T) {
	runner := queryTargetRunner(snmp.NewFakeSNMPWalker, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	entities, primaryHits, err := runner.queryTarget(ctx, config.Target{Host: "127.0.0.1", Port: 161})
	assert.Nil(t, entities)
	assert.Nil(t, primaryHits)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestQueryTargetContextTimeout(t *testing.T) {
	done := make(chan struct{})
	defer close(done)

	runner := queryTargetRunner(func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return &slowWalker{done: done}, nil
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	entities, primaryHits, err := runner.queryTarget(ctx, config.Target{Host: "127.0.0.1", Port: 161})
	assert.Nil(t, entities)
	assert.Nil(t, primaryHits)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestQueryTargetWalkError(t *testing.T) {
	walkErr := errors.New("snmp walk failed")
	entries := []config.MappingEntry{
		{
			OID:    "iso.3.6.1.2.1.2.2.1",
			Entity: "interface",
			Field:  "_id",
			MappingEntries: []config.MappingEntry{
				{OID: "iso.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
			},
		},
	}
	runner := queryTargetRunner(func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return &testWalker{walkErr: walkErr}, nil
	}, entries)

	entities, primaryHits, err := runner.queryTarget(context.Background(), config.Target{Host: "127.0.0.1", Port: 161})
	assert.Nil(t, entities)
	assert.Nil(t, primaryHits)
	assert.ErrorIs(t, err, walkErr)
}

func TestQueryTargetSuccess(t *testing.T) {
	entries := []config.MappingEntry{
		{
			OID:    "iso.3.6.1.2.1.2.2.1",
			Entity: "interface",
			Field:  "_id",
			MappingEntries: []config.MappingEntry{
				{OID: "iso.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
			},
		},
	}
	runner := queryTargetRunner(snmp.NewFakeSNMPWalker, entries)

	entities, _, err := runner.queryTarget(context.Background(), config.Target{Host: "127.0.0.1", Port: 161})
	require.NoError(t, err)
	assert.NotEmpty(t, entities)
}

// staticWalker emits a fixed PDU set per walked OID. Used by the OBS-1896
// integration test so we can seed properly-indexed interface + ipAddress
// PDUs that the mapping pipeline will group correctly.
type staticWalker struct {
	pdus map[string]map[string]snmp.PDU
}

func (w *staticWalker) Connect() error { return nil }
func (w *staticWalker) Close() error   { return nil }
func (w *staticWalker) Walk(oid string, _ int) (map[string]snmp.PDU, error) {
	if p, ok := w.pdus[oid]; ok {
		return p, nil
	}
	return map[string]snmp.PDU{}, nil
}

// TestQueryTargetAssignsPrimaryIPFromTarget is the OBS-1896 end-to-end check:
// when the SNMP target host equals a discovered interface IP, the emitted
// Device (reachable via any Interface entity) must carry that IPAddress as
// its PrimaryIp4.
func TestQueryTargetAssignsPrimaryIPFromTarget(t *testing.T) {
	// Walker emits the same OIDs as production mapping.yaml: one interface
	// (ifIndex=1, name=Gi0), one IPv4 address 10.0.0.1 assigned to that
	// interface via ipAdEntIfIndex=1.
	walker := &staticWalker{
		pdus: map[string]map[string]snmp.PDU{
			"1.3.6.1.2.1.2.2.1.2": {
				"1.3.6.1.2.1.2.2.1.2.1": {
					Value: "Gi0", Type: gosnmp.OctetString, IdentifierSize: 1,
				},
			},
			"1.3.6.1.2.1.4.20.1.1": {
				"1.3.6.1.2.1.4.20.1.1.10.0.0.1": {
					Value: "10.0.0.1", Type: gosnmp.IPAddress, IdentifierSize: 4,
				},
			},
			"1.3.6.1.2.1.4.20.1.2": {
				"1.3.6.1.2.1.4.20.1.2.10.0.0.1": {
					Value: 1, Type: gosnmp.Integer, IdentifierSize: 4,
				},
			},
		},
	}
	factory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return walker, nil
	}

	entries := []config.MappingEntry{
		{
			OID:            "1.3.6.1.2.1.2.2.1",
			Entity:         "interface",
			Field:          "_id",
			IdentifierSize: 1,
			MappingEntries: []config.MappingEntry{
				{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
			},
		},
		{
			OID:            "1.3.6.1.2.1.4.20.1",
			Entity:         "ipAddress",
			Field:          "_id",
			IdentifierSize: 4,
			MappingEntries: []config.MappingEntry{
				{OID: "1.3.6.1.2.1.4.20.1.1", Entity: "ipAddress", Field: "address"},
				{
					OID:          "1.3.6.1.2.1.4.20.1.2",
					Entity:       "ipAddress",
					Field:        "assignedObject",
					Relationship: config.Relationship{Type: "interface"},
				},
			},
		},
	}

	runner := queryTargetRunner(factory, entries)
	entities, primaryHits, err := runner.queryTarget(context.Background(), config.Target{Host: "10.0.0.1", Port: 161})
	require.NoError(t, err)
	require.NotEmpty(t, entities)

	// Locate the emitted IPAddress and confirm it is wired to the Gi0
	// interface — this is the "verified interface IP" guarantee the
	// primary-IP assignment depends on.
	var primaryIP *diode.IPAddress
	for _, e := range entities {
		if ip, ok := e.(*diode.IPAddress); ok && ip.Address != nil && *ip.Address == "10.0.0.1/32" {
			primaryIP = ip
			break
		}
	}
	require.NotNil(t, primaryIP, "expected IPAddress 10.0.0.1/32 in emitted entities")
	iface, ok := primaryIP.AssignedObject.(*diode.Interface)
	require.True(t, ok, "IPAddress must be assigned to an Interface")
	require.NotNil(t, iface.Name)
	assert.Equal(t, "Gi0", *iface.Name)

	// The Device is reached via the assigned interface's Device pointer;
	// device.PrimaryIp4 is a detached snapshot of the matched IPAddress
	// (see detachForPrimaryIP) — compare by content, not by pointer.
	require.NotNil(t, iface.Device, "assigned interface must carry a device reference")
	require.NotNil(t, iface.Device.PrimaryIp4, "device.PrimaryIp4 must be set from target host")
	assert.Equal(t, *primaryIP.Address, *iface.Device.PrimaryIp4.Address)
	snapshotIface, ok := iface.Device.PrimaryIp4.AssignedObject.(*diode.Interface)
	require.True(t, ok, "PrimaryIp4 snapshot must preserve the interface assignment")
	require.NotNil(t, snapshotIface.Name)
	assert.Equal(t, "Gi0", *snapshotIface.Name)
	require.NotNil(t, snapshotIface.Device,
		"PrimaryIp4 snapshot's interface must carry a Device (Diode validation)")
	assert.Nil(t, snapshotIface.Device.PrimaryIp4,
		"nested Device must have PrimaryIp4 cleared to break the cycle")

	// The cycle-closer is the IPAddress entity for the primary IP itself.
	// queryTarget reports it via primaryHits keyed by the live entity.
	require.NotNil(t, primaryHits, "queryTarget must report the primary-IP cycle-closer hits")
	assert.True(t, primaryHits[primaryIP],
		"the primary IPAddress entity must be flagged as a cycle-closer")

	// Post-prune: the cycle-closer IP entity's nested device keeps a
	// matcher-only primary_ip4 (it can validly close the circular
	// reference within its own change set), while a non-primary nested
	// device stub is stripped. Mirror the production sequence.
	annotateEntitiesWithRunID(entities, "run-primary")
	mapping.PruneNestedRefs(entities, mapping.CurrentDeviceFrom(entities), primaryHits)

	closerIface, ok := primaryIP.AssignedObject.(*diode.Interface)
	require.True(t, ok, "cycle-closer IP must still carry an interface stub after prune")
	require.NotNil(t, closerIface.Type, "cycle-closer interface keeps its Type after prune")
	require.NotNil(t, closerIface.Device, "cycle-closer interface keeps a device stub")
	require.NotNil(t, closerIface.Device.PrimaryIp4,
		"cycle-closer nested device keeps a matcher-only primary_ip4")
	assert.Equal(t, "10.0.0.1/32", *closerIface.Device.PrimaryIp4.Address)
	assert.Nil(t, closerIface.Device.PrimaryIp4.AssignedObject,
		"cycle-closer's primary_ip4 is matcher-only (no AssignedObject)")
}

// TestQueryTargetAssignsPrimaryIPFromTarget_ModernIpAddressTable is the
// runner-level integration check for OBS-2798: a device that returns
// only RFC 4293 ipAddressTable rows (no legacy ipAddrTable) must
// still emit IP entities and have device.PrimaryIp4 / PrimaryIp6
// populated when the SNMP target matches a discovered address. This
// test exercises Config.ObjectIDs() on the inet_address-indexed
// entries and the SNMP walking + grouping path end-to-end through
// the runner, which the mapper-only unit tests don't cover.
func TestQueryTargetAssignsPrimaryIPFromTarget_ModernIpAddressTable(t *testing.T) {
	// Walker emits ipAddressTable PDUs only — zero ipAddrTable rows.
	// Both an IPv4 and an IPv6 address are bound to ifIndex=1.
	// IPv4: 10.0.0.1/24
	//   ipAddressIfIndex.1.4.10.0.0.1 = 1
	//   ipAddressType.1.4.10.0.0.1 = 1 (unicast)
	//   ipAddressPrefix.1.4.10.0.0.1 = .1.3.6.1.2.1.4.32.1.5.1.1.4.10.0.0.0.24
	//   ipAddressStatus.1.4.10.0.0.1 = 1 (preferred)
	//   ipAddressRowStatus.1.4.10.0.0.1 = 1 (active)
	// IPv6: 2001:db8::1/64
	//   ipAddressIfIndex.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1 = 1
	//   ipAddressType.* = 1, ipAddressStatus.* = 1, ipAddressRowStatus.* = 1
	//   ipAddressPrefix.* = .1.3.6.1.2.1.4.32.1.5.1.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.0.64
	v6Suffix := "2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1"
	walker := &staticWalker{
		pdus: map[string]map[string]snmp.PDU{
			"1.3.6.1.2.1.2.2.1.2": {
				"1.3.6.1.2.1.2.2.1.2.1": {
					Value: "Gi0", Type: gosnmp.OctetString, IdentifierSize: 1,
				},
			},
			"1.3.6.1.2.1.4.34.1.3": {
				"1.3.6.1.2.1.4.34.1.3.1.4.10.0.0.1": {
					Value: 1, Type: gosnmp.Integer, IdentifierSize: 0,
				},
				"1.3.6.1.2.1.4.34.1.3." + v6Suffix: {
					Value: 1, Type: gosnmp.Integer, IdentifierSize: 0,
				},
			},
			"1.3.6.1.2.1.4.34.1.4": {
				"1.3.6.1.2.1.4.34.1.4.1.4.10.0.0.1": {
					Value: 1, Type: gosnmp.Integer, IdentifierSize: 0,
				},
				"1.3.6.1.2.1.4.34.1.4." + v6Suffix: {
					Value: 1, Type: gosnmp.Integer, IdentifierSize: 0,
				},
			},
			"1.3.6.1.2.1.4.34.1.5": {
				"1.3.6.1.2.1.4.34.1.5.1.4.10.0.0.1": {
					Value: ".1.3.6.1.2.1.4.32.1.5.1.1.4.10.0.0.0.24",
					Type:  gosnmp.ObjectIdentifier, IdentifierSize: 0,
				},
				"1.3.6.1.2.1.4.34.1.5." + v6Suffix: {
					Value: ".1.3.6.1.2.1.4.32.1.5.1.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.0.64",
					Type:  gosnmp.ObjectIdentifier, IdentifierSize: 0,
				},
			},
			"1.3.6.1.2.1.4.34.1.7": {
				"1.3.6.1.2.1.4.34.1.7.1.4.10.0.0.1": {
					Value: 1, Type: gosnmp.Integer, IdentifierSize: 0,
				},
				"1.3.6.1.2.1.4.34.1.7." + v6Suffix: {
					Value: 1, Type: gosnmp.Integer, IdentifierSize: 0,
				},
			},
			"1.3.6.1.2.1.4.34.1.10": {
				"1.3.6.1.2.1.4.34.1.10.1.4.10.0.0.1": {
					Value: 1, Type: gosnmp.Integer, IdentifierSize: 0,
				},
				"1.3.6.1.2.1.4.34.1.10." + v6Suffix: {
					Value: 1, Type: gosnmp.Integer, IdentifierSize: 0,
				},
			},
		},
	}
	factory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return walker, nil
	}

	entries := []config.MappingEntry{
		{
			OID: "1.3.6.1.2.1.2.2.1", Entity: "interface", Field: "_id", IdentifierSize: 1,
			MappingEntries: []config.MappingEntry{
				{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
			},
		},
		{
			OID: "1.3.6.1.2.1.4.34.1", Entity: "ipAddress", Field: "_id",
			IndexKind: "inet_address",
			MappingEntries: []config.MappingEntry{
				{
					OID: "1.3.6.1.2.1.4.34.1.3", Entity: "ipAddress", Field: "assignedObject",
					Relationship: config.Relationship{Type: "interface"},
				},
				{OID: "1.3.6.1.2.1.4.34.1.4", Entity: "ipAddress", Field: "addressType"},
				{OID: "1.3.6.1.2.1.4.34.1.5", Entity: "ipAddress", Field: "addressPrefix"},
				{OID: "1.3.6.1.2.1.4.34.1.7", Entity: "ipAddress", Field: "addressStatus"},
				{OID: "1.3.6.1.2.1.4.34.1.10", Entity: "ipAddress", Field: "addressRowStatus"},
			},
		},
	}

	// Run twice — once for IPv4 target, once for IPv6 — using a fresh
	// runner each time so the mapping registry doesn't carry state
	// between scans.
	t.Run("IPv4 target -> PrimaryIp4", func(t *testing.T) {
		runner := queryTargetRunner(factory, entries)
		entities, _, err := runner.queryTarget(context.Background(), config.Target{Host: "10.0.0.1", Port: 161})
		require.NoError(t, err)
		require.NotEmpty(t, entities)

		var primaryIP *diode.IPAddress
		for _, e := range entities {
			if ip, ok := e.(*diode.IPAddress); ok && ip.Address != nil && *ip.Address == "10.0.0.1/24" {
				primaryIP = ip
				break
			}
		}
		require.NotNil(t, primaryIP, "expected IPAddress 10.0.0.1/24 in emitted entities")
		iface, ok := primaryIP.AssignedObject.(*diode.Interface)
		require.True(t, ok)
		require.NotNil(t, iface.Device)
		require.NotNil(t, iface.Device.PrimaryIp4, "PrimaryIp4 must be set from ipAddressTable target")
		assert.Equal(t, "10.0.0.1/24", *iface.Device.PrimaryIp4.Address)
	})

	t.Run("IPv6 target -> PrimaryIp6", func(t *testing.T) {
		runner := queryTargetRunner(factory, entries)
		entities, _, err := runner.queryTarget(context.Background(), config.Target{Host: "2001:db8::1", Port: 161})
		require.NoError(t, err)
		require.NotEmpty(t, entities)

		var primaryIP *diode.IPAddress
		for _, e := range entities {
			if ip, ok := e.(*diode.IPAddress); ok && ip.Address != nil && *ip.Address == "2001:db8::1/64" {
				primaryIP = ip
				break
			}
		}
		require.NotNil(t, primaryIP, "expected IPAddress 2001:db8::1/64 in emitted entities")
		iface, ok := primaryIP.AssignedObject.(*diode.Interface)
		require.True(t, ok)
		require.NotNil(t, iface.Device)
		require.NotNil(t, iface.Device.PrimaryIp6, "PrimaryIp6 must be set from ipAddressTable target")
		assert.Equal(t, "2001:db8::1/64", *iface.Device.PrimaryIp6.Address)
	})
}

func TestRunner_HasActiveHostJobsField(t *testing.T) {
	cron := "0 * * * *"
	pol := config.Policy{
		Config: config.PolicyConfig{Schedule: &cron, Timeout: 120},
		Scope:  config.Scope{Targets: []config.Target{{Host: "192.168.1.1", Port: 161}}},
	}
	runner, err := NewRunner(context.Background(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		"test-policy", pol, nil, snmp.NewFakeSNMPWalker, &config.Mapping{}, nil, nil, NewRunStore())
	require.NoError(t, err)
	defer func() { _ = runner.Stop() }()
	assert.NotNil(t, runner.activeHostJobs, "NewRunner must initialize activeHostJobs")
}

func TestRunScanWithOriginal_SkipsDuplicateCrawlJob(t *testing.T) {
	scheduler, err := gocron.NewScheduler()
	require.NoError(t, err)

	// Schedule a pre-existing crawl job with a known ID
	existingJobID := uuid.New()
	_, err = scheduler.NewJob(
		gocron.CronJob("0 * * * *", false),
		gocron.NewTask(func() {}),
		gocron.WithIdentifier(existingJobID),
	)
	require.NoError(t, err)

	runStore := NewRunStore()
	runner := &Runner{
		scheduler: scheduler,
		ctx:       context.WithValue(context.Background(), policyKey, "test-policy"),
		timeout:   5 * time.Second,
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		runStore:  runStore,
		activeHostJobs: map[string]uuid.UUID{
			"192.168.1.0/24::192.168.1.1:161": existingJobID,
		},
	}
	runner.ClientFactory = func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return &testWalker{}, nil
	}

	runner.runScanWithOriginal([]config.Target{
		{Host: "192.168.1.1", Port: 161},
	}, "192.168.1.0/24")

	// Still only 1 job — the pre-existing one; no duplicate was added
	assert.Len(t, scheduler.Jobs(), 1)
}

func TestRunScanWithOriginal_FailsWhenNoResponsiveHosts(t *testing.T) {
	scheduler, err := gocron.NewScheduler()
	require.NoError(t, err)

	runStore := NewRunStore()
	runner := &Runner{
		scheduler:      scheduler,
		ctx:            context.WithValue(context.Background(), policyKey, "test-policy"),
		timeout:        5 * time.Second,
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		runStore:       runStore,
		activeHostJobs: make(map[string]uuid.UUID),
	}
	// All hosts fail the SNMP probe
	runner.ClientFactory = func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return &testWalker{walkErr: errors.New("no response")}, nil
	}

	runner.runScanWithOriginal([]config.Target{
		{Host: "192.168.1.1", Port: 161},
		{Host: "192.168.1.2", Port: 161},
	}, "192.168.1.0/24")

	runs := runStore.GetRunsForTarget("test-policy", "192.168.1.0/24", 161)
	require.Len(t, runs, 1, "scan run should be created")
	assert.Equal(t, RunStatusFailed, runs[0].Status, "scan run should be FAILED when no hosts respond")
	assert.Contains(t, runs[0].Reason, "no hosts responded to SNMP probe")
	assert.Len(t, scheduler.Jobs(), 0, "no crawl jobs should be scheduled")
}

func TestRunScanWithOriginal_NoDuplicateForRepeatedResponsiveHost(t *testing.T) {
	scheduler, err := gocron.NewScheduler()
	require.NoError(t, err)

	runStore := NewRunStore()
	runner := &Runner{
		scheduler:      scheduler,
		ctx:            context.WithValue(context.Background(), policyKey, "test-policy"),
		timeout:        5 * time.Second,
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		runStore:       runStore,
		activeHostJobs: make(map[string]uuid.UUID),
	}
	runner.ClientFactory = func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return &testWalker{}, nil
	}

	// Same host appears twice in the targets list (simulates misconfigured overlapping range)
	runner.runScanWithOriginal([]config.Target{
		{Host: "192.168.1.1", Port: 161},
		{Host: "192.168.1.1", Port: 161},
	}, "192.168.1.0/24")

	// Only one crawl job should be scheduled despite duplicate in responsive list
	assert.Len(t, scheduler.Jobs(), 1)
}

// TestRunnerAnnotateThenPrune locks in the runner-level contract:
// after annotation + prune, the top-level Device keeps full payload
// and Metadata (source_match, run_id); nested Device/Interface refs
// are matcher-only stubs with no Metadata; IP.AssignedObject is a
// stub Interface; the Device stub's PrimaryIp4 has no AssignedObject.
func TestRunnerAnnotateThenPrune(t *testing.T) {
	walker := &staticWalker{
		pdus: map[string]map[string]snmp.PDU{
			// sysName — triggers DeviceMapper and emits a top-level Device.
			"1.3.6.1.2.1.1.5": {
				"1.3.6.1.2.1.1.5.0": {Value: "router-1", Type: gosnmp.OctetString, IdentifierSize: 1},
			},
			"1.3.6.1.2.1.2.2.1.2": {
				"1.3.6.1.2.1.2.2.1.2.1": {Value: "Gi0", Type: gosnmp.OctetString, IdentifierSize: 1},
			},
			"1.3.6.1.2.1.4.20.1.1": {
				"1.3.6.1.2.1.4.20.1.1.10.0.0.1": {Value: "10.0.0.1", Type: gosnmp.IPAddress, IdentifierSize: 4},
			},
			"1.3.6.1.2.1.4.20.1.2": {
				"1.3.6.1.2.1.4.20.1.2.10.0.0.1": {Value: 1, Type: gosnmp.Integer, IdentifierSize: 4},
			},
		},
	}
	factory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return walker, nil
	}
	entries := []config.MappingEntry{
		{
			OID: "1.3.6.1.2.1.1", Entity: "device", Field: "_id", IdentifierSize: 1,
			MappingEntries: []config.MappingEntry{
				{OID: "1.3.6.1.2.1.1.5", Entity: "device", Field: "name"},
			},
		},
		{
			OID:            "1.3.6.1.2.1.2.2.1",
			Entity:         "interface",
			Field:          "_id",
			IdentifierSize: 1,
			MappingEntries: []config.MappingEntry{
				{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
			},
		},
		{
			OID:            "1.3.6.1.2.1.4.20.1",
			Entity:         "ipAddress",
			Field:          "_id",
			IdentifierSize: 4,
			MappingEntries: []config.MappingEntry{
				{OID: "1.3.6.1.2.1.4.20.1.1", Entity: "ipAddress", Field: "address"},
				{
					OID:          "1.3.6.1.2.1.4.20.1.2",
					Entity:       "ipAddress",
					Field:        "assignedObject",
					Relationship: config.Relationship{Type: "interface"},
				},
			},
		},
	}

	runner := queryTargetRunner(factory, entries)
	entities, primaryHits, err := runner.queryTarget(context.Background(), config.Target{Host: "10.0.0.1", Port: 161})
	require.NoError(t, err)
	require.NotEmpty(t, entities)

	// Mirror the production sequence: annotate, then prune.
	netboxID := 42
	annotateDeviceWithSourceMatch(entities, netboxID)
	annotateEntitiesWithRunID(entities, "run-abc")
	mapping.PruneNestedRefs(entities, mapping.CurrentDeviceFrom(entities), primaryHits)

	// Find the rich top-level Device.
	var richDevice *diode.Device
	for _, e := range entities {
		if d, ok := e.(*diode.Device); ok {
			richDevice = d
			break
		}
	}
	require.NotNil(t, richDevice, "expected a top-level Device in entities")

	// Top-level Device keeps annotation Metadata.
	require.NotNil(t, richDevice.Metadata)
	assert.Equal(t, "run-abc", richDevice.Metadata["run_id"])
	sourceMatch, ok := richDevice.Metadata["source_match"].(diode.Metadata)
	require.True(t, ok, "source_match should be a nested Metadata map")
	assert.Equal(t, netboxID, sourceMatch["netbox_id"])

	// Find the IPAddress and confirm AssignedObject is a stub Interface.
	// This is the primary way Interfaces reach the entities list — via the
	// ipAddress.assignedObject relationship. The mapper groups interfaces
	// by their SNMP index (ifIndex) and only emits top-level Interface
	// entities when they appear independently of IP assignments; in this
	// fixture, the interface is only discovered via the IP's relationship.
	var ip *diode.IPAddress
	for _, e := range entities {
		if a, ok := e.(*diode.IPAddress); ok && a.Address != nil && *a.Address == "10.0.0.1/32" {
			ip = a
			break
		}
	}
	require.NotNil(t, ip, "expected IPAddress 10.0.0.1/32 in entities")
	stubIface, ok := ip.AssignedObject.(*diode.Interface)
	require.True(t, ok, "IPAddress.AssignedObject must be a *diode.Interface stub after prune")

	// Confirm the stub Interface has no annotation and its Device is a stub.
	assert.Nil(t, stubIface.Metadata, "stub Interface must not carry annotation Metadata")
	require.NotNil(t, stubIface.Device, "Interface stub must keep a Device reference for matching")
	assert.NotSame(t, richDevice, stubIface.Device, "nested Device must be a stub, not the rich pointer")
	assert.Nil(t, stubIface.Device.Serial, "stub Device must not carry rich fields")

	// stub Device may carry source_match (PK-based match path — preserved
	// intentionally) but must never carry run_id annotation.
	if stubIface.Device.Metadata != nil {
		_, hasRunID := stubIface.Device.Metadata["run_id"]
		assert.False(t, hasRunID, "stub Device must not carry run_id annotation")
		// source_match is allowed: when annotateDeviceWithSourceMatch
		// runs first (NetboxID != nil), the stub carries it for the
		// plugin's PK-based matcher.
		if sm, ok := stubIface.Device.Metadata["source_match"]; ok {
			smMap, isMap := sm.(diode.Metadata)
			assert.True(t, isMap, "source_match value must be a Metadata map")
			assert.Equal(t, netboxID, smMap["netbox_id"])
		}
	}

	// PrimaryIp4 cycle-break: only exercised if the rich Device's PrimaryIp4 was set
	// by mappers. This walker doesn't populate it (no SNMP target IP / interface match
	// in this fixture), so the inner block is a no-op here. The stubs_test.go golden
	// covers the cycle-break property directly.
	if stubIface.Device.PrimaryIp4 != nil {
		assert.Nil(t, stubIface.Device.PrimaryIp4.AssignedObject,
			"stub Device's PrimaryIp4 must have AssignedObject == nil")
	}
}

// chassisEntries returns the minimal config.MappingEntry slice needed to
// walk ENTITY-MIB entPhysicalTable columns so that TranslateAsStack has data.
// The entries mirror the chassis_inventory block in policy/mapping.yaml.
func chassisEntries() []config.MappingEntry {
	return []config.MappingEntry{
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
			},
		},
		{
			OID:            "1.3.6.1.2.1.47.1.1.1",
			Entity:         "chassis_inventory",
			Field:          "_id",
			IdentifierSize: 2,
			MappingEntries: []config.MappingEntry{
				{OID: "1.3.6.1.2.1.47.1.1.1.1.4", Entity: "chassis_inventory", Field: "containedIn"},
				{OID: "1.3.6.1.2.1.47.1.1.1.1.5", Entity: "chassis_inventory", Field: "class"},
				{OID: "1.3.6.1.2.1.47.1.1.1.1.6", Entity: "chassis_inventory", Field: "parentRelPos"},
				{OID: "1.3.6.1.2.1.47.1.1.1.1.7", Entity: "chassis_inventory", Field: "name"},
				{OID: "1.3.6.1.2.1.47.1.1.1.1.11", Entity: "chassis_inventory", Field: "serialNumber"},
				{OID: "1.3.6.1.2.1.47.1.1.1.1.13", Entity: "chassis_inventory", Field: "modelName"},
			},
		},
	}
}

// TestRunWithMetadata_StandaloneSetsSerialFromEntityMib confirms that the
// ENTITY-MIB serial walk path (TranslateAsStack standalone branch) sets
// master.Serial when exactly one chassis row is present — no VirtualChassis
// is emitted and no member Devices are added.
func TestRunWithMetadata_StandaloneSetsSerialFromEntityMib(t *testing.T) {
	// Single chassis row: class=3, containedIn=0, serial="FOC1234A".
	// Keys in the inner PDU map use leading dots so extractInventory finds them.
	// Integer-typed PDUs must use Go int values; MapPDU does a type-assertion.
	walker := &staticWalker{
		pdus: map[string]map[string]snmp.PDU{
			"1.3.6.1.2.1.1.5": {
				"1.3.6.1.2.1.1.5.0": {Value: "router-1", Type: gosnmp.OctetString, IdentifierSize: 1},
			},
			"1.3.6.1.2.1.47.1.1.1.1.4": {
				".1.3.6.1.2.1.47.1.1.1.1.4.1": {Value: 0, Type: gosnmp.Integer, IdentifierSize: 2},
			},
			"1.3.6.1.2.1.47.1.1.1.1.5": {
				".1.3.6.1.2.1.47.1.1.1.1.5.1": {Value: 3, Type: gosnmp.Integer, IdentifierSize: 2},
			},
			"1.3.6.1.2.1.47.1.1.1.1.6": {
				".1.3.6.1.2.1.47.1.1.1.1.6.1": {Value: 0, Type: gosnmp.Integer, IdentifierSize: 2},
			},
			"1.3.6.1.2.1.47.1.1.1.1.11": {
				".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "FOC1234A", Type: gosnmp.OctetString, IdentifierSize: 2},
			},
			"1.3.6.1.2.1.47.1.1.1.1.13": {
				".1.3.6.1.2.1.47.1.1.1.1.13.1": {Value: "WS-C3850-48P", Type: gosnmp.OctetString, IdentifierSize: 2},
			},
		},
	}
	factory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return walker, nil
	}

	runner := queryTargetRunner(factory, chassisEntries())
	entities, _, err := runner.queryTarget(context.Background(), config.Target{Host: "192.0.2.1", Port: 161})
	require.NoError(t, err)
	require.NotEmpty(t, entities)

	// Exactly one Device, no VirtualChassis, Serial set from ENTITY-MIB.
	var devices []*diode.Device
	var vcs []*diode.VirtualChassis
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Device:
			devices = append(devices, v)
		case *diode.VirtualChassis:
			vcs = append(vcs, v)
		}
	}
	require.Len(t, devices, 1, "standalone: exactly one Device")
	assert.Empty(t, vcs, "standalone: no VirtualChassis emitted")
	require.NotNil(t, devices[0].Serial, "standalone: master.Serial must be set from ENTITY-MIB")
	assert.Equal(t, "FOC1234A", *devices[0].Serial)
}

// TestRunWithMetadata_EmitsFullStackShape asserts the complete emission
// shape for a 2-member stack end-to-end through the runner pipeline:
// TranslateAsStack, annotators, and PruneNestedRefs. Checks:
//   - 1 VirtualChassis with correct Name; VC.Metadata["run_id"] set
//   - VC.Master.VirtualChassis nil (non-recursion invariant)
//   - 2 Devices: master (VcPosition nil, source_match present) and
//     member (VcPosition=2, source_match absent)
//   - Interface Gi1/0/1 routed to master; Gi2/0/1 routed to member
func TestRunWithMetadata_EmitsFullStackShape(t *testing.T) {
	// Two chassis rows: member 1 (parentRelPos=1) and member 2 (parentRelPos=2).
	// Two interfaces: Gi1/0/1 (ifIndex=1, routes to member 1) and
	// Gi2/0/1 (ifIndex=2, routes to member 2 via ParseMemberID).
	// Integer-typed PDUs must use Go int values; MapPDU does a type-assertion.
	walker := &staticWalker{
		pdus: map[string]map[string]snmp.PDU{
			"1.3.6.1.2.1.1.5": {
				"1.3.6.1.2.1.1.5.0": {Value: "3850-stack", Type: gosnmp.OctetString, IdentifierSize: 1},
			},
			"1.3.6.1.2.1.2.2.1.2": {
				"1.3.6.1.2.1.2.2.1.2.1": {Value: "Gi1/0/1", Type: gosnmp.OctetString, IdentifierSize: 1},
				"1.3.6.1.2.1.2.2.1.2.2": {Value: "Gi2/0/1", Type: gosnmp.OctetString, IdentifierSize: 1},
			},
			// Member 1 (entPhysicalIndex=1).
			"1.3.6.1.2.1.47.1.1.1.1.4": {
				".1.3.6.1.2.1.47.1.1.1.1.4.1":    {Value: 0, Type: gosnmp.Integer, IdentifierSize: 2},
				".1.3.6.1.2.1.47.1.1.1.1.4.1000": {Value: 0, Type: gosnmp.Integer, IdentifierSize: 2},
			},
			"1.3.6.1.2.1.47.1.1.1.1.5": {
				".1.3.6.1.2.1.47.1.1.1.1.5.1":    {Value: 3, Type: gosnmp.Integer, IdentifierSize: 2},
				".1.3.6.1.2.1.47.1.1.1.1.5.1000": {Value: 3, Type: gosnmp.Integer, IdentifierSize: 2},
			},
			"1.3.6.1.2.1.47.1.1.1.1.6": {
				".1.3.6.1.2.1.47.1.1.1.1.6.1":    {Value: 1, Type: gosnmp.Integer, IdentifierSize: 2},
				".1.3.6.1.2.1.47.1.1.1.1.6.1000": {Value: 2, Type: gosnmp.Integer, IdentifierSize: 2},
			},
			"1.3.6.1.2.1.47.1.1.1.1.11": {
				".1.3.6.1.2.1.47.1.1.1.1.11.1":    {Value: "FCW2147L0K3", Type: gosnmp.OctetString, IdentifierSize: 2},
				".1.3.6.1.2.1.47.1.1.1.1.11.1000": {Value: "FCW2147L0K4", Type: gosnmp.OctetString, IdentifierSize: 2},
			},
			"1.3.6.1.2.1.47.1.1.1.1.13": {
				".1.3.6.1.2.1.47.1.1.1.1.13.1":    {Value: "WS-C3850-48P", Type: gosnmp.OctetString, IdentifierSize: 2},
				".1.3.6.1.2.1.47.1.1.1.1.13.1000": {Value: "WS-C3850-48P", Type: gosnmp.OctetString, IdentifierSize: 2},
			},
		},
	}
	factory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return walker, nil
	}

	runner := queryTargetRunner(factory, chassisEntries())

	// Use NetboxID=42 on the target so we can verify source_match on master.
	netboxID := 42
	target := config.Target{Host: "192.0.2.1", Port: 161, NetboxID: &netboxID}
	entities, primaryHits, err := runner.queryTarget(context.Background(), target)
	require.NoError(t, err)
	require.NotEmpty(t, entities)

	// Mirror production sequence: annotate, prune.
	if target.NetboxID != nil {
		annotateDeviceWithSourceMatch(entities, *target.NetboxID)
	}
	annotateEntitiesWithRunID(entities, "run-stack-123")
	mapping.PruneNestedRefs(entities, mapping.CurrentDeviceFrom(entities), primaryHits)

	// Collect typed results.
	var masterDev, memberDev *diode.Device
	var vcEntity *diode.VirtualChassis
	var ifaces []*diode.Interface
	for _, e := range entities {
		switch v := e.(type) {
		case *diode.Device:
			if v.VcPosition == nil {
				masterDev = v
			} else {
				memberDev = v
			}
		case *diode.VirtualChassis:
			vcEntity = v
		case *diode.Interface:
			ifaces = append(ifaces, v)
		}
	}

	// VC assertions.
	require.NotNil(t, vcEntity, "VirtualChassis must be emitted for a 2-member stack")
	require.NotNil(t, vcEntity.Name)
	assert.Equal(t, "3850-stack", *vcEntity.Name)
	assert.Equal(t, "run-stack-123", vcEntity.Metadata["run_id"], "VC must carry run_id")
	require.NotNil(t, vcEntity.Master)
	assert.Nil(t, vcEntity.Master.VirtualChassis, "VC.Master.VirtualChassis must be nil (non-recursion)")

	// Master Device assertions.
	require.NotNil(t, masterDev, "master Device must be present")
	assert.Nil(t, masterDev.VcPosition, "master has no VcPosition")
	require.NotNil(t, masterDev.Serial)
	assert.Equal(t, "FCW2147L0K3", *masterDev.Serial, "master Serial = lowest-id chassis serial")
	require.NotNil(t, masterDev.Metadata)
	sm, ok := masterDev.Metadata["source_match"].(diode.Metadata)
	require.True(t, ok, "master must carry source_match")
	assert.Equal(t, netboxID, sm["netbox_id"])

	// Member Device assertions.
	require.NotNil(t, memberDev, "member Device must be present")
	require.NotNil(t, memberDev.VcPosition)
	assert.Equal(t, int64(2), *memberDev.VcPosition)
	_, hasSM := memberDev.Metadata["source_match"]
	assert.False(t, hasSM, "member must NOT carry source_match")

	// VirtualChassis.Master source_match assertions (Fix 1):
	// Both the top-level VC.Master ref AND the member's inline
	// VirtualChassis.Master ref must carry source_match so Diode's
	// unique_master matcher resolves consistently on reruns.
	wantSM := diode.Metadata{"netbox_id": netboxID}
	require.NotNil(t, vcEntity.Master, "VC.Master must be set")
	vcMasterSM, vcMasterOK := vcEntity.Master.Metadata["source_match"].(diode.Metadata)
	require.True(t, vcMasterOK, "VC.Master must carry source_match")
	assert.Equal(t, wantSM, vcMasterSM, "VC.Master source_match must match netboxID")

	require.NotNil(t, memberDev.VirtualChassis, "member.VirtualChassis must be set")
	require.NotNil(t, memberDev.VirtualChassis.Master, "member.VirtualChassis.Master must be set")
	memberMasterSM, memberMasterOK := memberDev.VirtualChassis.Master.Metadata["source_match"].(diode.Metadata)
	require.True(t, memberMasterOK, "member.VirtualChassis.Master must carry source_match")
	assert.Equal(t, wantSM, memberMasterSM, "member.VirtualChassis.Master source_match must match netboxID")

	// Interface routing: exactly 2 interfaces, Gi1/0/1 → master, Gi2/0/1 → member.
	assert.Len(t, ifaces, 2, "expect exactly 2 top-level interfaces: Gi1/0/1 (master) and Gi2/0/1 (member)")
	ifaceByName := map[string]*diode.Interface{}
	for _, iface := range ifaces {
		if iface.Name != nil {
			ifaceByName[*iface.Name] = iface
		}
	}
	gi1 := ifaceByName["Gi1/0/1"]
	gi2 := ifaceByName["Gi2/0/1"]
	require.NotNil(t, gi1, "Gi1/0/1 must be present")
	require.NotNil(t, gi2, "Gi2/0/1 must be present")
	require.NotNil(t, gi1.Device)
	require.NotNil(t, gi2.Device)
	assert.Equal(t, "3850-stack", *gi1.Device.Name, "Gi1/0/1 routes to master")
	assert.Equal(t, "3850-stack-2", *gi2.Device.Name, "Gi2/0/1 routes to member")
}

func TestNewRunner_RangeScheduledWithCron(t *testing.T) {
	cron := "0 * * * *"
	pol := config.Policy{
		Config: config.PolicyConfig{
			Schedule: &cron,
			Timeout:  120,
		},
		Scope: config.Scope{
			Targets: []config.Target{
				{Host: "192.168.1.1-2", Port: 161},
			},
		},
	}
	runStore := NewRunStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	runner, err := NewRunner(context.Background(), logger, "test-policy", pol, nil,
		snmp.NewFakeSNMPWalker, &config.Mapping{}, nil, nil, runStore)
	require.NoError(t, err)
	runner.scheduler.Start()
	defer func() { _ = runner.Stop() }()

	jobs := runner.scheduler.Jobs()
	require.Len(t, jobs, 1, "one job for the range scan")

	nextRuns, err := jobs[0].NextRuns(2)
	require.NoError(t, err)
	require.Len(t, nextRuns, 2)
	assert.False(t, nextRuns[1].IsZero(), "second next run must be a real future time, not zero — proves this is a cron job not a one-time job")
	assert.True(t, nextRuns[1].After(nextRuns[0]), "cron next runs must be strictly increasing")
}

// TestAssetTagClaimer_Semantics tests the per-policy claim logic directly.
// First claim: allowed and recorded. Same-host re-claim: allowed.
// Cross-host claim: rejected with warn log. Map state reflects ownership.
func TestAssetTagClaimer_Semantics(t *testing.T) {
	r := &Runner{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		assetTagOwners: map[string]string{},
	}

	claimA := r.assetTagClaimer("host-A")
	claimB := r.assetTagClaimer("host-B")

	// First claim by host-A: must succeed.
	assert.True(t, claimA("TAG-001"), "first claim must be allowed")

	// Verify ownership recorded.
	r.assetTagOwnersMu.Lock()
	assert.Equal(t, "host-A", r.assetTagOwners["TAG-001"])
	r.assetTagOwnersMu.Unlock()

	// Same-host re-claim on next cycle: must succeed.
	assert.True(t, claimA("TAG-001"), "same-host re-claim must be allowed")

	// Cross-host claim: must be rejected.
	assert.False(t, claimB("TAG-001"), "cross-host claim must be suppressed")

	// Ownership must remain with the original host.
	r.assetTagOwnersMu.Lock()
	assert.Equal(t, "host-A", r.assetTagOwners["TAG-001"], "ownership must not transfer on rejected claim")
	r.assetTagOwnersMu.Unlock()

	// A different tag has no prior owner: host-B can claim it.
	assert.True(t, claimB("TAG-002"), "host-B must be able to claim an unclaimed tag")
}

// TestAssetTagClaimer_PortDistinguishesTargets: two agents on the same
// host behind different SNMP ports are distinct devices (the runner's
// job identity is host:port), so claims must be keyed by the full
// target identity — a cloned tag on the second port must be suppressed.
func TestAssetTagClaimer_PortDistinguishesTargets(t *testing.T) {
	r := &Runner{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		assetTagOwners: map[string]string{},
	}

	claim161 := r.assetTagClaimer("10.0.0.1:161")
	claim1161 := r.assetTagClaimer("10.0.0.1:1161")

	assert.True(t, claim161("CLONED"), "first port claims the tag")
	assert.False(t, claim1161("CLONED"),
		"same host on a different port is a different target; cloned tag must be suppressed")
}

// TestAssetTagClaimer_NilMapLazyInit: a Runner built as a literal
// (without NewRunner) must not panic on the first claim — the claimer
// lazily initializes the ownership map under the mutex.
func TestAssetTagClaimer_NilMapLazyInit(t *testing.T) {
	r := &Runner{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	claim := r.assetTagClaimer("10.0.0.1:161")
	assert.NotPanics(t, func() {
		assert.True(t, claim("TAG-001"), "first claim on lazily-initialized map must succeed")
	})
	assert.False(t, r.assetTagClaimer("10.0.0.2:161")("TAG-001"),
		"ownership recorded in the lazily-created map must suppress cross-target claims")
}

// engineWalker answers Walk with an error but reports that the credential-free
// v3 engine discovery exchange completed, which is what a real agent does when
// the probe's placeholder user is not one it knows.
type engineWalker struct {
	testWalker
	discovered bool
}

func (e *engineWalker) EngineDiscovered() bool { return e.discovered }

func TestProbeAuthenticationStripsV3Credentials(t *testing.T) {
	configured := &config.Authentication{
		ProtocolVersion: snmp.ProtocolVersion3,
		SecurityLevel:   "authPriv",
		Username:        "netbox-monitor",
		AuthProtocol:    "SHA",
		AuthPassphrase:  "auth-secret",
		PrivProtocol:    "AES",
		PrivPassphrase:  "priv-secret",
		ContextName:     "vrf-mgmt",
	}

	probe := probeAuthentication(configured)

	assert.NotEqual(t, configured.Username, probe.Username, "the operator's user must not reach a scanned address")
	assert.NotEmpty(t, probe.Username, "gosnmp rejects an empty USM user")
	assert.Empty(t, probe.AuthPassphrase)
	assert.Empty(t, probe.PrivPassphrase)
	assert.Equal(t, "noAuthNoPriv", probe.SecurityLevel, "no HMAC means no offline attack material")
	assert.Equal(t, "netbox-monitor", configured.Username, "the caller's authentication must not be mutated")
}

func TestProbeAuthenticationLeavesV2cUnchanged(t *testing.T) {
	// Documents the gap rather than hiding it: v2c has no credential-free
	// exchange, and a wrong community is silently discarded by a conformant
	// agent, so substituting one would turn every device into a false negative.
	configured := &config.Authentication{
		ProtocolVersion: snmp.ProtocolVersion2c,
		Community:       "s3cret",
	}

	probe := probeAuthentication(configured)

	assert.Equal(t, "s3cret", probe.Community)
}

func TestProbeTargetV3AdmitsOnEngineDiscovery(t *testing.T) {
	walker := &engineWalker{discovered: true}
	walker.walkErr = errors.New("unknown user name")
	var gotAuth *config.Authentication

	runner := &Runner{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		scope: config.Scope{Authentication: config.Authentication{
			ProtocolVersion: snmp.ProtocolVersion3,
			SecurityLevel:   "authPriv",
			Username:        "netbox-monitor",
			AuthProtocol:    "SHA",
			AuthPassphrase:  "auth-secret",
			PrivProtocol:    "AES",
			PrivPassphrase:  "priv-secret",
		}},
		snmpProbeTimeout: time.Second,
		ClientFactory: func(_ string, _ uint16, _ int, _ time.Duration, auth *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
			gotAuth = auth
			return walker, nil
		},
	}

	ok := runner.probeTarget(context.Background(), config.Target{Host: "127.0.0.1", Port: 161})

	require.True(t, ok, "an agent that answered engine discovery is present")
	require.NotNil(t, gotAuth)
	assert.NotEqual(t, "netbox-monitor", gotAuth.Username)
	assert.Empty(t, gotAuth.AuthPassphrase)
	assert.Empty(t, gotAuth.PrivPassphrase)
}

func TestProbeTargetV3RejectsWithoutEngineDiscovery(t *testing.T) {
	walker := &engineWalker{discovered: false}
	walker.walkErr = errors.New("request timeout")

	runner := &Runner{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		scope: config.Scope{Authentication: config.Authentication{
			ProtocolVersion: snmp.ProtocolVersion3,
			SecurityLevel:   "authPriv",
			Username:        "netbox-monitor",
			AuthProtocol:    "SHA",
			AuthPassphrase:  "auth-secret",
		}},
		snmpProbeTimeout: time.Second,
		ClientFactory: func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
			return walker, nil
		},
	}

	assert.False(t, runner.probeTarget(context.Background(), config.Target{Host: "127.0.0.1", Port: 161}))
}

func TestProbeAuthenticationBuildsARealClient(t *testing.T) {
	// The other probe tests inject a fake ClientFactory, so none of them
	// exercises snmp.NewClient. That is how an earlier revision shipped a
	// probe authentication the real factory rejected outright: it cleared the
	// protocol fields to "", and getAuthProtocol/getPrivProtocol accept
	// "NoAuth"/"NoPriv" but not the empty string, so every v3 address was
	// refused before a packet was sent and no v3 range scan found anything.
	for _, level := range []string{"noAuthNoPriv", "authNoPriv", "authPriv"} {
		t.Run(level, func(t *testing.T) {
			probe := probeAuthentication(&config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				SecurityLevel:   level,
				Username:        "netbox-monitor",
				AuthProtocol:    "SHA",
				AuthPassphrase:  "auth-secret",
				PrivProtocol:    "AES",
				PrivPassphrase:  "priv-secret",
			})

			client, err := snmp.NewClient("127.0.0.1", 161, 0, time.Second, probe, slog.New(slog.NewTextHandler(io.Discard, nil)))
			require.NoError(t, err, "the real factory must accept the probe authentication")
			require.NotNil(t, client)
		})
	}
}
