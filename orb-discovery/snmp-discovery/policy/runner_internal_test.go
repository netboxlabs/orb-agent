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
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/mapping"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/snmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	entities, err := runner.queryTarget(ctx, config.Target{Host: "127.0.0.1", Port: 161})
	assert.Nil(t, entities)
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

	entities, err := runner.queryTarget(ctx, config.Target{Host: "127.0.0.1", Port: 161})
	assert.Nil(t, entities)
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

	entities, err := runner.queryTarget(context.Background(), config.Target{Host: "127.0.0.1", Port: 161})
	assert.Nil(t, entities)
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

	entities, err := runner.queryTarget(context.Background(), config.Target{Host: "127.0.0.1", Port: 161})
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
	entities, err := runner.queryTarget(context.Background(), config.Target{Host: "10.0.0.1", Port: 161})
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
		entities, err := runner.queryTarget(context.Background(), config.Target{Host: "10.0.0.1", Port: 161})
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
		entities, err := runner.queryTarget(context.Background(), config.Target{Host: "2001:db8::1", Port: 161})
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
	entities, err := runner.queryTarget(context.Background(), config.Target{Host: "10.0.0.1", Port: 161})
	require.NoError(t, err)
	require.NotEmpty(t, entities)

	// Mirror the production sequence: annotate, then prune.
	netboxID := 42
	annotateDeviceWithSourceMatch(entities, netboxID)
	annotateEntitiesWithRunID(entities, "run-abc")
	mapping.PruneNestedRefs(entities, mapping.CurrentDeviceFrom(entities))

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
	assert.Nil(t, stubIface.Device.Metadata, "stub Device must not carry annotation Metadata")
	assert.Nil(t, stubIface.Device.Serial, "stub Device must not carry rich fields")

	// PrimaryIp4 cycle-break: only exercised if the rich Device's PrimaryIp4 was set
	// by mappers. This walker doesn't populate it (no SNMP target IP / interface match
	// in this fixture), so the inner block is a no-op here. The stubs_test.go golden
	// covers the cycle-break property directly.
	if stubIface.Device.PrimaryIp4 != nil {
		assert.Nil(t, stubIface.Device.PrimaryIp4.AssignedObject,
			"stub Device's PrimaryIp4 must have AssignedObject == nil")
	}
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
