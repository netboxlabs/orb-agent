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
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/snmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	require.Len(t, expanded[0], 2)
	assert.Equal(t, "192.168.1.1", expanded[0][0].Host)
	assert.Equal(t, uint16(161), expanded[0][0].Port)
	assert.Equal(t, "192.168.1.2", expanded[0][1].Host)
	assert.Equal(t, uint16(161), expanded[0][1].Port)

	require.Len(t, expanded[1], 1)
	assert.Equal(t, "example.com", expanded[1][0].Host)
	assert.Equal(t, uint16(162), expanded[1][0].Port)
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

	runner := &Runner{
		scheduler: scheduler,
		ctx:       context.WithValue(context.Background(), policyKey, "test-policy"),
		timeout:   5 * time.Second,
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	runner.ClientFactory = func(host string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		if host == "good-1" || host == "good-2" {
			return &testWalker{}, nil
		}
		return &testWalker{walkErr: errors.New("no response")}, nil
	}

	runner.runScan([]config.Target{
		{Host: "good-1", Port: 161},
		{Host: "bad-1", Port: 161},
		{Host: "good-2", Port: 161},
	})

	assert.Len(t, runner.tasks, 2)
	assert.Len(t, runner.scheduler.Jobs(), 2)
}
