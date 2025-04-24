package snmp_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/snmp"
)

// MockSNMP is a mock for SNMPWalker
type MockSNMP struct {
	mock.Mock
}

// MockConn is a mock for the connection
type MockConn struct {
	mock.Mock
}

func (m *MockConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockClient mocks the diode.Client
type MockClient struct {
	mock.Mock
}

// Close implements diode.Client.
func (m *MockClient) Close() error {
	panic("unimplemented")
}

// Ingest implements diode.Client.
func (m *MockClient) Ingest(context.Context, []diode.Entity) (*diodepb.IngestResponse, error) {
	panic("unimplemented")
}

// FakeSNMPWalker is a no-op implementation of SNMPWalker
type FakeSNMPWalker struct{}

// Connect implements SNMPWalker interface
func (n *FakeSNMPWalker) Connect() error {
	return nil
}

// Close implements SNMPWalker interface
func (n *FakeSNMPWalker) Close() error {
	return nil
}

// Walk implements SNMPWalker interface
func (n *FakeSNMPWalker) Walk(oid string) (snmp.ObjectIDValueMap, error) {
	if oid == "1.3.6.1.2.1.4.20.1.1" {
		return snmp.ObjectIDValueMap{
			"1.3.6.1.2.1.4.20.1.1": "192.168.1.1",
		}, nil
	}
	return make(snmp.ObjectIDValueMap), nil
}

func NewFakeSNMPWalker(_ string) snmp.SNMPWalker {
	return &FakeSNMPWalker{}
}

func TestSNMPHost(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	const ipAddressObjectId = "1.3.6.1.2.1.4.20.1.1"
	t.Run("Successfully walks a host", func(t *testing.T) {
		// Setup
		objectIdsToQuery := []string{ipAddressObjectId}
		fakeWalker := NewFakeSNMPWalker("")
		host := snmp.NewSNMPHost("192.168.1.1", logger, func(_ string) snmp.SNMPWalker { return fakeWalker }, objectIdsToQuery)

		// Execute
		oids, err := host.Walk("192.168.1.1")

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, len(objectIdsToQuery), len(oids))
		assert.Equal(t, "192.168.1.1", oids[ipAddressObjectId])
	})

	t.Run("Handles SNMP connection error", func(t *testing.T) {
		// Setup
		mockWalker := &MockSNMP{}
		mockWalker.On("Connect").Return(assert.AnError)
		mockWalker.On("Close").Return(nil)
		host := snmp.NewSNMPHost("192.168.1.1", logger, func(_ string) snmp.SNMPWalker { return mockWalker }, []string{"1.3.6.1.2.1.4.20.1.1"})

		// Execute
		oids, err := host.Walk("192.168.1.1")

		// Assert
		assert.Error(t, err)
		assert.Nil(t, oids)
		mockWalker.AssertExpectations(t)
	})
}

// Connect implements SNMPWalker interface
func (m *MockSNMP) Connect() error {
	args := m.Called()
	return args.Error(0)
}

// Close implements SNMPWalker interface
func (m *MockSNMP) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Walk implements SNMPWalker interface
func (m *MockSNMP) Walk(oid string) (snmp.ObjectIDValueMap, error) {
	args := m.Called(oid)
	return args.Get(0).(snmp.ObjectIDValueMap), args.Error(1)
}
