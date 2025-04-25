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

func TestSNMPHost(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	const ipAddressObjectId = "1.3.6.1.2.1.4.20.1.1"
	t.Run("Successfully walks a host", func(t *testing.T) {
		// Setup
		objectIdsToQuery := []string{ipAddressObjectId}
		fakeWalker := snmp.NewFakeSNMPWalker("")
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

	t.Run("Handles SNMP walk error", func(t *testing.T) {
		// Setup
		mockWalker := &MockSNMP{}
		mockWalker.On("Connect").Return(nil)
		mockWalker.On("Close").Return(nil)
		mockWalker.On("Walk", mock.Anything).Return(nil, assert.AnError)
		host := snmp.NewSNMPHost("192.168.1.1", logger, func(_ string) snmp.SNMPWalker { return mockWalker }, []string{ipAddressObjectId})

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
	return nil, args.Error(1)
}

func TestMapObjectIDsToEntity(t *testing.T) {
	mapper := snmp.NewObjectIDMapper()
	objectIDs := snmp.ObjectIDValueMap{
		"1.3.6.1.2.1.4.20.1.1": "192.168.1.1",
	}

	entities := mapper.MapObjectIDsToEntity(objectIDs)

	assert.Len(t, entities, 1)
	ipEntity, ok := entities[0].(*diode.IPAddress)
	assert.True(t, ok)
	assert.Equal(t, "192.168.1.1/32", *ipEntity.Address)
}

func TestObjectIDs(t *testing.T) {
	mapper := snmp.NewObjectIDMapper()

	expectedObjectIDs := []string{
		"1.3.6.1.2.1.4.20.1.1",
	}

	objectIDs := mapper.ObjectIDs()

	assert.ElementsMatch(t, expectedObjectIDs, objectIDs)
}
