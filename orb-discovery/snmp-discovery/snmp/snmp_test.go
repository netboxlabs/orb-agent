package snmp_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/snmp"
)

// MockSNMP is a mock for Walker
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
	const ipAddressObjectID = "1.3.6.1.2.1.4.20.1.1"
	t.Run("Successfully walks a host", func(t *testing.T) {
		// Setup
		objectIDsToQuery := []string{ipAddressObjectID}
		fakeWalker, _ := snmp.NewFakeSNMPWalker("192.168.1.1", 161, nil)
		host := snmp.NewHost("192.168.1.1", 161, nil, logger, func(_ string, _ uint16, _ *config.Authentication) (snmp.Walker, error) {
			return fakeWalker, nil
		})

		// Execute
		oids, err := host.Walk(objectIDsToQuery)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, len(objectIDsToQuery), len(oids))
		assert.Equal(t, "192.168.1.1", oids[ipAddressObjectID])
	})

	t.Run("Handles SNMP connection error", func(t *testing.T) {
		// Setup
		mockWalker := &MockSNMP{}
		mockWalker.On("Connect").Return(assert.AnError)
		mockWalker.On("Close").Return(nil)
		host := snmp.NewHost("192.168.1.1", 161, nil, logger, func(_ string, _ uint16, _ *config.Authentication) (snmp.Walker, error) {
			return mockWalker, nil
		})

		// Execute
		oids, err := host.Walk([]string{"1.3.6.1.2.1.4.20.1.1"})

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
		host := snmp.NewHost("192.168.1.1", 161, nil, logger, func(_ string, _ uint16, _ *config.Authentication) (snmp.Walker, error) {
			return mockWalker, nil
		})

		// Execute
		oids, err := host.Walk([]string{ipAddressObjectID})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, oids)
		mockWalker.AssertExpectations(t)
	})

	t.Run("Handles SNMP client creation error", func(t *testing.T) {
		// Setup
		mockWalker := &MockSNMP{}
		mockWalker.On("Connect").Return(nil)
		mockWalker.On("Close").Return(nil)
		mockWalker.On("Walk", mock.Anything).Return(nil, assert.AnError)
		host := snmp.NewHost("192.168.1.1", 161, nil, logger, func(_ string, _ uint16, _ *config.Authentication) (snmp.Walker, error) {
			return nil, fmt.Errorf("error creating client")
		})

		// Execute
		oids, err := host.Walk([]string{ipAddressObjectID})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, oids)
	})
}

// Connect implements Walker interface
func (m *MockSNMP) Connect() error {
	args := m.Called()
	return args.Error(0)
}

// Close implements Walker interface
func (m *MockSNMP) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Walk implements Walker interface
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

func TestNewClient(t *testing.T) {
	t.Run("Creates SNMPv2c client successfully", func(t *testing.T) {
		auth := &config.Authentication{
			ProtocolVersion: snmp.ProtocolVersion1,
			Community:       "public",
		}
		client, err := snmp.NewClient("192.168.1.1", 161, auth)

		assert.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("Creates SNMPv2c client successfully", func(t *testing.T) {
		auth := &config.Authentication{
			ProtocolVersion: snmp.ProtocolVersion2c,
			Community:       "public",
		}
		client, err := snmp.NewClient("192.168.1.1", 161, auth)

		assert.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("Creates SNMPv3 client successfully", func(t *testing.T) {
		auth := &config.Authentication{
			ProtocolVersion: snmp.ProtocolVersion3,
			Username:        "testuser",
			AuthProtocol:    "SHA",
			AuthPassphrase:  "testpass",
			PrivProtocol:    "AES",
			PrivPassphrase:  "testpass",
		}
		client, err := snmp.NewClient("192.168.1.1", 161, auth)

		assert.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("Returns error for unsupported protocol version", func(t *testing.T) {
		auth := &config.Authentication{
			ProtocolVersion: "SNMPv4",
		}
		client, err := snmp.NewClient("192.168.1.1", 161, auth)

		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Equal(t, "unsupported protocol version: SNMPv4", err.Error())
	})
}
