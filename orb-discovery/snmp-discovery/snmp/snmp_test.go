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
	"github.com/netboxlabs/orb-discovery/snmp-discovery/mapping"
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
		snmpClientFactory := func(_ string, _ uint16, _ int, _ *config.Authentication) (snmp.Walker, error) {
			fakeWalker, _ := snmp.NewFakeSNMPWalker("192.168.1.1", 161, 3, nil)
			return fakeWalker, nil
		}
		host := snmp.NewHost("192.168.1.1", 161, 3, nil, logger, snmpClientFactory)

		// Execute
		oids, err := host.Walk(objectIDsToQuery)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, len(objectIDsToQuery), len(oids))
		assert.Equal(t, mapping.Value{Value: "192.168.1.1", Type: mapping.Asn1BER(mapping.IPAddress)}, oids[ipAddressObjectID])
	})

	t.Run("Handles SNMP connection error", func(t *testing.T) {
		// Setup
		mockWalker := &MockSNMP{}
		mockWalker.On("Connect").Return(assert.AnError)
		mockWalker.On("Close").Return(nil)
		snmpClientFactory := func(_ string, _ uint16, _ int, _ *config.Authentication) (snmp.Walker, error) {
			return mockWalker, nil
		}
		host := snmp.NewHost("192.168.1.1", 161, 3, nil, logger, snmpClientFactory)

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
		snmpClientFactory := func(_ string, _ uint16, _ int, _ *config.Authentication) (snmp.Walker, error) {
			return mockWalker, nil
		}
		host := snmp.NewHost("192.168.1.1", 161, 3, nil, logger, snmpClientFactory)

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
		snmpClientFactory := func(_ string, _ uint16, _ int, _ *config.Authentication) (snmp.Walker, error) {
			return nil, fmt.Errorf("error creating client")
		}
		host := snmp.NewHost("192.168.1.1", 161, 3, nil, logger, snmpClientFactory)

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
func (m *MockSNMP) Walk(oid string) (mapping.ObjectIDValueMap, error) {
	args := m.Called(oid)
	return nil, args.Error(1)
}

func TestNewClient(t *testing.T) {
	testCases := []struct {
		name           string
		auth           *config.Authentication
		expectError    bool
		expectedErrMsg string
	}{
		{
			name: "Creates SNMPv1 client successfully",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion1,
				Community:       "public",
			},
			expectError: false,
		},
		{
			name: "Creates SNMPv2c client successfully",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion2c,
				Community:       "public",
			},
			expectError: false,
		},
		{
			name: "Creates SNMPv3 client successfully with SHA/AES",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    "SHA",
				AuthPassphrase:  "testpass",
				PrivProtocol:    "AES",
				PrivPassphrase:  "testpass",
			},
			expectError: false,
		},
		{
			name: "Creates SNMPv3 client successfully with MD5/DES",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    "MD5",
				AuthPassphrase:  "testpass",
				PrivProtocol:    "DES",
				PrivPassphrase:  "testpass",
				SecurityLevel:   "authPriv",
			},
			expectError: false,
		},

		{
			name: "Invalid SNMPv3 auth protocol",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    "InvalidProtocol",
				AuthPassphrase:  "testpass",
				PrivProtocol:    "DES",
				PrivPassphrase:  "testpass",
				SecurityLevel:   "authPriv",
			},
			expectError:    true,
			expectedErrMsg: "unsupported authentication protocol: InvalidProtocol",
		},
		{
			name: "Invalid SNMPv3 priv protocol",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    "MD5",
				AuthPassphrase:  "testpass",
				PrivProtocol:    "InvalidProtocol",
				PrivPassphrase:  "testpass",
				SecurityLevel:   "authPriv",
			},
			expectError:    true,
			expectedErrMsg: "unsupported privacy protocol: InvalidProtocol",
		},
		{
			name: "Returns error for unsupported protocol version",
			auth: &config.Authentication{
				ProtocolVersion: "SNMPv4",
			},
			expectError:    true,
			expectedErrMsg: "unsupported protocol version: SNMPv4",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := snmp.NewClient("192.168.1.1", 161, 3, tc.auth)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
				assert.Equal(t, tc.expectedErrMsg, err.Error())
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}
