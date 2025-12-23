package snmp_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/mapping"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/snmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockSNMP is a mock for Walker
type MockSNMP struct {
	mock.Mock
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
func (m *MockSNMP) Walk(oid string, identifierSize int) (map[string]snmp.PDU, error) {
	args := m.Called(oid, identifierSize)
	return args.Get(0).(map[string]snmp.PDU), args.Error(1)
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
	const interfaceNameOID = "1.3.6.1.2.1.2.2.1.2"
	const interfaceSpeedOID = "1.3.6.1.2.1.2.2.1.5"
	objectIDsToQuery := make(map[string]int)
	objectIDsToQuery[ipAddressObjectID] = 4
	objectIDsToQuery[interfaceNameOID] = 1
	objectIDsToQuery[interfaceSpeedOID] = 1

	t.Run("Successfully walks a host", func(t *testing.T) {
		// Setup
		snmpClientFactory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, logger *slog.Logger) (snmp.Walker, error) {
			fakeWalker, _ := snmp.NewFakeSNMPWalker("192.168.1.1", 161, 3, 1*time.Second, nil, logger)
			return fakeWalker, nil
		}
		host := snmp.NewHost("192.168.1.1", 161, 3, 1*time.Second, nil, logger, snmpClientFactory)

		// Execute
		oids, err := host.Walk(map[string]int{
			ipAddressObjectID: 4,
		})

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, 1, len(oids))
		assert.Equal(t, mapping.Value{Value: "192.168.1.1", Type: mapping.Asn1BER(mapping.IPAddress)}, oids[ipAddressObjectID])
	})

	t.Run("Handles multiple OIDs with different types", func(t *testing.T) {
		// Setup
		mockWalker := &MockSNMP{}
		mockWalker.On("Connect").Return(nil)
		mockWalker.On("Close").Return(nil)
		mockWalker.On("Walk", ipAddressObjectID, 4).Return(map[string]snmp.PDU{
			ipAddressObjectID: {Value: "192.168.1.1", Type: gosnmp.IPAddress, IdentifierSize: 4},
		}, nil)
		mockWalker.On("Walk", interfaceNameOID, 1).Return(map[string]snmp.PDU{
			interfaceNameOID + ".1": {Value: "GigabitEthernet1/0/1", Type: gosnmp.OctetString, IdentifierSize: 1},
		}, nil)
		mockWalker.On("Walk", interfaceSpeedOID, 1).Return(map[string]snmp.PDU{
			interfaceSpeedOID + ".1": {Value: 1000000, Type: gosnmp.Integer, IdentifierSize: 1},
		}, nil)

		snmpClientFactory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
			return mockWalker, nil
		}
		host := snmp.NewHost("192.168.1.1", 161, 3, 1*time.Second, nil, logger, snmpClientFactory)

		// Execute
		oids, err := host.Walk(objectIDsToQuery)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, 3, len(oids))
		assert.Equal(t, mapping.Value{Value: "192.168.1.1", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4}, oids[ipAddressObjectID])
		assert.Equal(t, mapping.Value{Value: "GigabitEthernet1/0/1", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1}, oids[interfaceNameOID+".1"])
		assert.Equal(t, mapping.Value{Value: "1000000", Type: mapping.Asn1BER(mapping.Integer), IdentifierSize: 1}, oids[interfaceSpeedOID+".1"])
		mockWalker.AssertExpectations(t)
	})

	t.Run("Handles connection close errors", func(t *testing.T) {
		// Setup
		mockWalker := &MockSNMP{}
		mockWalker.On("Connect").Return(nil)
		mockWalker.On("Close").Return(fmt.Errorf("close error"))
		mockWalker.On("Walk", ipAddressObjectID, 4).Return(map[string]snmp.PDU{
			ipAddressObjectID: {Value: "192.168.1.1", Type: gosnmp.IPAddress, IdentifierSize: 4},
		}, nil)

		snmpClientFactory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
			return mockWalker, nil
		}
		host := snmp.NewHost("192.168.1.1", 161, 3, 1*time.Second, nil, logger, snmpClientFactory)

		// Execute
		oids, err := host.Walk(map[string]int{
			ipAddressObjectID: 4,
		})

		// Assert
		assert.NoError(t, err) // Close error should be logged but not returned
		assert.Equal(t, 1, len(oids))
		assert.Equal(t, mapping.Value{Value: "192.168.1.1", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4}, oids[ipAddressObjectID])
		mockWalker.AssertExpectations(t)
	})

	t.Run("Handles SNMP connection error", func(t *testing.T) {
		// Setup
		mockWalker := &MockSNMP{}
		mockWalker.On("Connect").Return(assert.AnError)
		mockWalker.On("Close").Return(nil)
		snmpClientFactory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
			return mockWalker, nil
		}
		host := snmp.NewHost("192.168.1.1", 161, 3, 1*time.Second, nil, logger, snmpClientFactory)

		// Execute
		oids, err := host.Walk(objectIDsToQuery)

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
		mockWalker.On("Walk", mock.Anything, mock.Anything).Return(make(map[string]snmp.PDU), assert.AnError)
		snmpClientFactory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
			return mockWalker, nil
		}
		host := snmp.NewHost("192.168.1.1", 161, 3, 1*time.Second, nil, logger, snmpClientFactory)

		// Execute
		oids, err := host.Walk(objectIDsToQuery)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, oids)
		mockWalker.AssertExpectations(t)
	})

	t.Run("Handles PDU mapping error", func(t *testing.T) {
		// Setup
		mockWalker := &MockSNMP{}
		mockWalker.On("Connect").Return(nil)
		mockWalker.On("Close").Return(nil)
		mockWalker.On("Walk", ipAddressObjectID, 4).Return(map[string]snmp.PDU{
			ipAddressObjectID: {Value: "192.168.1.1", Type: gosnmp.IPAddress, IdentifierSize: 4},
		}, nil)
		mockWalker.On("Walk", interfaceNameOID, 1).Return(map[string]snmp.PDU{
			interfaceNameOID + ".1": {Value: "GigabitEthernet1/0/1", Type: gosnmp.OctetString, IdentifierSize: 1},
		}, nil)
		mockWalker.On("Walk", interfaceSpeedOID, 1).Return(map[string]snmp.PDU{
			interfaceSpeedOID + ".1": {Value: "invalid", Type: gosnmp.Asn1BER(255), IdentifierSize: 1}, // Invalid type
		}, nil)

		snmpClientFactory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
			return mockWalker, nil
		}
		host := snmp.NewHost("192.168.1.1", 161, 3, 1*time.Second, nil, logger, snmpClientFactory)

		// Execute
		oids, err := host.Walk(objectIDsToQuery)

		// Assert
		assert.NoError(t, err)        // Walk should continue despite PDU mapping error
		assert.Equal(t, 2, len(oids)) // Should have 2 valid PDUs
		assert.Equal(t, mapping.Value{Value: "192.168.1.1", Type: mapping.Asn1BER(mapping.IPAddress), IdentifierSize: 4}, oids[ipAddressObjectID])
		assert.Equal(t, mapping.Value{Value: "GigabitEthernet1/0/1", Type: mapping.Asn1BER(mapping.OctetString), IdentifierSize: 1}, oids[interfaceNameOID+".1"])
		// The invalid PDU should be skipped
		_, exists := oids[interfaceSpeedOID+".1"]
		assert.False(t, exists)
		mockWalker.AssertExpectations(t)
	})

	t.Run("Handles SNMP client creation error", func(t *testing.T) {
		// Setup
		mockWalker := &MockSNMP{}
		mockWalker.On("Connect").Return(nil)
		mockWalker.On("Close").Return(nil)
		mockWalker.On("Walk", mock.Anything, mock.Anything).Return(nil, assert.AnError)
		snmpClientFactory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
			return nil, fmt.Errorf("error creating client")
		}
		host := snmp.NewHost("192.168.1.1", 161, 3, 1*time.Second, nil, logger, snmpClientFactory)

		// Execute
		oids, err := host.Walk(objectIDsToQuery)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, oids)
	})
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
			name: "Creates SNMPv3 client successfully with SHA224/AES",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    "SHA224",
				AuthPassphrase:  "testpass",
				PrivProtocol:    "AES",
				PrivPassphrase:  "testpass",
			},
			expectError: false,
		},
		{
			name: "Creates SNMPv3 client successfully with SHA256/AES",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    "SHA256",
				AuthPassphrase:  "testpass",
				PrivProtocol:    "AES",
				PrivPassphrase:  "testpass",
			},
			expectError: false,
		},
		{
			name: "Creates SNMPv3 client successfully with SHA384/AES",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    "SHA384",
				AuthPassphrase:  "testpass",
				PrivProtocol:    "AES",
				PrivPassphrase:  "testpass",
			},
			expectError: false,
		},
		{
			name: "Creates SNMPv3 client successfully with SHA512/AES",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    "SHA512",
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
			name: "Creates SNMPv3 client successfully with MD5/AES192",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    "MD5",
				AuthPassphrase:  "testpass",
				PrivProtocol:    "AES192",
				PrivPassphrase:  "testpass",
				SecurityLevel:   "authPriv",
			},
			expectError: false,
		},
		{
			name: "Creates SNMPv3 client successfully with MD5/AES256",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    "MD5",
				AuthPassphrase:  "testpass",
				PrivProtocol:    "AES256",
				PrivPassphrase:  "testpass",
				SecurityLevel:   "authPriv",
			},
			expectError: false,
		},
		{
			name: "Creates SNMPv3 client successfully with MD5/AES192C",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    "MD5",
				AuthPassphrase:  "testpass",
				PrivProtocol:    "AES192C",
				PrivPassphrase:  "testpass",
				SecurityLevel:   "authPriv",
			},
			expectError: false,
		},
		{
			name: "Creates SNMPv3 client successfully with MD5/AES256C",
			auth: &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    "MD5",
				AuthPassphrase:  "testpass",
				PrivProtocol:    "AES256C",
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
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
			client, err := snmp.NewClient("192.168.1.1", 161, 3, 1*time.Second, tc.auth, logger)

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

func TestNewClientSecurityLevelMsgFlags(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	testCases := []struct {
		name          string
		securityLevel string
		authProtocol  string
		privProtocol  string
		expectedFlag  gosnmp.SnmpV3MsgFlags
	}{
		{
			name:          "noAuthNoPriv sets NoAuthNoPriv flags",
			securityLevel: "noAuthNoPriv",
			authProtocol:  "NoAuth",
			privProtocol:  "NoPriv",
			expectedFlag:  gosnmp.NoAuthNoPriv,
		},
		{
			name:          "authNoPriv sets AuthNoPriv flags",
			securityLevel: "authNoPriv",
			authProtocol:  "SHA",
			privProtocol:  "NoPriv",
			expectedFlag:  gosnmp.AuthNoPriv,
		},
		{
			name:          "authPriv sets AuthPriv flags",
			securityLevel: "authPriv",
			authProtocol:  "SHA",
			privProtocol:  "AES",
			expectedFlag:  gosnmp.AuthPriv,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			auth := &config.Authentication{
				ProtocolVersion: snmp.ProtocolVersion3,
				Username:        "testuser",
				AuthProtocol:    tc.authProtocol,
				AuthPassphrase:  "testpass",
				PrivProtocol:    tc.privProtocol,
				PrivPassphrase:  "testpass",
				SecurityLevel:   tc.securityLevel,
			}

			client, err := snmp.NewClient("192.168.1.1", 161, 3, 1*time.Second, auth, logger)

			assert.NoError(t, err)
			typed, ok := client.(*snmp.Client)
			assert.True(t, ok)
			if ok {
				assert.Equal(t, tc.expectedFlag, typed.MsgFlags)
			}
		})
	}
}

func TestMapPDU(t *testing.T) {
	testCases := []struct {
		name          string
		pdu           snmp.PDU
		expectedValue mapping.Value
		expectError   bool
	}{
		{
			name: "OctetString as string",
			pdu: snmp.PDU{
				Name:  "test.1",
				Type:  gosnmp.OctetString,
				Value: "test string",
			},
			expectedValue: mapping.Value{
				Type:  mapping.Asn1BER(gosnmp.OctetString),
				Value: "test string",
			},
			expectError: false,
		},
		{
			name: "OctetString as bytes",
			pdu: snmp.PDU{
				Name:  "test.2",
				Type:  gosnmp.OctetString,
				Value: []byte("\xF4\x7F\x35\x93\xAF\xC0"),
			},
			expectedValue: mapping.Value{
				Type:  mapping.Asn1BER(gosnmp.OctetString),
				Value: string([]byte("\xF4\x7F\x35\x93\xAF\xC0")),
			},
			expectError: false,
		},
		{
			name: "Integer",
			pdu: snmp.PDU{
				Name:  "test.3",
				Type:  gosnmp.Integer,
				Value: 42,
			},
			expectedValue: mapping.Value{
				Type:  mapping.Asn1BER(gosnmp.Integer),
				Value: "42",
			},
			expectError: false,
		},
		{
			name: "IPAddress",
			pdu: snmp.PDU{
				Name:  "test.4",
				Type:  gosnmp.IPAddress,
				Value: "192.168.1.1",
			},
			expectedValue: mapping.Value{
				Type:  mapping.Asn1BER(gosnmp.IPAddress),
				Value: "192.168.1.1",
			},
			expectError: false,
		},
		{
			name: "ObjectIdentifier",
			pdu: snmp.PDU{
				Name:  "test.5",
				Type:  gosnmp.ObjectIdentifier,
				Value: "1.3.6.1.2.1.1.1.0",
			},
			expectedValue: mapping.Value{
				Type:  mapping.Asn1BER(gosnmp.ObjectIdentifier),
				Value: "1.3.6.1.2.1.1.1.0",
			},
			expectError: false,
		},
		{
			name: "TimeTicks",
			pdu: snmp.PDU{
				Name:  "test.6",
				Type:  gosnmp.TimeTicks,
				Value: uint32(123456),
			},
			expectedValue: mapping.Value{
				Type:  mapping.Asn1BER(gosnmp.TimeTicks),
				Value: "123456",
			},
			expectError: false,
		},
		{
			name: "Counter32",
			pdu: snmp.PDU{
				Name:  "test.7",
				Type:  gosnmp.Counter32,
				Value: uint(4294967295),
			},
			expectedValue: mapping.Value{
				Type:  mapping.Asn1BER(gosnmp.Counter32),
				Value: "4294967295",
			},
			expectError: false,
		},
		{
			name: "Gauge32",
			pdu: snmp.PDU{
				Name:  "test.8",
				Type:  gosnmp.Gauge32,
				Value: uint(4294967295),
			},
			expectedValue: mapping.Value{
				Type:  mapping.Asn1BER(gosnmp.Gauge32),
				Value: "4294967295",
			},
			expectError: false,
		},
		{
			name: "Counter64",
			pdu: snmp.PDU{
				Name:  "test.9",
				Type:  gosnmp.Counter64,
				Value: uint(18446744073709551615),
			},
			expectedValue: mapping.Value{
				Type:  mapping.Asn1BER(gosnmp.Counter64),
				Value: "18446744073709551615",
			},
			expectError: false,
		},
		{
			name: "Unhandled type",
			pdu: snmp.PDU{
				Name:  "test.10",
				Type:  gosnmp.Asn1BER(255), // Invalid type
				Value: "test",
			},
			expectedValue: mapping.Value{},
			expectError:   true,
		},
		{
			name: "Empty OctetString",
			pdu: snmp.PDU{
				Name:  "test.11",
				Type:  gosnmp.OctetString,
				Value: "",
			},
			expectedValue: mapping.Value{
				Type:  mapping.Asn1BER(gosnmp.OctetString),
				Value: "",
			},
			expectError: false,
		},
		{
			name: "Zero Integer",
			pdu: snmp.PDU{
				Name:  "test.12",
				Type:  gosnmp.Integer,
				Value: 0,
			},
			expectedValue: mapping.Value{
				Type:  mapping.Asn1BER(gosnmp.Integer),
				Value: "0",
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := snmp.MapPDU(tc.pdu)

			if tc.expectError {
				assert.Error(t, err)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedValue.Type, result.Type)
				assert.Equal(t, tc.expectedValue.Value, result.Value)
				assert.Equal(t, tc.pdu.IdentifierSize, result.IdentifierSize)
			}
		})
	}
}
