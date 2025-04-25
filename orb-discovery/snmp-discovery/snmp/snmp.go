package snmp

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
)

// ObjectIDMapping is a map of ObjectIDs to entity types
type ObjectIDMapping map[string]string

// ObjectIDValueMap is a map of ObjectIDs to their values
type ObjectIDValueMap map[string]string

// ObjectIDMapper is a struct that maps ObjectIDs to entities
type ObjectIDMapper struct {
	mapping ObjectIDMapping
}

// NewObjectIDMapper creates a new ObjectIDMapper
func NewObjectIDMapper() *ObjectIDMapper {
	return &ObjectIDMapper{
		mapping: ObjectIDMapping{
			"1.3.6.1.2.1.4.20.1.1": "ipAddress.address",
		},
	}
}

// MapObjectIDsToEntity maps ObjectIDs to entities
// In future this will be dynamic based on the ObjectIDMapping from the policy
func (m *ObjectIDMapper) MapObjectIDsToEntity(objectIDs ObjectIDValueMap) []diode.Entity {
	ipEntity := &diode.IPAddress{
		Address: diode.String(objectIDs["1.3.6.1.2.1.4.20.1.1"] + "/32"),
	}
	return []diode.Entity{ipEntity}
}

// ObjectIDs returns the ObjectIDs that the ObjectIDMapper can map
func (m *ObjectIDMapper) ObjectIDs() []string {
	objectIDs := make([]string, 0, len(m.mapping))
	for objectID := range m.mapping {
		objectIDs = append(objectIDs, objectID)
	}
	return objectIDs
}

// Host is a struct that represents an SNMP host
type Host struct {
	address        string
	port           uint16
	retries        int
	authentication *config.Authentication
	logger         *slog.Logger
	ClientFactory  ClientFactory
}

// NewHost creates a new Host
func NewHost(host string, port uint16, retries int, authentication *config.Authentication, logger *slog.Logger, ClientFactory ClientFactory) *Host {
	return &Host{
		address:        host,
		port:           port,
		retries:        retries,
		authentication: authentication,
		logger:         logger,
		ClientFactory:  ClientFactory,
	}
}

// Walk walks the SNMP host
func (s *Host) Walk(objectIDs []string) (ObjectIDValueMap, error) {
	s.logger.Info("Scanning", "host", s.address)

	snmpClient, err := s.ClientFactory(s.address, s.port, s.retries, s.authentication)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := snmpClient.Close(); err != nil {
			s.logger.Warn("Error closing SNMP connection", "host", s.address, "error", err)
		}
	}()

	err = snmpClient.Connect()
	if err != nil {
		s.logger.Warn("Could not connect to host", "host", s.address, "error", err)
		return nil, err
	}

	output := make(ObjectIDValueMap)
	for _, objectID := range objectIDs {
		pdu, err := snmpClient.Walk(objectID)
		if err != nil {
			s.logger.Warn("Error walking ObjectID", "objectID", objectID, "error", err)
			return nil, err
		}
		for k, v := range pdu {
			if _, ok := output[k]; ok {
				s.logger.Warn("Duplicate ObjectID", "objectID", k)
				continue
			}
			output[k] = v
		}
	}

	return output, nil
}

// Client wraps gosnmp.GoSNMP to implement the Walker interface
type Client struct {
	*gosnmp.GoSNMP
}

// Close implements the Walker interface by closing the SNMP connection
func (c *Client) Close() error {
	return c.Conn.Close()
}

// Walk implements the Walker interface by walking the SNMP tree
func (c *Client) Walk(objectID string) (ObjectIDValueMap, error) {
	pdu, err := c.WalkAll(objectID)
	if err != nil {
		return nil, err
	}
	output := make(ObjectIDValueMap)
	for _, pdu := range pdu {
		if value, ok := pdu.Value.(string); ok {
			output[pdu.Name] = value
		} else {
			slog.Warn("Unexpected type for pdu.Value", "name", pdu.Name, "type", fmt.Sprintf("%T", pdu.Value))
		}
	}
	return output, nil
}

const (
	// ProtocolVersion1 is the SNMPv1 protocol version
	ProtocolVersion1 = "SNMPv1"
	// ProtocolVersion2c is the SNMPv2c protocol version
	ProtocolVersion2c = "SNMPv2c"
	// ProtocolVersion3 is the SNMPv3 protocol version
	ProtocolVersion3 = "SNMPv3"
)

// ClientFactory is a function that creates a new SNMPClient
type ClientFactory func(host string, port uint16, retries int, authentication *config.Authentication) (Walker, error)

// NewClient creates a new SNMPClient for the given target host
func NewClient(host string, port uint16, retries int, authentication *config.Authentication) (Walker, error) {
	switch authentication.ProtocolVersion {
	case ProtocolVersion1:
		return &Client{
			&gosnmp.GoSNMP{
				Target:    host,
				Port:      port,
				Community: authentication.Community,
				Version:   gosnmp.Version1,
				Timeout:   time.Duration(2) * time.Second,
			},
		}, nil
	case ProtocolVersion2c:
		return &Client{
			&gosnmp.GoSNMP{
				Target:    host,
				Port:      port,
				Community: authentication.Community,
				Version:   gosnmp.Version2c,
				Timeout:   time.Duration(2) * time.Second,
			},
		}, nil
	case ProtocolVersion3:
		return &Client{
			&gosnmp.GoSNMP{
				Target:  host,
				Port:    port,
				Version: gosnmp.Version3,
				Timeout: time.Duration(2) * time.Second,
				Retries: retries,
				SecurityParameters: &gosnmp.UsmSecurityParameters{
					UserName:                 authentication.Username,
					AuthenticationProtocol:   getAuthProtocol(authentication.AuthProtocol),
					AuthenticationPassphrase: authentication.AuthPassphrase,
					PrivacyProtocol:          getPrivProtocol(authentication.PrivProtocol),
					PrivacyPassphrase:        authentication.PrivPassphrase,
				},
			},
		}, nil
	}
	return nil, fmt.Errorf("unsupported protocol version: %s", authentication.ProtocolVersion)
}

func getAuthProtocol(authProtocol string) gosnmp.SnmpV3AuthProtocol {
	switch authProtocol {
	case "NoAuth":
		return gosnmp.NoAuth
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	}
	return gosnmp.NoAuth
}

func getPrivProtocol(privProtocol string) gosnmp.SnmpV3PrivProtocol {
	switch privProtocol {
	case "NoPriv":
		return gosnmp.NoPriv
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	}
	return gosnmp.AES
}

// Walker interface defines methods for walking SNMP trees
// It allows for connecting to SNMP devices, traversing ObjectID trees,
// and properly closing connections when finished
type Walker interface {
	Walk(objectID string) (ObjectIDValueMap, error)
	Connect() error
	Close() error
}
