package snmp

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
)

const (
	community = "public"
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
	address           string
	objects           map[string]string
	logger            *slog.Logger
	snmpClientFactory func(host string) Walker
	objectIDs         []string
}

// NewHost creates a new Host
func NewHost(host string, logger *slog.Logger, snmpClientFactory func(host string) Walker, objectIDs []string) *Host {
	return &Host{
		address:           host,
		objects:           make(map[string]string),
		logger:            logger,
		snmpClientFactory: snmpClientFactory,
		objectIDs:         objectIDs,
	}
}

// Walk walks the SNMP host
func (s *Host) Walk(host string) (ObjectIDValueMap, error) {
	s.logger.Info("Scanning", "host", host)

	Client := s.snmpClientFactory(host)
	defer func() {
		if err := Client.Close(); err != nil {
			s.logger.Warn("Error closing SNMP connection", "host", host, "error", err)
		}
	}()

	err := Client.Connect()
	if err != nil {
		s.logger.Warn("Could not connect to host", "host", host, "error", err)
		return nil, err
	}

	output := make(ObjectIDValueMap)
	for _, objectID := range s.objectIDs {
		pdu, err := Client.Walk(objectID)
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

// NewClient creates a new Client for the given target host
func NewClient(host string) Walker {
	return &Client{
		&gosnmp.GoSNMP{
			Target:    host,
			Port:      161,
			Community: community,
			Version:   gosnmp.Version2c,
			Timeout:   time.Duration(2) * time.Second,
		},
	}
}

// Walker interface defines methods for walking SNMP trees
// It allows for connecting to SNMP devices, traversing ObjectID trees,
// and properly closing connections when finished
type Walker interface {
	Walk(objectID string) (ObjectIDValueMap, error)
	Connect() error
	Close() error
}
