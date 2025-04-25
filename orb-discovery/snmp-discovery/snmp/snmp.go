package snmp

import (
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

func NewObjectIDMapper() *ObjectIDMapper {
	return &ObjectIDMapper{
		mapping: ObjectIDMapping{
			"1.3.6.1.2.1.4.20.1.1": "ipAddress.address",
		},
	}
}

// mapObjectIDsToEntity maps ObjectIDs to entities
// In future this will be dynamic based on the ObjectIDMapping from the policy
func (m *ObjectIDMapper) MapObjectIDsToEntity(objectIDs ObjectIDValueMap) []diode.Entity {
	ipEntity := &diode.IPAddress{
		Address: diode.String(objectIDs["1.3.6.1.2.1.4.20.1.1"] + "/32"),
	}
	return []diode.Entity{ipEntity}
}

func (m *ObjectIDMapper) ObjectIDs() []string {
	objectIDs := make([]string, 0, len(m.mapping))
	for objectID := range m.mapping {
		objectIDs = append(objectIDs, objectID)
	}
	return objectIDs
}

type SNMPHost struct {
	address           string
	objects           map[string]string
	logger            *slog.Logger
	snmpClientFactory func(host string) SNMPWalker
	objectIDs         []string
}

func NewSNMPHost(host string, logger *slog.Logger, snmpClientFactory func(host string) SNMPWalker, objectIds []string) *SNMPHost {
	return &SNMPHost{
		address:           host,
		objects:           make(map[string]string),
		logger:            logger,
		snmpClientFactory: snmpClientFactory,
		objectIDs:         objectIds,
	}
}

func (s *SNMPHost) Walk(host string) (ObjectIDValueMap, error) {
	s.logger.Info("Scanning", "host", host)

	snmpClient := s.snmpClientFactory(host)
	defer func() {
		if err := snmpClient.Close(); err != nil {
			s.logger.Warn("Error closing SNMP connection", "host", host, "error", err)
		}
	}()

	err := snmpClient.Connect()
	if err != nil {
		s.logger.Warn("Could not connect to host", "host", host, "error", err)
		return nil, err
	}

	output := make(ObjectIDValueMap)
	for _, objectID := range s.objectIDs {
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

// SNMPClient wraps gosnmp.GoSNMP to implement the SNMPWalker interface
type SNMPClient struct {
	*gosnmp.GoSNMP
}

// Close implements the SNMPWalker interface by closing the SNMP connection
func (c *SNMPClient) Close() error {
	return c.Conn.Close()
}

func (c *SNMPClient) Walk(objectID string) (ObjectIDValueMap, error) {
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

// NewSNMPWalker creates a new SNMPClient for the given target host
func NewSNMPWalker(host string) SNMPWalker {
	return &SNMPClient{
		&gosnmp.GoSNMP{
			Target:    host,
			Port:      161,
			Community: community,
			Version:   gosnmp.Version2c,
			Timeout:   time.Duration(2) * time.Second,
		},
	}
}

// SNMPWalker interface defines methods for walking SNMP trees
// It allows for connecting to SNMP devices, traversing ObjectID trees,
// and properly closing connections when finished
type SNMPWalker interface {
	Walk(objectID string) (ObjectIDValueMap, error)
	Connect() error
	Close() error
}
