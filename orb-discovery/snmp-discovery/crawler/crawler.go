package crawler

import (
	"context"
	"log/slog"
	"maps"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
)

type contextKey string

const (
	community            = "public"
	policyKey contextKey = "policy"
)

// Crawler handles network discovery by scanning SNMP-enabled devices
type Crawler struct {
	logger            *slog.Logger
	entities          []diode.Entity
	targets           []string
	ctx               context.Context
	client            diode.Client
	snmpClientFactory func(host string) SNMPWalker
	mapper            *OIDMapper
}

// NewCrawler creates a new Crawler instance with the provided context, logger, client, and target IPs.
func NewCrawler(ctx context.Context, logger *slog.Logger, client diode.Client, targets []string, snmpClientFactory func(host string) SNMPWalker) *Crawler {
	return &Crawler{
		ctx:               ctx,
		logger:            logger,
		client:            client,
		targets:           targets,
		entities:          make([]diode.Entity, 0),
		snmpClientFactory: snmpClientFactory,
		mapper: &OIDMapper{
			mapping: OIDMapping{
				"1.3.6.1.2.1.4.20.1.1": "ipAddress.address",
			},
		},
	}
}

// CrawlTargets initiates the network crawl process on the specified targets
// and returns the discovered entities.
func (c *Crawler) CrawlTargets() ([]diode.Entity, error) {
	c.logger.Info("Starting crawler for targets:", "targets", c.targets)

	for _, target := range c.targets {
		host := &SNMPHost{
			address:           target,
			objects:           make(map[string]string),
			logger:            c.logger,
			snmpClientFactory: c.snmpClientFactory,
			oids:              c.mapper.OIDs(),
		}
		oids, err := host.Walk(target)
		if err != nil {
			c.logger.Warn("Error crawling host", "ip", target, "error", err)
			continue
		}
		entities := c.mapper.MapOIDsToEntity(oids)
		c.entities = append(c.entities, entities...)
	}
	c.logger.Info("SNMP crawl complete.")
	return c.entities, nil
}

// OIDMapping is a map of OIDs to entity types
type OIDMapping map[string]string

// OIDValueMap is a map of OIDs to their values
type OIDValueMap map[string]string

// OIDMapper is a struct that maps OIDs to entities
type OIDMapper struct {
	mapping OIDMapping
}

// mapOIDsToEntity maps OIDs to entities
// In future this will be dynamic based on the OIDMapping from the policy
func (m *OIDMapper) MapOIDsToEntity(oids OIDValueMap) []diode.Entity {
	ipEntity := &diode.IPAddress{
		Address: diode.String(oids["1.3.6.1.2.1.4.20.1.1"] + "/32"),
	}
	return []diode.Entity{ipEntity}
}

func (m *OIDMapper) OIDs() []string {
	objectIDs := make([]string, 0, len(m.mapping))
	for oid := range m.mapping {
		objectIDs = append(objectIDs, oid)
	}
	return objectIDs
}

type SNMPHost struct {
	address           string
	objects           map[string]string
	logger            *slog.Logger
	snmpClientFactory func(host string) SNMPWalker
	oids              []string
}

func (s *SNMPHost) Walk(host string) (OIDValueMap, error) {
	s.logger.Info("Scanning", "host", host)

	snmp := s.snmpClientFactory(host)
	defer func() {
		if err := snmp.Close(); err != nil {
			s.logger.Warn("Error closing SNMP connection", "host", host, "error", err)
		}
	}()

	err := snmp.Connect()
	if err != nil {
		s.logger.Warn("Could not connect to host", "host", host, "error", err)
		return nil, err
	}

	output := make(OIDValueMap)
	for _, oid := range s.oids {
		pdu, err := snmp.Walk(oid)
		if err != nil {
			s.logger.Warn("Error walking OID", "oid", oid, "error", err)
			continue
		}
		maps.Copy(output, pdu)
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

func (c *SNMPClient) Walk(oid string) (OIDValueMap, error) {
	pdu, err := c.WalkAll(oid)
	if err != nil {
		return nil, err
	}
	output := make(OIDValueMap)
	for _, pdu := range pdu {
		output[pdu.Name] = pdu.Value.(string)
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
// It allows for connecting to SNMP devices, traversing OID trees,
// and properly closing connections when finished
type SNMPWalker interface {
	Walk(oid string) (OIDValueMap, error)
	Connect() error
	Close() error
}
