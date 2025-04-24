package crawler

import (
	"context"
	"log/slog"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
)

type contextKey string

const (
	queueSize            = 100
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
	}
}

// CrawlTargets initiates the network crawl process on the specified targets
// and returns the discovered entities.
func (c *Crawler) CrawlTargets() ([]diode.Entity, error) {
	c.logger.Info("Starting crawler for targets:", "targets", c.targets)

	for _, target := range c.targets {
		c.crawlHost(target)
	}
	c.logger.Info("Network crawl complete.")
	return c.entities, nil
}

func (c *Crawler) crawlHost(ip string) {

	c.logger.Info("Scanning", "ip", ip)

	snmp := c.snmpClientFactory(ip)
	defer func() {
		if err := snmp.Close(); err != nil {
			c.logger.Warn("Error closing SNMP connection", "ip", ip, "error", err)
		}
	}()

	err := snmp.Connect()
	if err != nil {
		c.logger.Warn("Could not connect to host", "ip", ip, "error", err)
		return
	}

	ipEntity := &diode.IPAddress{
		Address: diode.String(ip + "/32"),
	}
	c.logger.Info("Found IP address", "ip", ip, "entity", ipEntity)

	c.entities = append(c.entities, ipEntity)
}

// SNMPClient wraps gosnmp.GoSNMP to implement the SNMPWalker interface
type SNMPClient struct {
	*gosnmp.GoSNMP
}

// Close implements the SNMPWalker interface by closing the SNMP connection
func (c *SNMPClient) Close() error {
	return c.Conn.Close()
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
	WalkAll(oid string) ([]gosnmp.SnmpPDU, error)
	Connect() error
	Close() error
}
