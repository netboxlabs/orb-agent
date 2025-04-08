package crawler

import (
	"context"
	"log/slog"
	"strings"
	"sync"
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
	logger     *slog.Logger
	wg         sync.WaitGroup
	scanned    map[string]bool
	scannedMux *sync.Mutex
	queue      chan string
	entities   []diode.Entity
	entityMux  *sync.Mutex
	targets    []string
	ctx        context.Context
	client     diode.Client
}

// NewCrawler creates a new Crawler instance with the provided context, logger, client, and target IPs.
func NewCrawler(ctx context.Context, logger *slog.Logger, client diode.Client, targets []string) *Crawler {
	return &Crawler{
		ctx:        ctx,
		logger:     logger,
		client:     client,
		targets:    targets,
		wg:         sync.WaitGroup{},
		scanned:    make(map[string]bool),
		scannedMux: &sync.Mutex{},
		queue:      make(chan string, queueSize),
		entities:   make([]diode.Entity, 0),
		entityMux:  &sync.Mutex{},
	}
}

// CrawlTargets initiates the network crawl process on the specified targets
// and returns the discovered entities.
func (c *Crawler) CrawlTargets() ([]diode.Entity, error) {
	c.logger.Info("Starting crawler for targets:", "targets", c.targets)

	go func() {
		for ip := range c.queue {
			go c.crawlHost(ip, c.queue)
		}
	}()

	for _, target := range c.targets {
		c.wg.Add(1)
		c.queue <- target
	}
	c.wg.Wait()
	close(c.queue)
	c.logger.Info("Network crawl complete.")
	return c.entities, nil
}

// Stop waits for all crawling operations to complete and then stops the crawler.
func (c *Crawler) Stop() {
	c.wg.Wait()
	close(c.queue)
	c.logger.Info("Network crawl complete.")
}

func (c *Crawler) crawlHost(ip string, queue chan string) {
	defer c.wg.Done()

	c.scannedMux.Lock()
	if c.scanned[ip] {
		c.scannedMux.Unlock()
		return
	}
	c.scanned[ip] = true
	c.scannedMux.Unlock()

	c.logger.Info("Scanning", "ip", ip)

	params := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(2) * time.Second,
	}
	defer func() {
		if err := params.Conn.Close(); err != nil {
			c.logger.Warn("Error closing SNMP connection", "ip", ip, "error", err)
		}
	}()

	err := params.Connect()
	if err != nil {
		c.logger.Warn("Could not connect to host", "ip", ip, "error", err)
		return
	}

	ipEntity := &diode.IPAddress{
		Address: diode.String(ip + "/32"),
	}
	c.logger.Info("Found IP address", "ip", ip, "entity", ipEntity)

	c.entityMux.Lock()
	c.entities = append(c.entities, ipEntity)
	c.entityMux.Unlock()

	// Get ARP table
	arpEntries, _ := params.WalkAll(".1.3.6.1.2.1.4.22.1.2")
	for _, v := range arpEntries {
		oidParts := strings.Split(v.Name, ".")
		if len(oidParts) >= 4 {
			neighborIP := strings.Join(oidParts[len(oidParts)-4:], ".")
			c.logger.Info("Found neighbor host", "ip", neighborIP)

			// Enqueue for next crawl
			c.wg.Add(1)
			queue <- neighborIP
		}
	}
}
