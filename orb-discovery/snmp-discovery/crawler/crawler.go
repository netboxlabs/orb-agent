package crawler

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"context"

	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
)

type contextKey string

const (
	queueSize            = 100
	community            = "public"
	policyKey contextKey = "policy"
)

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

func (c *Crawler) Stop() {
	c.wg.Wait()
	close(c.queue)
	c.logger.Info("Network crawl complete.")
}

type Device struct {
	IP         string
	SysName    string
	Interfaces map[string]string
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
		Retries:   1,
	}
	err := params.Connect()
	if err != nil {
		c.logger.Warn("Could not connect to host", "ip", ip, "error", err)
		return
	}
	defer params.Conn.Close()

	ipEntity := &diode.IPAddress{
		Address: diode.String(ip + "/32"),
	}
	c.logger.Info("Found IP address", "ip", ip, "entity", ipEntity)

	c.entityMux.Lock()
	c.entities = append(c.entities, ipEntity)
	c.entityMux.Unlock()

	// Get system name
	// sysNameOID := ".1.3.6.1.2.1.1.5.0"
	// sysName, err := params.Get([]string{sysNameOID})
	// if err == nil && len(sysName.Variables) > 0 {
	// 	if name, ok := sysName.Variables[0].Value.(string); ok {
	// 		device.SysName = name
	// 	}
	// }
	// c.logger.Info("%s - %s\n", ip, device.SysName)

	// Get interfaces
	// ifaces, _ := params.WalkAll(".1.3.6.1.2.1.2.2.1.2")
	// for _, v := range ifaces {
	// 	ifIndex := v.Name[strings.LastIndex(v.Name, ".")+1:]
	// 	ifName := fmt.Sprintf("%v", v.Value)
	// 	device.Interfaces[ifIndex] = ifName
	// }

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
