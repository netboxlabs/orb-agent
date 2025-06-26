package snmp

import (
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
)

// FakeSNMPWalker is a no-op implementation of SNMPWalker
type FakeSNMPWalker struct{}

// Connect implements Walker interface
func (n *FakeSNMPWalker) Connect() error {
	return nil
}

// Close implements Walker interface
func (n *FakeSNMPWalker) Close() error {
	return nil
}

// Walk implements Walker interface
func (n *FakeSNMPWalker) Walk(oid string, _ int) (map[string]PDU, error) {
	if oid == "1.3.6.1.2.1.4.20.1.1" {
		return map[string]PDU{
			"1.3.6.1.2.1.4.20.1.1": {Value: "192.168.1.1", Type: gosnmp.IPAddress},
		}, nil
	}

	if oid == "iso.3.6.1.2.1.2.2.1" {
		return map[string]PDU{
			"iso.3.6.1.2.1.2.2.1.2.999": {Value: "GigabitEthernet1/0/1", Type: gosnmp.OctetString},
		}, nil
	}
	return make(map[string]PDU), nil
}

// NewFakeSNMPWalker creates a new FakeSNMPWalker
func NewFakeSNMPWalker(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication) (Walker, error) {
	return &FakeSNMPWalker{}, nil
}
