package snmp

import (
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/mapping"
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
func (n *FakeSNMPWalker) Walk(oid string) (mapping.ObjectIDValueMap, error) {
	if oid == "1.3.6.1.2.1.4.20.1.1" {
		return mapping.ObjectIDValueMap{
			"1.3.6.1.2.1.4.20.1.1": mapping.Value{Value: "192.168.1.1", Type: mapping.Asn1BER(mapping.IPAddress)},
		}, nil
	}

	if oid == "iso.3.6.1.2.1.2.2.1" {
		return mapping.ObjectIDValueMap{
			"iso.3.6.1.2.1.2.2.1.2.999": mapping.Value{Value: "GigabitEthernet1/0/1", Type: mapping.Asn1BER(mapping.OctetString)},
		}, nil
	}
	return make(mapping.ObjectIDValueMap), nil
}

// NewFakeSNMPWalker creates a new FakeSNMPWalker
func NewFakeSNMPWalker(_ string, _ uint16, _ int, _ *config.Authentication) (Walker, error) {
	return &FakeSNMPWalker{}, nil
}
