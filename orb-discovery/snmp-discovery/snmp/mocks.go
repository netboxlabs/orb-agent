package snmp

import "github.com/netboxlabs/orb-discovery/snmp-discovery/config"

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
func (n *FakeSNMPWalker) Walk(oid string) (ObjectIDValueMap, error) {
	if oid == "1.3.6.1.2.1.4.20.1.1" {
		return ObjectIDValueMap{
			"1.3.6.1.2.1.4.20.1.1": "192.168.1.1",
		}, nil
	}
	return make(ObjectIDValueMap), nil
}

// NewFakeSNMPWalker creates a new FakeSNMPWalker
func NewFakeSNMPWalker(_ string, _ uint16, _ int, _ *config.Authentication) (Walker, error) {
	return &FakeSNMPWalker{}, nil
}
