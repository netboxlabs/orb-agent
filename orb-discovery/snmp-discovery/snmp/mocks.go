package snmp

// FakeSNMPWalker is a no-op implementation of SNMPWalker
type FakeSNMPWalker struct{}

// Connect implements SNMPWalker interface
func (n *FakeSNMPWalker) Connect() error {
	return nil
}

// Close implements SNMPWalker interface
func (n *FakeSNMPWalker) Close() error {
	return nil
}

// Walk implements SNMPWalker interface
func (n *FakeSNMPWalker) Walk(oid string) (ObjectIDValueMap, error) {
	if oid == "1.3.6.1.2.1.4.20.1.1" {
		return ObjectIDValueMap{
			"1.3.6.1.2.1.4.20.1.1": "192.168.1.1",
		}, nil
	}
	return make(ObjectIDValueMap), nil
}

func NewFakeSNMPWalker(_ string) SNMPWalker {
	return &FakeSNMPWalker{}
}
