package snmp

import (
	"context"
	"log/slog"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// FakeSNMPWalker is a no-op implementation of Walker
type FakeSNMPWalker struct {
	// Walks records every walk in order, with the request type it would have
	// been issued as. A double that answered the same whatever was asked would
	// let a regression to GETNEXT pass unnoticed.
	Walks []FakeWalk

	bulkWalk bool
}

// FakeWalk is one walk a FakeSNMPWalker was asked for.
type FakeWalk struct {
	OID      string
	BulkWalk bool
}

// SetBulkWalk implements the Walker interface by recording the mode subsequent
// walks are issued under. The fake has no protocol version, so unlike the real
// client it has no reason to refuse.
func (n *FakeSNMPWalker) SetBulkWalk(enabled bool) {
	n.bulkWalk = enabled
}

// Connect implements Walker interface
func (n *FakeSNMPWalker) Connect() error {
	return nil
}

// Close implements Walker interface
func (n *FakeSNMPWalker) Close() error {
	return nil
}

// Walk implements Walker interface.
//
// PDU names carry a leading dot because gosnmp emits them that way. Requested
// OIDs do not, matching the profile OIDs callers pass in.
func (n *FakeSNMPWalker) Walk(oid string, _ int) (map[string]PDU, error) {
	n.Walks = append(n.Walks, FakeWalk{OID: oid, BulkWalk: n.bulkWalk})

	if oid == "1.3.6.1.2.1.4.20.1.1" {
		return map[string]PDU{
			".1.3.6.1.2.1.4.20.1.1": {Name: ".1.3.6.1.2.1.4.20.1.1", Value: "192.168.1.1", Type: gosnmp.IPAddress},
		}, nil
	}

	if oid == "1.3.6.1.2.1.2.2.1.2" {
		return map[string]PDU{
			".1.3.6.1.2.1.2.2.1.2.999": {Name: ".1.3.6.1.2.1.2.2.1.2.999", Value: "GigabitEthernet1/0/1", Type: gosnmp.OctetString},
		}, nil
	}

	if oid == "1.3.6.1.2.1.2.2.1.5" {
		return map[string]PDU{
			".1.3.6.1.2.1.2.2.1.5.999": {Name: ".1.3.6.1.2.1.2.2.1.5.999", Value: 1000000, Type: gosnmp.Integer},
		}, nil
	}

	return make(map[string]PDU), nil
}

// NewFakeSNMPWalker creates a new FakeSNMPWalker
func NewFakeSNMPWalker(_ context.Context, _ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (Walker, error) {
	return &FakeSNMPWalker{}, nil
}
