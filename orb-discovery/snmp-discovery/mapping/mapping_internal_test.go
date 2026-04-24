// Copyright 2024 NetBox Labs Inc
package mapping

import (
	"io"
	"log/slog"
	"testing"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveMappingEntry_FallsBackThroughPDUs covers the Codex P1 from
// PR #369 deterministically. groupByObjectIDIndex captures the Parent
// OID of the first PDU iterated per ifIndex; Go map iteration is
// randomised, so when the captured Parent is a child-only subtree with
// no top-level mapping entry (e.g. ifXTable .1.3.6.1.2.1.31.1.1.1.*),
// the whole index group is dropped. resolveMappingEntry must fall back
// to each other PDU's Parent until one resolves.
//
// The probabilistic form of this test (run through MapObjectIDsToEntity
// and hope Go happens to iterate the bad parent first) is flaky by
// construction. Here we build ObjectIDIndexDetails directly with
// Index set to the non-resolving parent, forcing the failure path.
func TestResolveMappingEntry_FallsBackThroughPDUs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	entries := []config.MappingEntry{
		{
			OID:            ".1.3.6.1.2.1.2.2.1",
			Entity:         "interface",
			Field:          "_id",
			IdentifierSize: 1,
			MappingEntries: []config.MappingEntry{
				{OID: ".1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"},
				{OID: ".1.3.6.1.2.1.31.1.1.1.1", Entity: "interface", Field: "name_alternate"},
			},
		},
	}
	mappingConfig, err := NewConfig(entries, logger, nil, nil, nil)
	require.NoError(t, err)

	m := NewObjectIDMapper(mappingConfig, logger, &config.Defaults{}, "")

	// Force the degenerate case: the captured Index is the ifXTable
	// parent (which has no top-level entry), and the group contains
	// a second PDU whose Parent IS a top-level entry.
	details := NewObjectIDIndexDetails(".1.3.6.1.2.1.31.1.1.1.1")
	details.Values[ObjectIDIndex(".1.3.6.1.2.1.31.1.1.1.1.1")] = &ObjectIDValue{
		OID:    ".1.3.6.1.2.1.31.1.1.1.1.1",
		Index:  "1",
		Parent: ".1.3.6.1.2.1.31.1.1.1.1",
		Value:  "mgmt",
		Type:   OctetString,
	}
	details.Values[ObjectIDIndex(".1.3.6.1.2.1.2.2.1.2.1")] = &ObjectIDValue{
		OID:    ".1.3.6.1.2.1.2.2.1.2.1",
		Index:  "1",
		Parent: ".1.3.6.1.2.1.2.2.1.2",
		Value:  "",
		Type:   OctetString,
	}

	// Direct lookup on the captured (non-resolving) Index must fail.
	_, err = mappingConfig.getMappingEntry(details.Index)
	require.Error(t, err, "precondition: captured parent must not resolve on its own")

	// resolveMappingEntry must find the interface Entry via the
	// secondary PDU's Parent.
	entry, err := m.resolveMappingEntry(details)
	require.NoError(t, err, "resolveMappingEntry must fall back to a resolvable PDU parent")
	require.NotNil(t, entry)
	assert.Equal(t, "interface", entry.Entity)

	// Control: when NO PDU's parent resolves, the helper returns the
	// original error. Seed a details with only an ifXTable PDU.
	details2 := NewObjectIDIndexDetails(".1.3.6.1.2.1.31.1.1.1.1")
	details2.Values[ObjectIDIndex(".1.3.6.1.2.1.31.1.1.1.1.1")] = &ObjectIDValue{
		OID:    ".1.3.6.1.2.1.31.1.1.1.1.1",
		Index:  "1",
		Parent: ".1.3.6.1.2.1.31.1.1.1.1",
		Value:  "mgmt",
		Type:   OctetString,
	}
	_, err = m.resolveMappingEntry(details2)
	assert.Error(t, err, "when no PDU parent resolves, the original error must propagate")
}
