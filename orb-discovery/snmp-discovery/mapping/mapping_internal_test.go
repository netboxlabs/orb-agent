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
	mappingConfig, err := NewConfig(entries, logger, nil, nil, nil, config.Options{})
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

func TestNewObjectIDValueForEntry_InetAddressIPv4(t *testing.T) {
	entry := &Entry{OID: ".1.3.6.1.2.1.4.34.1", IndexKind: "inet_address"}
	val := Value{Value: "1", Type: Integer, IdentifierSize: 0}
	got, err := newObjectIDValueForEntry(".1.3.6.1.2.1.4.34.1.3.1.4.10.0.0.1", val, entry)
	require.NoError(t, err)
	assert.Equal(t, ObjectIDIndex("ipv4:10.0.0.1"), got.Index)
	assert.Equal(t, ".1.3.6.1.2.1.4.34.1.3", got.Parent)
}

func TestNewObjectIDValueForEntry_InetAddressIPv6(t *testing.T) {
	entry := &Entry{OID: ".1.3.6.1.2.1.4.34.1", IndexKind: "inet_address"}
	val := Value{Value: "1", Type: Integer, IdentifierSize: 0}
	oid := ".1.3.6.1.2.1.4.34.1.3.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1"
	got, err := newObjectIDValueForEntry(oid, val, entry)
	require.NoError(t, err)
	assert.Equal(t, ObjectIDIndex("ipv6:2001:db8::1"), got.Index)
	assert.Equal(t, ".1.3.6.1.2.1.4.34.1.3", got.Parent)
}

// TestNewObjectIDValueForEntry_InetAddressIPv6TailLooksLikeIPv4 is the
// regression test for the suffix-guessing bug Codex flagged: an IPv6 row
// whose final 6 sub-OIDs spell out a valid IPv4 InetAddress shape
// (`1.4.x.x.x.x`) would have been silently classified as IPv4 by the
// original implementation. With the entry-OID anchor, the addrType byte
// is read at the correct position (right after the column sub-OID) and
// the row decodes as IPv6.
func TestNewObjectIDValueForEntry_InetAddressIPv6TailLooksLikeIPv4(t *testing.T) {
	entry := &Entry{OID: ".1.3.6.1.2.1.4.34.1", IndexKind: "inet_address"}
	val := Value{Value: "1", Type: Integer, IdentifierSize: 0}
	// IPv6 with 16 address bytes whose final 6 spell `1.4.10.0.0.1`.
	// Bytes: 0,0,0,0,0,0,0,0,0,0,1,4,10,0,0,1 (10 zeros + the trap pattern).
	oid := ".1.3.6.1.2.1.4.34.1.3.2.16.0.0.0.0.0.0.0.0.0.0.1.4.10.0.0.1"
	got, err := newObjectIDValueForEntry(oid, val, entry)
	require.NoError(t, err)
	// netip.AddrFrom16 normalizes to canonical RFC 5952 form. The trailing
	// IPv4-mapped-octet pattern must NOT be mistaken for an IPv4 row.
	assert.Truef(t, len(string(got.Index)) > len("ipv6:"), "must decode as ipv6: prefix, got %q", got.Index)
	assert.NotEqual(t, ObjectIDIndex("ipv4:10.0.0.1"), got.Index)
	assert.Contains(t, string(got.Index), "ipv6:")
}

func TestNewObjectIDValueForEntry_InetAddressMalformed(t *testing.T) {
	entry := &Entry{OID: ".1.3.6.1.2.1.4.34.1", IndexKind: "inet_address"}
	val := Value{Value: "1", Type: Integer, IdentifierSize: 0}
	_, err := newObjectIDValueForEntry(".1.3.6.1.2.1.4.34.1.3.99.4.1.2.3.4", val, entry)
	require.Error(t, err)
}

func TestNewObjectIDValueForEntry_FixedIdentifierSizeUnchanged(t *testing.T) {
	entry := &Entry{IdentifierSize: 4}
	val := Value{Value: "10.0.0.1", Type: IPAddress, IdentifierSize: 4}
	got, err := newObjectIDValueForEntry(".1.3.6.1.2.1.4.20.1.1.10.0.0.1", val, entry)
	require.NoError(t, err)
	assert.Equal(t, ObjectIDIndex("10.0.0.1"), got.Index)
	assert.Equal(t, ".1.3.6.1.2.1.4.20.1.1", got.Parent)
}

// TestGroupByObjectIDIndex_SerialDoesNotCollideWithIfIndex verifies that
// identifier_size:2 on the entPhysicalSerialNum entry produces an index
// ("11.1") that is disjoint from single-component ifIndex values ("1"),
// preventing groupByObjectIDIndex from merging serial PDUs into interface
// index buckets.
func TestGroupByObjectIDIndex_SerialDoesNotCollideWithIfIndex(t *testing.T) {
	// With identifier_size:2, entPhysicalSerialNum.1 gets index "11.1",
	// not "1", so it is never merged into the ifIndex "1" bucket.
	objectIDs := ObjectIDValueMap{
		".1.3.6.1.2.1.2.2.1.2.1":       {Value: "eth0", Type: OctetString, IdentifierSize: 1},
		".1.3.6.1.2.1.47.1.1.1.1.11.1": {Value: "SER001", Type: OctetString, IdentifierSize: 2},
	}
	mapper := &ObjectIDMapper{logger: slog.Default()}
	groups := mapper.groupByObjectIDIndex(objectIDs)

	assert.Len(t, groups, 2)
	_, hasIfIndex := groups["1"]
	_, hasSerialIndex := groups["11.1"]
	assert.True(t, hasIfIndex, "ifIndex group '1' should exist")
	assert.True(t, hasSerialIndex, "serial group '11.1' should exist")
}

// TestNewConfig_RejectsUnknownIndexKind ensures NewConfig fails fast
// when index_kind carries a value outside the documented enum. A typo
// that silently fell through to the legacy fixed-size path would
// regress modern-only devices to "no IPs discovered".
func TestNewConfig_RejectsUnknownIndexKind(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	entries := []config.MappingEntry{
		{
			OID:       ".1.3.6.1.2.1.4.34.1",
			Entity:    "ipAddress",
			Field:     "_id",
			IndexKind: "InetAddress", // wrong case — typo
		},
	}
	_, err := NewConfig(entries, logger, nil, nil, nil, config.Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid index_kind")
}

// TestNewConfig_RejectsInetAddressOnChildlessTopLevel verifies that
// index_kind:"inet_address" requires the top-level entry to have at
// least one child mapping_entry. A childless entry would pass every
// other validation, then newObjectIDValueForEntry would treat every
// row as malformed (because its column boundary lands inside the
// InetAddress index, not the column sub-OID).
func TestNewConfig_RejectsInetAddressOnChildlessTopLevel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	entries := []config.MappingEntry{
		{
			OID:       ".1.3.6.1.2.1.4.34.1",
			Entity:    "ipAddress",
			Field:     "_id",
			IndexKind: "inet_address",
			// No child columns — would parse as scalar / table-prefix
			// without the column boundary the parser assumes.
		},
	}
	_, err := NewConfig(entries, logger, nil, nil, nil, config.Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one child mapping_entry")
}

// TestNewConfig_RejectsChildIndexKindOverridingParent verifies the
// stricter rule: index_kind may only be declared on the top-level
// table entry. Any explicit child-level declaration — whether it
// matches the parent, differs from it, or appears with no parent
// declaration at all — is rejected, since the fast-path cache only
// sees top-level entries and a child-only declaration would silently
// drop the table back to fixed-size parsing.
func TestNewConfig_RejectsChildIndexKindOverridingParent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name   string
		parent string
		child  string
	}{
		{name: "child differs from parent", parent: "inet_address", child: "fixed"},
		{name: "child set with empty parent", parent: "", child: "inet_address"},
		{name: "child duplicates parent", parent: "inet_address", child: "inet_address"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entries := []config.MappingEntry{
				{
					OID:       ".1.3.6.1.2.1.4.34.1",
					Entity:    "ipAddress",
					Field:     "_id",
					IndexKind: c.parent,
					MappingEntries: []config.MappingEntry{
						{
							OID:       ".1.3.6.1.2.1.4.34.1.5",
							Entity:    "ipAddress",
							Field:     "addressPrefix",
							IndexKind: c.child,
						},
					},
				},
			}
			_, err := NewConfig(entries, logger, nil, nil, nil, config.Options{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must be declared only on the top-level")
		})
	}
}

// TestInetAddressEntryFor_LongestPrefixWins guards against the
// random-map-iteration bug Copilot flagged: when two inet_address
// entries overlap, the longest matching prefix must win so
// newObjectIDValueForEntry splits the column boundary at the right
// depth.
func TestInetAddressEntryFor_LongestPrefixWins(t *testing.T) {
	short := &Entry{OID: ".1.3.6.1.2.1.4.34.1", IndexKind: "inet_address"}
	long := &Entry{OID: ".1.3.6.1.2.1.4.34.1.X.Y", IndexKind: "inet_address"}
	cfg := &Config{
		inetAddressEntries: map[string]*Entry{
			short.OID: short,
			long.OID:  long,
		},
	}
	got := cfg.inetAddressEntryFor(".1.3.6.1.2.1.4.34.1.X.Y.suffix")
	require.NotNil(t, got)
	assert.Equal(t, long.OID, got.OID, "longest matching prefix must win")
}
