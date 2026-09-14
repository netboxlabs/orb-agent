package mapping

import (
	"io"
	"log/slog"
	"os"
	"strconv"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

func ptrBool(b bool) *bool { return &b }

func TestVlanMapper_MapIsNoop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	vm := NewVlanMapper(logger, config.Options{})
	got := vm.Map(nil, nil, nil, nil)
	if got != nil {
		t.Errorf("Map returned non-nil entity: %v", got)
	}
}

func TestVlanMapper_PostMap_NoVLANRows(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	vm := NewVlanMapper(logger, config.Options{})
	registry := NewEntityRegistry(logger)
	defaults := &config.Defaults{}
	got := vm.PostMap(ObjectIDValueMap{}, registry, defaults)
	if len(got) != 0 {
		t.Errorf("PostMap with empty input: got %d entities, want 0", len(got))
	}
}

func TestVlanMapper_PostMap_AccessPort_MutatesInterface(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	// Pre-populate an Interface as if InterfaceMapper had run.
	iface := &diode.Interface{Name: StringPtr("Ethernet1")}
	if registry.entities[InterfaceEntityType] == nil {
		registry.entities[InterfaceEntityType] = map[ObjectIDIndex]diode.Entity{}
	}
	registry.entities[InterfaceEntityType]["101"] = iface
	registry.MarkInterfaceVerified(iface)

	rows := buildAccessPortFixture(101, 10)

	vm := NewVlanMapper(logger, config.Options{})
	defaults := &config.Defaults{VLAN: config.VLANDefaults{Status: "active"}}
	emitted := vm.PostMap(rows, registry, defaults)

	if iface.Mode == nil || *iface.Mode != "access" {
		t.Errorf("Interface.Mode: got %v, want access", iface.Mode)
	}
	if iface.UntaggedVlan == nil || iface.UntaggedVlan.Vid == nil || *iface.UntaggedVlan.Vid != 10 {
		t.Errorf("Interface.UntaggedVlan: got %+v, want VID 10 (int64)", iface.UntaggedVlan)
	}

	vlanCount := 0
	for _, e := range emitted {
		if _, ok := e.(*diode.VLAN); ok {
			vlanCount++
		}
	}
	if vlanCount == 0 {
		t.Error("expected at least one diode.VLAN entity emitted")
	}
}

// buildAccessPortFixture constructs a minimal ObjectIDValueMap covering an
// access port with one VLAN. Mirrors the OID layout the runtime walker
// produces.
// NOTE: in this fixture, bridge port 1 maps to the given ifIndex
// (dot1dBasePortIfIndex.1 = ifIndex). The dot1qPvid OID is therefore rooted
// at bridge port 1, NOT at ifIndex. The new
// TestVlanMapper_PostMap_BridgePortIfIndexTranslation test exercises the
// non-identity case (bridge port 1 → ifIndex 101) explicitly.
func buildAccessPortFixture(ifIndex, vid int) ObjectIDValueMap {
	out := ObjectIDValueMap{}
	put := func(oid string, val string, t Asn1BER) {
		out[oid] = Value{Value: val, Type: t}
	}
	// dot1dBasePortIfIndex.1 = ifIndex  (bridge port 1 -> ifIndex)
	put(".1.3.6.1.2.1.17.1.4.1.2.1", strconv.Itoa(ifIndex), Integer)
	// dot1qPvid is indexed by dot1dBasePort (bridge port), not ifIndex.
	// In this fixture, bridge port 1 maps to the single port (ifIndex).
	put(".1.3.6.1.2.1.17.7.1.4.5.1.1.1", strconv.Itoa(vid), Integer)
	// dot1qVlanStaticName.<vid>
	put(".1.3.6.1.2.1.17.7.1.4.3.1.1."+strconv.Itoa(vid), "Eng", OctetString)
	// dot1qVlanStaticEgressPorts.<vid> = 0x80 (port 1)
	put(".1.3.6.1.2.1.17.7.1.4.3.1.2."+strconv.Itoa(vid), "\x80", OctetString)
	// dot1qVlanStaticUntaggedPorts.<vid> = 0x80
	put(".1.3.6.1.2.1.17.7.1.4.3.1.4."+strconv.Itoa(vid), "\x80", OctetString)
	// dot1qVlanStaticRowStatus.<vid> = active(1)
	put(".1.3.6.1.2.1.17.7.1.4.3.1.5."+strconv.Itoa(vid), "1", Integer)
	// ifAdminStatus.<ifIndex> = 1 (up)
	put(".1.3.6.1.2.1.2.2.1.7."+strconv.Itoa(ifIndex), "1", Integer)
	// ifType.<ifIndex> = 6 (ethernetCsmacd)
	put(".1.3.6.1.2.1.2.2.1.3."+strconv.Itoa(ifIndex), "6", Integer)
	return out
}

func TestVlanMapper_PostMap_BridgePortIfIndexTranslation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	iface := &diode.Interface{Name: StringPtr("Ethernet1")}
	if registry.entities[InterfaceEntityType] == nil {
		registry.entities[InterfaceEntityType] = map[ObjectIDIndex]diode.Entity{}
	}
	registry.entities[InterfaceEntityType]["101"] = iface
	registry.MarkInterfaceVerified(iface)

	// Build fixture with bridge port 1 -> ifIndex 101 (NON-identity).
	// PVID and membership masks are indexed by bridge port (1), NOT ifIndex.
	rows := ObjectIDValueMap{
		// dot1dBasePortIfIndex: bridge port 1 -> ifIndex 101
		".1.3.6.1.2.1.17.1.4.1.2.1": Value{Value: "101", Type: Integer},
		// dot1qPvid keyed by BRIDGE PORT (1), not ifIndex (101)
		".1.3.6.1.2.1.17.7.1.4.5.1.1.1": Value{Value: "10", Type: Integer},
		// VLAN 10 static name + status
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10": Value{Value: "Eng", Type: OctetString},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.10": Value{Value: "1", Type: Integer},
		// Egress + untagged masks for VLAN 10: bit 0 (port 1) set
		".1.3.6.1.2.1.17.7.1.4.3.1.2.10": Value{Value: "\x80", Type: OctetString},
		".1.3.6.1.2.1.17.7.1.4.3.1.4.10": Value{Value: "\x80", Type: OctetString},
		// IF-MIB ifAdminStatus + ifType for ifIndex 101
		".1.3.6.1.2.1.2.2.1.7.101": Value{Value: "1", Type: Integer},
		".1.3.6.1.2.1.2.2.1.3.101": Value{Value: "6", Type: Integer},
	}

	vm := NewVlanMapper(logger, config.Options{})
	_ = vm.PostMap(rows, registry, &config.Defaults{})

	if iface.Mode == nil || *iface.Mode != "access" {
		t.Errorf("Mode: got %v, want access; bridge-port->ifIndex translation likely failed", iface.Mode)
	}
	if iface.UntaggedVlan == nil || iface.UntaggedVlan.Vid == nil || *iface.UntaggedVlan.Vid != 10 {
		t.Errorf("UntaggedVlan.Vid: got %+v, want 10", iface.UntaggedVlan)
	}
}

func TestVlanMapper_PostMap_MissingBridgeTable_EmitsVLANsOnly(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	iface := &diode.Interface{Name: StringPtr("Ethernet1")}
	if registry.entities[InterfaceEntityType] == nil {
		registry.entities[InterfaceEntityType] = map[ObjectIDIndex]diode.Entity{}
	}
	registry.entities[InterfaceEntityType]["101"] = iface
	registry.MarkInterfaceVerified(iface)

	// VLAN static rows present, but NO dot1dBasePortIfIndex.
	rows := ObjectIDValueMap{
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10": Value{Value: "Eng", Type: OctetString},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.10": Value{Value: "1", Type: Integer},
	}

	vm := NewVlanMapper(logger, config.Options{})
	emitted := vm.PostMap(rows, registry, &config.Defaults{})

	// VLAN entity emitted.
	vlanCount := 0
	for _, e := range emitted {
		if _, ok := e.(*diode.VLAN); ok {
			vlanCount++
		}
	}
	if vlanCount != 1 {
		t.Errorf("expected 1 VLAN entity, got %d", vlanCount)
	}

	// Interface NOT mutated.
	if iface.Mode != nil {
		t.Errorf("Interface.Mode should be nil (no mutation), got %v", iface.Mode)
	}
	if iface.UntaggedVlan != nil {
		t.Errorf("Interface.UntaggedVlan should be nil (no mutation), got %+v", iface.UntaggedVlan)
	}
}

// TestVlanMapper_PostMap_AutoStubsForUnnamedAccessVlan verifies that when
// CreateUnknownVlans is true (the default), a port whose PVID references a
// VID with NO dot1qVlanStaticName row still gets a *diode.VLAN stub emitted
// and iface.UntaggedVlan linked to it. This mirrors classic Cisco IOS
// behaviour where vmVlan/dot1qPvid exposes VIDs never advertised via the
// Q-BRIDGE static table.
func TestVlanMapper_PostMap_AutoStubsForUnnamedAccessVlan(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)

	iface := &diode.Interface{Name: StringPtr("GigabitEthernet0/1")}
	if registry.entities[InterfaceEntityType] == nil {
		registry.entities[InterfaceEntityType] = map[ObjectIDIndex]diode.Entity{}
	}
	registry.entities[InterfaceEntityType]["101"] = iface
	registry.MarkInterfaceVerified(iface)

	// VID 525: PVID set (via bridge-port mapping) but NO dot1qVlanStaticName
	// row — mimics Cisco IOS where classic IOS doesn't populate Q-BRIDGE static.
	rows := ObjectIDValueMap{
		// dot1dBasePortIfIndex: bridge port 1 -> ifIndex 101
		".1.3.6.1.2.1.17.1.4.1.2.1": Value{Value: "101", Type: Integer},
		// dot1qPvid keyed by bridge port 1 -> VID 525
		".1.3.6.1.2.1.17.7.1.4.5.1.1.1": Value{Value: "525", Type: Integer},
		// Egress + untagged masks for VID 525: bit 0 (port 1) set
		".1.3.6.1.2.1.17.7.1.4.3.1.2.525": Value{Value: "\x80", Type: OctetString},
		".1.3.6.1.2.1.17.7.1.4.3.1.4.525": Value{Value: "\x80", Type: OctetString},
		// ifAdminStatus + ifType for ifIndex 101
		".1.3.6.1.2.1.2.2.1.7.101": Value{Value: "1", Type: Integer},
		".1.3.6.1.2.1.2.2.1.3.101": Value{Value: "6", Type: Integer},
		// NOTE: dot1qVlanStaticName.525 is intentionally absent.
	}

	vm := NewVlanMapper(logger, config.Options{CreateUnknownVlans: ptrBool(true)})
	emitted := vm.PostMap(rows, registry, &config.Defaults{})

	// Interface must classify as access.
	if iface.Mode == nil || *iface.Mode != "access" {
		t.Errorf("Interface.Mode: got %v, want access", iface.Mode)
	}
	// UntaggedVlan must be linked (stub was created).
	if iface.UntaggedVlan == nil || iface.UntaggedVlan.Vid == nil || *iface.UntaggedVlan.Vid != 525 {
		t.Errorf("Interface.UntaggedVlan: got %+v, want Vid=525", iface.UntaggedVlan)
	}

	// A *diode.VLAN stub for VID 525 must appear in emitted entities.
	var stub *diode.VLAN
	for _, e := range emitted {
		if v, ok := e.(*diode.VLAN); ok && v.Vid != nil && *v.Vid == 525 {
			stub = v
			break
		}
	}
	if stub == nil {
		t.Fatal("expected a *diode.VLAN stub for VID 525 in emitted entities, got none")
	}
	if stub.Name == nil || *stub.Name != "VLAN525" {
		t.Errorf("stub Name: got %v, want \"VLAN525\"", stub.Name)
	}
}

// TestVlanMapper_PostMap_CreateUnknownVlans_False verifies that when
// CreateUnknownVlans is false:
//   - VIDs with no dot1qVlanStaticName row are not emitted as VLAN entities.
//   - The interface still classifies (iface.Mode is set).
//   - iface.UntaggedVlan remains nil — operator opted out of stub creation.
func TestVlanMapper_PostMap_CreateUnknownVlans_False(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)

	// Pre-populate an interface as if InterfaceMapper had run.
	iface := &diode.Interface{Name: StringPtr("Ethernet1")}
	if registry.entities[InterfaceEntityType] == nil {
		registry.entities[InterfaceEntityType] = map[ObjectIDIndex]diode.Entity{}
	}
	registry.entities[InterfaceEntityType]["101"] = iface
	registry.MarkInterfaceVerified(iface)

	// VID 100: only RowStatus present, NO dot1qVlanStaticName row.
	// Also include an access port for ifIndex 101 / VID 100.
	rows := ObjectIDValueMap{
		// dot1dBasePortIfIndex: bridge port 1 -> ifIndex 101
		".1.3.6.1.2.1.17.1.4.1.2.1": Value{Value: "101", Type: Integer},
		// dot1qPvid (bridge port 1) -> VLAN 100
		".1.3.6.1.2.1.17.7.1.4.5.1.1.1": Value{Value: "100", Type: Integer},
		// dot1qVlanStaticRowStatus.100 = active(1) — status row present
		".1.3.6.1.2.1.17.7.1.4.3.1.5.100": Value{Value: "1", Type: Integer},
		// dot1qVlanStaticEgressPorts.100 — port 1 member
		".1.3.6.1.2.1.17.7.1.4.3.1.2.100": Value{Value: "\x80", Type: OctetString},
		// dot1qVlanStaticUntaggedPorts.100
		".1.3.6.1.2.1.17.7.1.4.3.1.4.100": Value{Value: "\x80", Type: OctetString},
		// ifAdminStatus + ifType for ifIndex 101
		".1.3.6.1.2.1.2.2.1.7.101": Value{Value: "1", Type: Integer},
		".1.3.6.1.2.1.2.2.1.3.101": Value{Value: "6", Type: Integer},
		// NOTE: dot1qVlanStaticName.100 is intentionally absent.
	}

	vm := NewVlanMapper(logger, config.Options{CreateUnknownVlans: ptrBool(false)})
	emitted := vm.PostMap(rows, registry, &config.Defaults{})

	// No VLAN entity should be emitted for VID 100 (no name row, stubs disabled).
	for _, e := range emitted {
		if v, ok := e.(*diode.VLAN); ok {
			if v.Vid != nil && *v.Vid == 100 {
				t.Errorf("unexpected VLAN entity emitted for VID 100 when create_unknown_vlans=false")
			}
		}
	}

	// Port still classifies as access even though no stub was created.
	if iface.Mode == nil || *iface.Mode != "access" {
		t.Errorf("Interface.Mode: got %v, want access (port still classifies)", iface.Mode)
	}
	// UntaggedVlan must remain nil — operator opted out of stub creation.
	if iface.UntaggedVlan != nil {
		t.Errorf("Interface.UntaggedVlan: got %+v, want nil (create_unknown_vlans=false)", iface.UntaggedVlan)
	}
}

// TestVlanMapper_EmitVLANs_AppliesDefaults confirms that Description,
// Tags, Tenant, and Group from defaults.VLAN are applied to emitted
// VLAN entities.
func TestVlanMapper_EmitVLANs_AppliesDefaults(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)

	// Minimal: one VLAN with a static name row so it will always be emitted.
	rows := ObjectIDValueMap{
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10": Value{Value: "Engineering", Type: OctetString},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.10": Value{Value: "1", Type: Integer},
	}

	defaults := &config.Defaults{
		Tags: []string{"policy-tag"},
		VLAN: config.VLANDefaults{
			Description: "auto-discovered",
			Tags:        []string{"vlan-tag"},
			Tenant:      "NetOps",
			Group:       config.VLANGroupParameters{Name: "campus-vlans"},
		},
	}

	vm := NewVlanMapper(logger, config.Options{CreateUnknownVlans: ptrBool(true)})
	emitted := vm.PostMap(rows, registry, defaults)

	var got *diode.VLAN
	for _, e := range emitted {
		if v, ok := e.(*diode.VLAN); ok && v.Vid != nil && *v.Vid == 10 {
			got = v
			break
		}
	}
	if got == nil {
		t.Fatal("expected VLAN entity for VID 10, got none")
	}
	if got.Description == nil || *got.Description != "auto-discovered" {
		t.Errorf("Description: got %v, want \"auto-discovered\"", got.Description)
	}
	// Both defaults.VLAN.Tags and defaults.Tags must appear (entity-specific first,
	// then top-level — matches the sibling mapper pattern in mappers.go).
	if len(got.Tags) != 2 {
		t.Errorf("Tags: got %d tags, want 2 (vlan-tag + policy-tag)", len(got.Tags))
	} else {
		if got.Tags[0].Name == nil || *got.Tags[0].Name != "vlan-tag" {
			t.Errorf("Tags[0].Name: got %v, want \"vlan-tag\"", got.Tags[0].Name)
		}
		if got.Tags[1].Name == nil || *got.Tags[1].Name != "policy-tag" {
			t.Errorf("Tags[1].Name: got %v, want \"policy-tag\"", got.Tags[1].Name)
		}
	}
	if got.Tenant == nil || got.Tenant.Name == nil || *got.Tenant.Name != "NetOps" {
		t.Errorf("Tenant.Name: got %v, want \"NetOps\"", got.Tenant)
	}
	if got.Group == nil || got.Group.Name == nil || *got.Group.Name != "campus-vlans" {
		t.Errorf("Group.Name: got %v, want \"campus-vlans\"", got.Group)
	}
}

// TestVlanMapper_PostMap_DeviceTenantDoesNotCascade pins the no-cascade
// design decision: the top-level defaults.tenant is device-only
// (matching device-discovery semantics) and must never leak onto
// emitted VLANs — only defaults.vlan.tenant sets a VLAN tenant.
func TestVlanMapper_PostMap_DeviceTenantDoesNotCascade(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)

	// Minimal: one VLAN with a static name row so it will always be emitted.
	rows := ObjectIDValueMap{
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10": Value{Value: "Engineering", Type: OctetString},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.10": Value{Value: "1", Type: Integer},
	}

	// Top-level device tenant set; defaults.vlan.tenant unset.
	defaults := &config.Defaults{
		Tenant: config.TenantParameters{Name: "acme", Group: "customers"},
	}

	vm := NewVlanMapper(logger, config.Options{CreateUnknownVlans: ptrBool(true)})
	emitted := vm.PostMap(rows, registry, defaults)

	var got *diode.VLAN
	for _, e := range emitted {
		if v, ok := e.(*diode.VLAN); ok && v.Vid != nil && *v.Vid == 10 {
			got = v
			break
		}
	}
	if got == nil {
		t.Fatal("expected VLAN entity for VID 10, got none")
	}
	if got.Tenant != nil {
		t.Errorf("Tenant: got %+v, want nil (top-level defaults.tenant must not cascade to VLANs)", got.Tenant)
	}
}

// TestVlanMapper_EmitVLANs_StripsNullBytesFromName verifies that NUL-padded or
// NUL-interrupted dot1qVlanStaticName values (seen on FS switches and other vendor
// agents) are sanitized before reaching the Diode payload. NetBox/PostgreSQL rejects
// NUL bytes in text fields, so an unsanitized name breaks ingestion.
func TestVlanMapper_EmitVLANs_StripsNullBytesFromName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)

	rows := ObjectIDValueMap{
		// VID 680: NUL-padded name as an FS switch reports it.
		".1.3.6.1.2.1.17.7.1.4.3.1.1.680": Value{Value: "Video\x00", Type: OctetString},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.680": Value{Value: "1", Type: Integer},
		// VID 690: name is nothing but NUL bytes — must be treated as empty
		// and fall back to the "VLAN<vid>" default rather than emitting a
		// NUL-only name.
		".1.3.6.1.2.1.17.7.1.4.3.1.1.690": Value{Value: "\x00", Type: OctetString},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.690": Value{Value: "1", Type: Integer},
		// VID 700: interior NUL (not just trailing padding) must also be
		// removed — PostgreSQL rejects a NUL anywhere in the field.
		".1.3.6.1.2.1.17.7.1.4.3.1.1.700": Value{Value: "Vo\x00IP", Type: OctetString},
		".1.3.6.1.2.1.17.7.1.4.3.1.5.700": Value{Value: "1", Type: Integer},
	}

	vm := NewVlanMapper(logger, config.Options{CreateUnknownVlans: ptrBool(true)})
	emitted := vm.PostMap(rows, registry, &config.Defaults{})

	byVid := map[int64]*diode.VLAN{}
	for _, e := range emitted {
		if v, ok := e.(*diode.VLAN); ok && v.Vid != nil {
			byVid[*v.Vid] = v
		}
	}

	got, ok := byVid[680]
	if !ok || got.Name == nil {
		t.Fatal("expected VLAN entity for VID 680 with a name")
	}
	if *got.Name != "Video" {
		t.Errorf("VID 680 Name: got %q, want %q", *got.Name, "Video")
	}

	stub, ok := byVid[690]
	if !ok || stub.Name == nil {
		t.Fatal("expected VLAN entity for VID 690 with a name")
	}
	if *stub.Name != "VLAN690" {
		t.Errorf("VID 690 Name: got %q, want %q (NUL-only name should be empty)", *stub.Name, "VLAN690")
	}

	interior, ok := byVid[700]
	if !ok || interior.Name == nil {
		t.Fatal("expected VLAN entity for VID 700 with a name")
	}
	if *interior.Name != "VoIP" {
		t.Errorf("VID 700 Name: got %q, want %q (interior NUL must be removed)", *interior.Name, "VoIP")
	}
}

// applyVLANDefaults: when defaults.Site is a real value and a VLAN Group is
// configured, the Group must carry Name + Slug + Scope = Site{Name: defaults.Site}.
func TestApplyVLANDefaults_GroupScopeSite_WhenSiteDefined(t *testing.T) {
	v := &diode.VLAN{}
	defaults := &config.Defaults{
		Site: "NYC",
		VLAN: config.VLANDefaults{Group: config.VLANGroupParameters{Name: "Lab VLAN Group"}},
	}

	applyVLANDefaults(v, defaults)

	if v.Group == nil {
		t.Fatal("Group: got nil, want non-nil")
	}
	if v.Group.Name == nil || *v.Group.Name != "Lab VLAN Group" {
		t.Errorf("Group.Name: got %v, want \"Lab VLAN Group\"", v.Group.Name)
	}
	if v.Group.Slug == nil || *v.Group.Slug != "lab-vlan-group" {
		t.Errorf("Group.Slug: got %v, want \"lab-vlan-group\"", v.Group.Slug)
	}
	site, ok := v.Group.Scope.(*diode.Site)
	if !ok {
		t.Fatalf("Group.Scope: got %T, want *diode.Site", v.Group.Scope)
	}
	if site.Name == nil || *site.Name != "NYC" {
		t.Errorf("Group.Scope.Site.Name: got %v, want \"NYC\"", site.Name)
	}
}

// applyVLANDefaults: when defaults.Site is the sentinel "undefined" string,
// scope_site is still populated (the value "undefined" is treated like any
// other site name so the scoped-slug dedup path keeps working).
func TestApplyVLANDefaults_GroupScopeSite_WhenSiteUndefined(t *testing.T) {
	v := &diode.VLAN{}
	defaults := &config.Defaults{
		Site: "undefined",
		VLAN: config.VLANDefaults{Group: config.VLANGroupParameters{Name: "campus-vlans"}},
	}

	applyVLANDefaults(v, defaults)

	if v.Group == nil {
		t.Fatal("Group: got nil, want non-nil")
	}
	if v.Group.Slug == nil || *v.Group.Slug != "campus-vlans" {
		t.Errorf("Group.Slug: got %v, want \"campus-vlans\"", v.Group.Slug)
	}
	site, ok := v.Group.Scope.(*diode.Site)
	if !ok {
		t.Fatalf("Group.Scope: got %T, want *diode.Site", v.Group.Scope)
	}
	if site.Name == nil || *site.Name != "undefined" {
		t.Errorf("Group.Scope.Site.Name: got %v, want \"undefined\"", site.Name)
	}
}

// applyVLANDefaults: when defaults.Site is empty, the Group must still carry
// Slug but no scope_site.
func TestApplyVLANDefaults_GroupNoScopeSite_WhenSiteEmpty(t *testing.T) {
	v := &diode.VLAN{}
	defaults := &config.Defaults{
		VLAN: config.VLANDefaults{Group: config.VLANGroupParameters{Name: "campus-vlans"}},
	}

	applyVLANDefaults(v, defaults)

	if v.Group == nil {
		t.Fatal("Group: got nil, want non-nil")
	}
	if v.Group.Slug == nil || *v.Group.Slug != "campus-vlans" {
		t.Errorf("Group.Slug: got %v, want \"campus-vlans\"", v.Group.Slug)
	}
	if v.Group.Scope != nil {
		t.Errorf("Group.Scope: got %v, want nil (site is empty)", v.Group.Scope)
	}
}

// applyVLANDefaults: when no VLAN Group default is set, defaults.Site must not
// synthesize a Group out of thin air.
func TestApplyVLANDefaults_NoGroup_SiteIgnored(t *testing.T) {
	v := &diode.VLAN{}
	defaults := &config.Defaults{
		Site: "NYC",
		VLAN: config.VLANDefaults{},
	}

	applyVLANDefaults(v, defaults)

	if v.Group != nil {
		t.Errorf("Group: got %v, want nil (no group configured)", v.Group)
	}
}

// buildCiscoSBFixture models a Cisco Catalyst 1200 as reported in issue #482:
// dot1qPvid answers 1 for the port even though it is really on accessVid, the
// per-VLAN egress/untagged masks come back empty, and the private CISCOSB
// column carries the real VLAN keyed by ifIndex.
func buildCiscoSBFixture(ifIndex, accessVid int) ObjectIDValueMap {
	out := ObjectIDValueMap{}
	put := func(oid, val string, t Asn1BER) { out[oid] = Value{Value: val, Type: t} }
	idx := strconv.Itoa(ifIndex)
	vid := strconv.Itoa(accessVid)

	put(".1.3.6.1.2.1.17.1.4.1.2."+idx, idx, Integer)     // bridge port -> ifIndex
	put(".1.3.6.1.2.1.17.7.1.4.5.1.1."+idx, "1", Integer) // the platform's wrong PVID
	put(".1.3.6.1.2.1.2.2.1.7."+idx, "1", Integer)
	put(".1.3.6.1.2.1.2.2.1.3."+idx, "6", Integer)

	// The VLAN exists in the static table but its port masks are all zero.
	put(".1.3.6.1.2.1.17.7.1.4.3.1.1."+vid, "vlan"+vid, OctetString)
	put(".1.3.6.1.2.1.17.7.1.4.3.1.2."+vid, string(make([]byte, 126)), OctetString)
	put(".1.3.6.1.2.1.17.7.1.4.3.1.4."+vid, string(make([]byte, 126)), OctetString)
	put(".1.3.6.1.2.1.17.7.1.4.3.1.5."+vid, "1", Integer)

	put(".1.3.6.1.4.1.9.6.1.101.48.62.1.1."+idx, vid, Integer)
	return out
}

func newVlanTestRegistry(t *testing.T, ifIndex int, name string) (*EntityRegistry, *diode.Interface) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	iface := &diode.Interface{Name: StringPtr(name)}
	if registry.entities[InterfaceEntityType] == nil {
		registry.entities[InterfaceEntityType] = map[ObjectIDIndex]diode.Entity{}
	}
	registry.entities[InterfaceEntityType][ObjectIDIndex(strconv.Itoa(ifIndex))] = iface
	registry.MarkInterfaceVerified(iface)
	return registry, iface
}

// Issue #482: the port must land on the VLAN the private column reports, not on
// the 1 that dot1qPvid claims.
func TestVlanMapper_PostMap_CiscoSB_OverridesWrongPvid(t *testing.T) {
	registry, iface := newVlanTestRegistry(t, 2, "gi2")
	NewVlanMapper(slog.New(slog.NewTextHandler(os.Stderr, nil)), config.Options{}).
		PostMap(buildCiscoSBFixture(2, 2137), registry,
			&config.Defaults{VLAN: config.VLANDefaults{Status: "active"}})

	if iface.Mode == nil || *iface.Mode != "access" {
		t.Fatalf("Interface.Mode: got %v, want access", iface.Mode)
	}
	if iface.UntaggedVlan == nil || iface.UntaggedVlan.Vid == nil {
		t.Fatalf("Interface.UntaggedVlan: got %+v, want VID 2137", iface.UntaggedVlan)
	}
	if got := *iface.UntaggedVlan.Vid; got != 2137 {
		t.Fatalf("UntaggedVlan.Vid: got %d, want 2137 (dot1qPvid's 1 must not win)", got)
	}
}

// Non-CISCOSB Cisco gear is walked for these OIDs too, so a host that does not
// answer them must classify exactly as before.
func TestVlanMapper_PostMap_CiscoSB_AbsentLeavesGenericBehaviour(t *testing.T) {
	registry, iface := newVlanTestRegistry(t, 101, "Ethernet1")
	NewVlanMapper(slog.New(slog.NewTextHandler(os.Stderr, nil)), config.Options{}).
		PostMap(buildAccessPortFixture(101, 10), registry,
			&config.Defaults{VLAN: config.VLANDefaults{Status: "active"}})

	if iface.UntaggedVlan == nil || iface.UntaggedVlan.Vid == nil || *iface.UntaggedVlan.Vid != 10 {
		t.Fatalf("Interface.UntaggedVlan: got %+v, want VID 10", iface.UntaggedVlan)
	}
}

// A port the bridge-port table omits stays untouched even when CISCOSB reports
// a VLAN for it: the overlay refines ports, it does not create them.
func TestVlanMapper_PostMap_CiscoSB_DoesNotCreatePorts(t *testing.T) {
	registry, bridged := newVlanTestRegistry(t, 2, "gi2")
	omitted := &diode.Interface{Name: StringPtr("gi3")}
	registry.entities[InterfaceEntityType]["3"] = omitted
	registry.MarkInterfaceVerified(omitted)

	rows := buildCiscoSBFixture(2, 2137)
	rows[".1.3.6.1.2.1.2.2.1.7.3"] = Value{Value: "1", Type: Integer}
	rows[".1.3.6.1.2.1.2.2.1.3.3"] = Value{Value: "6", Type: Integer}
	rows[".1.3.6.1.4.1.9.6.1.101.48.62.1.1.3"] = Value{Value: "999", Type: Integer}

	NewVlanMapper(slog.New(slog.NewTextHandler(os.Stderr, nil)), config.Options{}).
		PostMap(rows, registry, &config.Defaults{VLAN: config.VLANDefaults{Status: "active"}})

	if bridged.UntaggedVlan == nil || *bridged.UntaggedVlan.Vid != 2137 {
		t.Fatalf("bridged port: got %+v, want 2137", bridged.UntaggedVlan)
	}
	if omitted.Mode != nil || omitted.UntaggedVlan != nil {
		t.Fatalf("port omitted from the bridge table was mutated: mode=%v untagged=%+v",
			omitted.Mode, omitted.UntaggedVlan)
	}
}

// The two private columns are not interchangeable. An access column that
// explicitly reports VLAN 1 is evidence, because the operator configured it;
// the trunk-native column reading 1 is the factory default and is ignored on an
// access port. Parsing one into the other's map would silently swap the rules.
func TestVlanMapper_PostMap_CiscoSB_AccessAndNativeColumnsAreDistinct(t *testing.T) {
	for _, tc := range []struct {
		name         string
		oid          string
		wantUntagged int64
	}{
		// The access column naming VLAN 1 overrides the generic PVID of 50.
		{"access column", ".1.3.6.1.4.1.9.6.1.101.48.62.1.1.2", 1},
		// The native column naming VLAN 1 is indistinguishable from unset on an
		// access port, so the generic value stands.
		{"native column", ".1.3.6.1.4.1.9.6.1.101.48.61.1.1.2", 50},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry, iface := newVlanTestRegistry(t, 2, "gi2")
			rows := ObjectIDValueMap{
				".1.3.6.1.2.1.17.1.4.1.2.2":      Value{Value: "2", Type: Integer},
				".1.3.6.1.2.1.17.7.1.4.5.1.1.2":  Value{Value: "50", Type: Integer},
				".1.3.6.1.2.1.17.7.1.4.3.1.1.50": Value{Value: "vlan50", Type: OctetString},
				".1.3.6.1.2.1.17.7.1.4.3.1.5.50": Value{Value: "1", Type: Integer},
				".1.3.6.1.2.1.2.2.1.7.2":         Value{Value: "1", Type: Integer},
				".1.3.6.1.2.1.2.2.1.3.2":         Value{Value: "6", Type: Integer},
				tc.oid:                           Value{Value: "1", Type: Integer},
			}
			NewVlanMapper(slog.New(slog.NewTextHandler(os.Stderr, nil)), config.Options{}).
				PostMap(rows, registry, &config.Defaults{VLAN: config.VLANDefaults{Status: "active"}})

			if iface.UntaggedVlan == nil || iface.UntaggedVlan.Vid == nil {
				t.Fatalf("UntaggedVlan: got %+v, want VID %d", iface.UntaggedVlan, tc.wantUntagged)
			}
			if got := *iface.UntaggedVlan.Vid; got != tc.wantUntagged {
				t.Fatalf("UntaggedVlan.Vid: got %d, want %d", got, tc.wantUntagged)
			}
		})
	}
}

func TestEmitVLANs_ReadsVtpVlanNameWhenDot1qAbsent(t *testing.T) {
	// A device that publishes its VLAN database only through CISCO-VTP-MIB.
	oids := ObjectIDValueMap{
		".1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.10":  {Value: "office"},
		".1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.20":  {Value: "voice"},
		".1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.999": {Value: "engineering"},
		// Out of range: must be dropped by the existing 1..4094 filter.
		".1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.4095": {Value: "too-high"},
		".1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.0":    {Value: "too-low"},
	}
	m := NewVlanMapper(slog.Default(), config.Options{})
	got := map[int]string{}
	for _, e := range m.emitVLANs(oids, nil) {
		v, ok := e.(*diode.VLAN)
		require.True(t, ok)
		got[int(*v.Vid)] = *v.Name
	}
	assert.Equal(t, map[int]string{10: "office", 20: "voice", 999: "engineering"}, got,
		"VTP names produce VLAN entities; 4095 and 0 are outside 1..4094 and must be dropped")
}

// mergeVLANNames takes an ordered slice precisely so its precedence can be
// pinned against every arrival order, rather than against whichever order
// Go's randomised map iteration happens to produce on the day. Each case is
// run against every permutation of its own rows, so both of the orders that
// used to diverge are exercised on every run.
func TestMergeVLANNames_ResolvesTheSameNameInEveryArrivalOrder(t *testing.T) {
	const (
		dot1q10   = ".1.3.6.1.2.1.17.7.1.4.3.1.1.10"
		vtpDom1   = ".1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.10"
		vtpDom2   = ".1.3.6.1.4.1.9.9.46.1.3.1.1.4.2.10"
		nulPadded = "\x00\x00\x00"
	)
	cases := []struct {
		name string
		rows []vlanNameRow
		want map[int]string
	}{
		{
			// The flapping case: NUL padding collapses the dot1q name to
			// "", so the VTP name is the only one the device supplied.
			name: "an empty dot1q name never erases the vtp name",
			rows: []vlanNameRow{
				{oid: dot1q10, value: nulPadded},
				{oid: vtpDom1, value: "office"},
			},
			want: map[int]string{10: "office"},
		},
		{
			name: "a populated dot1q name always wins over vtp",
			rows: []vlanNameRow{
				{oid: dot1q10, value: "from-dot1q"},
				{oid: vtpDom1, value: "from-vtp"},
			},
			want: map[int]string{10: "from-dot1q"},
		},
		{
			// Two management domains listing the same VID: the populated
			// row wins either way round.
			name: "an empty vtp row never erases a populated one",
			rows: []vlanNameRow{
				{oid: vtpDom1, value: "office"},
				{oid: vtpDom2, value: nulPadded},
			},
			want: map[int]string{10: "office"},
		},
		{
			name: "two nameless rows leave the vid nameless",
			rows: []vlanNameRow{
				{oid: dot1q10, value: " "},
				{oid: vtpDom1, value: nulPadded},
			},
			want: map[int]string{10: ""},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orders := permuteVLANNameRows(tc.rows)
			require.Len(t, orders, 2, "both arrival orders must be exercised")
			for _, order := range orders {
				assert.Equal(t, tc.want, mergeVLANNames(order, nil),
					"arrival order %v", oidsOfRows(order))
			}
		})
	}
}

// permuteVLANNameRows returns every ordering of rows. The cases above are
// pairs, so this enumerates both arrival orders exhaustively rather than
// sampling whichever one a map iteration yields.
func permuteVLANNameRows(rows []vlanNameRow) [][]vlanNameRow {
	if len(rows) <= 1 {
		return [][]vlanNameRow{append([]vlanNameRow(nil), rows...)}
	}
	var out [][]vlanNameRow
	for i := range rows {
		rest := make([]vlanNameRow, 0, len(rows)-1)
		rest = append(rest, rows[:i]...)
		rest = append(rest, rows[i+1:]...)
		for _, tail := range permuteVLANNameRows(rest) {
			out = append(out, append([]vlanNameRow{rows[i]}, tail...))
		}
	}
	return out
}

func oidsOfRows(rows []vlanNameRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.oid)
	}
	return out
}

// A NUL-padded dot1qVlanStaticName collapses to "", which is not a name
// the device supplied — the VTP catalog is the only place that VID is
// named, and that name must survive whichever row is visited first.
// mergeVLANNames is pinned against both orders explicitly above; this
// case covers the map-level entry point.
func TestEmitVLANs_VtpNameSurvivesAnEmptyDot1qName(t *testing.T) {
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10":     {Value: "\x00\x00\x00"},
		".1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.10": {Value: "office"},
	}
	m := NewVlanMapper(slog.Default(), config.Options{})
	ents := m.emitVLANs(oids, nil)
	require.Len(t, ents, 1)
	assert.Equal(t, "office", *ents[0].(*diode.VLAN).Name,
		"an empty dot1q name must not erase the VTP name, nor fall through to the VLAN<vid> default")
}

func TestEmitVLANs_Dot1qWinsOverVtpForTheSameVid(t *testing.T) {
	// Both MIBs are disjoint across every device measured, but if one ever
	// reports both, the standard MIB is authoritative.
	oids := ObjectIDValueMap{
		".1.3.6.1.2.1.17.7.1.4.3.1.1.10":     {Value: "from-dot1q"},
		".1.3.6.1.4.1.9.9.46.1.3.1.1.4.1.10": {Value: "from-vtp"},
	}
	m := NewVlanMapper(slog.Default(), config.Options{})
	ents := m.emitVLANs(oids, nil)
	require.Len(t, ents, 1)
	assert.Equal(t, "from-dot1q", *ents[0].(*diode.VLAN).Name)
}

// applyVLANDefaults: the map form of vlan.group picks the scope NetBox
// attaches the group to. An explicit scope wins over defaults.site; a map
// without one falls back to defaults.site like the string form.
func TestApplyVLANDefaults_GroupExplicitScope(t *testing.T) {
	tests := []struct {
		name  string
		group config.VLANGroupParameters
		check func(t *testing.T, scope any)
	}{
		{"site group", config.VLANGroupParameters{Name: "g", ScopeSiteGroup: "Brussels"}, func(t *testing.T, scope any) {
			sg, ok := scope.(*diode.SiteGroup)
			if !ok {
				t.Fatalf("scope: got %T, want *diode.SiteGroup", scope)
			}
			if sg.Name == nil || *sg.Name != "Brussels" {
				t.Errorf("SiteGroup.Name: got %v, want Brussels", sg.Name)
			}
		}},
		{"region", config.VLANGroupParameters{Name: "g", ScopeRegion: "Benelux"}, func(t *testing.T, scope any) {
			r, ok := scope.(*diode.Region)
			if !ok {
				t.Fatalf("scope: got %T, want *diode.Region", scope)
			}
			if r.Name == nil || *r.Name != "Benelux" {
				t.Errorf("Region.Name: got %v, want Benelux", r.Name)
			}
		}},
		{"explicit site overrides defaults.site", config.VLANGroupParameters{Name: "g", ScopeSite: "other"}, func(t *testing.T, scope any) {
			s, ok := scope.(*diode.Site)
			if !ok {
				t.Fatalf("scope: got %T, want *diode.Site", scope)
			}
			if s.Name == nil || *s.Name != "other" {
				t.Errorf("Site.Name: got %v, want other", s.Name)
			}
		}},
		{"location carries defaults.site", config.VLANGroupParameters{Name: "g", ScopeLocation: "Floor 2"}, func(t *testing.T, scope any) {
			l, ok := scope.(*diode.Location)
			if !ok {
				t.Fatalf("scope: got %T, want *diode.Location", scope)
			}
			if l.Name == nil || *l.Name != "Floor 2" {
				t.Errorf("Location.Name: got %v, want Floor 2", l.Name)
			}
			if l.Site == nil || l.Site.Name == nil || *l.Site.Name != "NYC" {
				t.Errorf("Location.Site: got %v, want NYC", l.Site)
			}
		}},
		{"map without scope falls back to defaults.site", config.VLANGroupParameters{Name: "g"}, func(t *testing.T, scope any) {
			s, ok := scope.(*diode.Site)
			if !ok {
				t.Fatalf("scope: got %T, want *diode.Site", scope)
			}
			if s.Name == nil || *s.Name != "NYC" {
				t.Errorf("Site.Name: got %v, want NYC", s.Name)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &diode.VLAN{}
			applyVLANDefaults(v, &config.Defaults{Site: "NYC", VLAN: config.VLANDefaults{Group: tt.group}})
			if v.Group == nil {
				t.Fatal("Group: got nil, want non-nil")
			}
			if v.Group.Slug == nil || *v.Group.Slug != "g" {
				t.Errorf("Group.Slug: got %v, want g", v.Group.Slug)
			}
			tt.check(t, v.Group.Scope)
		})
	}
}

// A location scope with no site anywhere is still emitted; NetBox rejects
// it rather than the agent guessing a site.
func TestApplyVLANDefaults_GroupLocationWithoutSite(t *testing.T) {
	v := &diode.VLAN{}
	applyVLANDefaults(v, &config.Defaults{VLAN: config.VLANDefaults{Group: config.VLANGroupParameters{Name: "g", ScopeLocation: "Floor 2"}}})
	l, ok := v.Group.Scope.(*diode.Location)
	if !ok {
		t.Fatalf("scope: got %T, want *diode.Location", v.Group.Scope)
	}
	if l.Site != nil {
		t.Errorf("Location.Site: got %v, want nil", l.Site)
	}
}

// TestVlanMapper_PostMap_BridgeWithoutVlanFilteringEmitsNoVlan is the reported
// shape end to end: a bridge whose VLAN filtering is off, which answers the
// bridge port table and dot1qPvid but publishes no Q-BRIDGE VLAN tables at all.
//
// Every port reports the MIB's default PVID of 1. Read as configuration that
// made eleven access ports on a VLAN 1 the device never had, and fabricated the
// VLAN to attach them to.
func TestVlanMapper_PostMap_BridgeWithoutVlanFilteringEmitsNoVlan(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)

	names := map[int]string{}
	for i := range 11 {
		names[100+i] = "sfp" + strconv.Itoa(i+2)
	}
	ifaces := interfacesFor(registry, names)

	all := ObjectIDValueMap{}
	for i := range 11 {
		bp, ifIndex := strconv.Itoa(i+1), strconv.Itoa(100+i)
		all[oidDot1dBasePortIfIndex+bp] = Value{Value: ifIndex}
		all[oidDot1qPvid+bp] = Value{Value: "1"}
		all[oidIfAdminStatus+ifIndex] = Value{Value: "1"}
		all[oidIfType+ifIndex] = Value{Value: "6"}
	}
	// No dot1qVlanStaticTable, no VTP catalog: the device names no VLAN.

	vm := NewVlanMapper(logger, config.Options{})
	entities := vm.PostMap(all, registry, &config.Defaults{})

	for _, e := range entities {
		if v, ok := e.(*diode.VLAN); ok && v != nil && v.Vid != nil {
			t.Errorf("no VLAN may be emitted for a device that named none, got vid %d", *v.Vid)
		}
	}
	for ifIndex, iface := range ifaces {
		if iface.Mode != nil {
			t.Errorf("%s: mode %q written from the MIB default alone", names[ifIndex], *iface.Mode)
		}
		if iface.UntaggedVlan != nil {
			t.Errorf("%s: untagged VLAN attached from the MIB default alone", names[ifIndex])
		}
	}
}

// The same walk with one VLAN named by the device classifies as before: the
// refusal is about having no catalog, not about the value 1.
func TestVlanMapper_PostMap_DefaultPvidClassifiesOnceTheDeviceNamesAVlan(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	ifaces := interfacesFor(registry, map[int]string{100: "sfp2"})

	all := ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1": {Value: "100"},
		oidDot1qPvid + "1":            {Value: "1"},
		oidIfAdminStatus + "100":      {Value: "1"},
		oidIfType + "100":             {Value: "6"},
		oidDot1qVlanStaticName + "1":  {Value: "default"},
	}

	vm := NewVlanMapper(logger, config.Options{})
	vm.PostMap(all, registry, &config.Defaults{})

	iface := ifaces[100]
	if iface.Mode == nil || *iface.Mode != "access" {
		t.Errorf("mode: got %v, want access", iface.Mode)
	}
	if iface.UntaggedVlan == nil || iface.UntaggedVlan.Vid == nil || *iface.UntaggedVlan.Vid != 1 {
		t.Errorf("untagged: got %+v, want VLAN 1", iface.UntaggedVlan)
	}
}

// TestVlanMapper_PostMap_CurrentTableSuppliesMembershipTheStaticTableOmits is
// the reported Eltex shape: port-channels the switch runs as untagged members
// of VLAN 1, where VLAN 1 has no dot1qVlanStaticTable row and the port-channels
// have no dot1qPvid row either. The only place that membership appears is
// dot1qVlanCurrentTable, which was not walked.
func TestVlanMapper_PostMap_CurrentTableSuppliesMembershipTheStaticTableOmits(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	ifaces := interfacesFor(registry, map[int]string{1000: "Po1", 1001: "Po2", 105: "te1/0/1"})

	// The device's own index space: bridge ports 1000/1001 are the LAGs.
	all := ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1000": {Value: "1000"},
		oidDot1dBasePortIfIndex + "1001": {Value: "1001"},
		oidDot1dBasePortIfIndex + "105":  {Value: "105"},
		oidIfAdminStatus + "1000":        {Value: "1"},
		oidIfAdminStatus + "1001":        {Value: "1"},
		oidIfAdminStatus + "105":         {Value: "1"},
		oidIfType + "1000":               {Value: "161"},
		oidIfType + "1001":               {Value: "161"},
		oidIfType + "105":                {Value: "6"},
		// The static table knows only VLAN 151, tagged on te1/0/1.
		oidDot1qVlanStaticName + "151":        {Value: "UPLINK"},
		oidDot1qVlanStaticEgressPorts + "151": {Value: portMask(105)},
		// VLAN 1 exists only in the current table, with the LAGs untagged in
		// it. Index is <timemark>.<vid>.
		oidDot1qVlanCurrentEgressPorts + "0.1":   {Value: portMask(1000, 1001)},
		oidDot1qVlanCurrentUntaggedPorts + "0.1": {Value: portMask(1000, 1001)},
	}

	vm := NewVlanMapper(logger, config.Options{})
	vm.PostMap(all, registry, &config.Defaults{})

	for _, name := range []string{"Po1", "Po2"} {
		var iface *diode.Interface
		for ifIndex, i := range ifaces {
			if names := map[int]string{1000: "Po1", 1001: "Po2", 105: "te1/0/1"}; names[ifIndex] == name {
				iface = i
			}
		}
		if iface == nil {
			t.Fatalf("%s missing", name)
		}
		if iface.Mode == nil || *iface.Mode != "access" {
			t.Errorf("%s mode: got %v, want access", name, iface.Mode)
		}
		if iface.UntaggedVlan == nil || iface.UntaggedVlan.Vid == nil || *iface.UntaggedVlan.Vid != 1 {
			t.Errorf("%s untagged: got %+v, want VLAN 1", name, iface.UntaggedVlan)
		}
	}
	// The static table still wins where it speaks.
	if got := ifaces[105]; got.Mode == nil || *got.Mode != "tagged" {
		t.Errorf("te1/0/1 mode: got %v, want tagged", got.Mode)
	}
}

// The two-element index is the trap: reading the first element would take the
// time mark, which is 0 and not a VLAN, discarding every row.
func TestCurrentVlanRow_ReadsTheSecondIndexElement(t *testing.T) {
	for _, tc := range []struct {
		oid       string
		vid, mark int
		ok        bool
	}{
		{oidDot1qVlanCurrentEgressPorts + "0.1", 1, 0, true},
		{oidDot1qVlanCurrentEgressPorts + "12345.151", 151, 12345, true},
		{oidDot1qVlanCurrentEgressPorts + "1", 0, 0, false},
		{oidDot1qVlanCurrentEgressPorts + "0.x", 0, 0, false},
		{oidDot1qVlanCurrentEgressPorts + "x.1", 0, 0, false},
	} {
		vid, mark, ok := currentVlanRow(tc.oid, oidDot1qVlanCurrentEgressPorts)
		if vid != tc.vid || mark != tc.mark || ok != tc.ok {
			t.Errorf("%s: got (%d,%d,%v), want (%d,%d,%v)", tc.oid, vid, mark, ok, tc.vid, tc.mark, tc.ok)
		}
	}
}

// portMask builds a Q-BRIDGE PortList bitmap with the given bridge ports set,
// the same bit order the MIB defines: port 1 is the high bit of octet 0.
func portMask(ports ...int) string {
	maxPort := 0
	for _, p := range ports {
		if p > maxPort {
			maxPort = p
		}
	}
	mask := make([]byte, (maxPort+7)/8)
	for _, p := range ports {
		mask[(p-1)/8] |= 1 << (7 - (p-1)%8)
	}
	return string(mask)
}

// The static table is the configured intent and wins wherever it speaks. The
// current table reflects what is running, which can include VLANs learned
// dynamically, so it fills gaps rather than overriding.
func TestVlanMapper_BuildGenericRows_StaticMasksWinOverCurrent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	vm := NewVlanMapper(logger, config.Options{})

	rows := vm.buildGenericRows(ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1": {Value: "101"},
		// VLAN 10 is in both tables, with different members.
		oidDot1qVlanStaticEgressPorts + "10":    {Value: portMask(1)},
		oidDot1qVlanCurrentEgressPorts + "0.10": {Value: portMask(2)},
		// VLAN 20 is only in the current table.
		oidDot1qVlanCurrentEgressPorts + "0.20": {Value: portMask(3)},
	})

	if got, want := rows.VlanEgressPorts[10], portMask(1); string(got) != want {
		t.Errorf("VLAN 10: got %x, want the static mask %x", got, want)
	}
	if got, want := rows.VlanEgressPorts[20], portMask(3); string(got) != want {
		t.Errorf("VLAN 20: got %x, want the current mask %x", got, want)
	}
}

// A device whose only VLAN table is the current one is not a device that named
// no VLAN. It is classified from that membership, and never reaches the
// default-PVID refusal — which matters because its PVIDs are all the default,
// so without the current table it would be silenced entirely.
func TestVlanMapper_PostMap_CurrentTableOnlyDeviceIsNotRefused(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	ifaces := interfacesFor(registry, map[int]string{101: "gi1", 102: "gi2"})

	all := ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1": {Value: "101"},
		oidDot1dBasePortIfIndex + "2": {Value: "102"},
		oidIfAdminStatus + "101":      {Value: "1"},
		oidIfAdminStatus + "102":      {Value: "1"},
		oidIfType + "101":             {Value: "6"},
		oidIfType + "102":             {Value: "6"},
		// Every PVID is the MIB default: on its own this is the refused shape.
		oidDot1qPvid + "1": {Value: "1"},
		oidDot1qPvid + "2": {Value: "1"},
		// But the device does say which VLANs it runs and who is in them.
		oidDot1qVlanCurrentEgressPorts + "0.1":   {Value: portMask(1, 2)},
		oidDot1qVlanCurrentUntaggedPorts + "0.1": {Value: portMask(1, 2)},
	}

	// Decided from the snapshot the merge resolved, not from the walked rows.
	vmRows := NewVlanMapper(logger, config.Options{}).buildGenericRows(all)
	if !vmRows.VlanCatalogPresent {
		t.Fatal("the current table is VLAN knowledge; the refusal must not apply")
	}

	vm := NewVlanMapper(logger, config.Options{})
	vm.PostMap(all, registry, &config.Defaults{})

	for name, iface := range map[string]*diode.Interface{"gi1": ifaces[101], "gi2": ifaces[102]} {
		if iface.Mode == nil || *iface.Mode != "access" {
			t.Errorf("%s mode: got %v, want access", name, iface.Mode)
		}
		if iface.UntaggedVlan == nil || iface.UntaggedVlan.Vid == nil || *iface.UntaggedVlan.Vid != 1 {
			t.Errorf("%s untagged: got %+v, want VLAN 1", name, iface.UntaggedVlan)
		}
	}
}

// TestVlanMapper_BuildGenericRows_LatestTimeMarkWins is the determinism the
// table's index demands.
//
// dot1qVlanCurrentTable is INDEX { dot1qVlanTimeMark, dot1qVlanIndex }, so one
// VLAN is answered once per mark the agent still holds, with different masks.
// Taking whichever the walk map yielded made the result depend on Go's map
// iteration order: a real D-Link answering VLAN 1 under two marks alternated
// between two NetBox states on every poll, with Diode rewriting mode and
// tagged VLANs each way.
func TestVlanMapper_BuildGenericRows_LatestTimeMarkWins(t *testing.T) {
	vm := NewVlanMapper(slog.New(slog.NewTextHandler(os.Stderr, nil)), config.Options{})

	all := ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1": {Value: "101"},
		// The same VLAN under two marks, oldest last in source order.
		oidDot1qVlanCurrentEgressPorts + "2831.1": {Value: portMask(1, 2, 3, 4)},
		oidDot1qVlanCurrentEgressPorts + "2828.1": {Value: portMask(4)},
	}

	// Repeated because the defect was map-iteration order: one pass could
	// pass by luck.
	want := portMask(1, 2, 3, 4)
	for i := range 50 {
		if got := string(vm.buildGenericRows(all).VlanEgressPorts[1]); got != want {
			t.Fatalf("run %d: got %x, want the highest time mark's mask %x", i, got, want)
		}
	}
}

// A VLAN the current table mentions but places nobody in is not membership,
// and merging it is not harmless: an empty untagged row is still a row, and
// the generic extractor reads the presence of one for a port's PVID as "the
// device publishes an untagged table for that VLAN and left this port out",
// withdrawing the port's PVID. A ProCurve publishing six all-zero VLANs beside
// 23 ports with real PVIDs lost every one of them that way.
func TestVlanMapper_PostMap_AnEmptyCurrentVlanDoesNotWithdrawAPvid(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	ifaces := interfacesFor(registry, map[int]string{101: "gi1", 102: "gi2"})

	all := ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1": {Value: "101"},
		oidDot1dBasePortIfIndex + "2": {Value: "102"},
		oidIfAdminStatus + "101":      {Value: "1"},
		oidIfAdminStatus + "102":      {Value: "1"},
		oidIfType + "101":             {Value: "6"},
		oidIfType + "102":             {Value: "6"},
		// Real, operator-set PVIDs.
		oidDot1qPvid + "1": {Value: "22"},
		oidDot1qPvid + "2": {Value: "72"},
		// The current table names those VLANs and puts no port in them.
		oidDot1qVlanCurrentEgressPorts + "0.22":   {Value: string(make([]byte, 8))},
		oidDot1qVlanCurrentUntaggedPorts + "0.22": {Value: string(make([]byte, 8))},
		oidDot1qVlanCurrentEgressPorts + "0.72":   {Value: string(make([]byte, 8))},
		oidDot1qVlanCurrentUntaggedPorts + "0.72": {Value: string(make([]byte, 8))},
	}

	vm := NewVlanMapper(logger, config.Options{})
	vm.PostMap(all, registry, &config.Defaults{})

	for name, want := range map[string]int64{"gi1": 22, "gi2": 72} {
		iface := ifaces[101]
		if name == "gi2" {
			iface = ifaces[102]
		}
		if iface.Mode == nil || *iface.Mode != "access" {
			t.Errorf("%s mode: got %v, want access", name, iface.Mode)
		}
		if iface.UntaggedVlan == nil || iface.UntaggedVlan.Vid == nil || *iface.UntaggedVlan.Vid != want {
			t.Errorf("%s untagged: got %+v, want VLAN %d", name, iface.UntaggedVlan, want)
		}
	}
}

// An all-zero untagged mask beside a populated egress mask is meaningful: it is
// how a VLAN every member carries tagged reports. Only the pair being empty
// says the VLAN merely exists.
func TestVlanMapper_BuildGenericRows_AnAllTaggedCurrentVlanIsStillMembership(t *testing.T) {
	vm := NewVlanMapper(slog.New(slog.NewTextHandler(os.Stderr, nil)), config.Options{})

	rows := vm.buildGenericRows(ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1":             {Value: "101"},
		oidDot1qVlanCurrentEgressPorts + "0.30":   {Value: portMask(1)},
		oidDot1qVlanCurrentUntaggedPorts + "0.30": {Value: string(make([]byte, 8))},
	})

	if got, want := string(rows.VlanEgressPorts[30]), portMask(1); got != want {
		t.Errorf("egress: got %x, want %x", got, want)
	}
	if _, ok := rows.VlanUntaggedPorts[30]; !ok {
		t.Error("the empty untagged mask belongs with its populated egress mask")
	}
}

// A PortList bitmap byte can be any value, and several low ones are printable:
// 0x20 is the ASCII space and sets port 3, 0x30 is "0" and sets ports 3 and 4.
// Emptiness has to be tested on the bytes, or real membership is discarded as
// if it named nobody.
func TestIsEmptyPortMask_PrintableBytesAreStillPorts(t *testing.T) {
	for _, tc := range []struct {
		what string
		mask string
		want bool
	}{
		{"no value", "", true},
		{"all zero bytes", string(make([]byte, 8)), true},
		{"port 3 only, which is the ASCII space", portMask(3), false},
		{"ports 3 and 4, which is ASCII zero", portMask(3, 4), false},
		{"port 1", portMask(1), false},
		{"a zero byte beside a set one", string([]byte{0x00, 0x20}), false},
	} {
		if got := isEmptyPortMask(tc.mask); got != tc.want {
			t.Errorf("%s (% x): got %v, want %v", tc.what, tc.mask, got, tc.want)
		}
	}
}

// A device publishing only the current table has VLAN data, so a missing
// bridge-port table is partial data worth warning about rather than the quiet
// "this is not a switch" case.
func TestHasVLANSignal_CountsTheCurrentTable(t *testing.T) {
	if !hasVLANSignal(ObjectIDValueMap{
		oidDot1qVlanCurrentEgressPorts + "0.1": {Value: portMask(1)},
	}) {
		t.Error("the current table is a VLAN signal")
	}
	if !hasVLANSignal(ObjectIDValueMap{
		oidDot1qVlanCurrentUntaggedPorts + "0.1": {Value: portMask(1)},
	}) {
		t.Error("the current untagged table is a VLAN signal")
	}
	if hasVLANSignal(ObjectIDValueMap{oidIfDescr + "1": {Value: "eth0"}}) {
		t.Error("an interface table alone is not a VLAN signal")
	}
}

// Provenance has to survive the merge, or the distinction between the
// configured and operational tables is lost before anything can act on it.
// Recorded from both columns, since a VLAN can arrive through either.
func TestVlanMapper_BuildGenericRows_RecordsCurrentTableProvenance(t *testing.T) {
	vm := NewVlanMapper(slog.New(slog.NewTextHandler(os.Stderr, nil)), config.Options{})

	rows := vm.buildGenericRows(ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1": {Value: "101"},
		// VLAN 10 from the static table: configuration.
		oidDot1qVlanStaticEgressPorts + "10": {Value: portMask(1)},
		// VLAN 20 arrives through the current egress column only.
		oidDot1qVlanCurrentEgressPorts + "0.20": {Value: portMask(1)},
		// VLAN 30 through the current untagged column only.
		oidDot1qVlanCurrentUntaggedPorts + "0.30": {Value: portMask(1)},
	})

	if _, ok := rows.VlanEgressFromCurrent[20]; !ok {
		t.Error("VLAN 20's egress mask came from the current table")
	}
	if _, ok := rows.VlanUntaggedFromCurrent[30]; !ok {
		t.Error("VLAN 30's untagged mask came from the current table")
	}
	// Recorded per column, not per VLAN. VLAN 20 supplied only an egress
	// mask, so nothing may claim its untagged mask is operational — that
	// would suppress a withdrawal the static untagged table's own absence
	// should trigger.
	if _, ok := rows.VlanUntaggedFromCurrent[20]; ok {
		t.Error("VLAN 20 supplied no untagged mask; its untagged column is not from the current table")
	}
	// VLAN 30 supplied no egress mask, so one is synthesized from its untagged
	// mask: an untagged member is an egress member. The synthesized mask is
	// only as configured as the row it came from, which was operational, so it
	// carries that provenance and not a stronger one.
	if _, ok := rows.VlanEgressFromCurrent[30]; !ok {
		t.Error("an egress mask synthesized from a current untagged mask is operational too")
	}
	if got := string(rows.VlanEgressPorts[30]); got != portMask(1) {
		t.Errorf("VLAN 30's egress mask is its untagged mask: got %x", got)
	}
	for _, m := range []map[int]struct{}{rows.VlanEgressFromCurrent, rows.VlanUntaggedFromCurrent} {
		if _, ok := m[10]; ok {
			t.Error("VLAN 10 came from the static table and must not be marked")
		}
	}
}

// A VLAN whose egress mask is operational but whose untagged mask is
// configuration must still have its untagged absence honoured. A single
// per-VLAN provenance set marked it "from current" for both columns and
// suppressed a withdrawal the static table's own absence should trigger.
func TestVlanMapper_PostMap_ProvenanceIsPerColumnNotPerVlan(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	ifaces := interfacesFor(registry, map[int]string{101: "gi1", 102: "gi2"})

	all := ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1": {Value: "101"},
		oidDot1dBasePortIfIndex + "2": {Value: "102"},
		oidIfAdminStatus + "101":      {Value: "1"},
		oidIfAdminStatus + "102":      {Value: "1"},
		oidIfType + "101":             {Value: "6"},
		oidIfType + "102":             {Value: "6"},
		oidDot1qPvid + "1":            {Value: "31"},
		oidDot1qPvid + "2":            {Value: "31"},
		oidDot1qVlanStaticName + "31": {Value: "USERS"},
		// The untagged mask is CONFIGURATION and names only port 1, so port 2
		// is tagged there and its PVID names no untagged VLAN.
		oidDot1qVlanStaticUntaggedPorts + "31": {Value: portMask(1)},
		// The egress mask for the same VLAN is operational.
		oidDot1qVlanCurrentEgressPorts + "0.31": {Value: portMask(1, 2)},
	}

	NewVlanMapper(logger, config.Options{}).PostMap(all, registry, &config.Defaults{})

	if got := ifaces[102]; got.UntaggedVlan != nil {
		t.Errorf("the static untagged table leaves gi2 out, so its PVID names no untagged VLAN: got %+v", got.UntaggedVlan)
	}
	if got := ifaces[101]; got.UntaggedVlan == nil || *got.UntaggedVlan.Vid != 31 {
		t.Errorf("gi1 is untagged in VLAN 31: got %+v", got.UntaggedVlan)
	}
}

// The same distinction end to end, through the path a device actually takes:
// a port configured on a VLAN but not currently forwarding is absent from the
// operational untagged mask, and must keep the VLAN its PVID names.
func TestVlanMapper_PostMap_ANotForwardingPortKeepsItsPvid(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	ifaces := interfacesFor(registry, map[int]string{101: "et1", 102: "et2"})

	all := ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1": {Value: "101"},
		oidDot1dBasePortIfIndex + "2": {Value: "102"},
		oidIfAdminStatus + "101":      {Value: "1"},
		oidIfAdminStatus + "102":      {Value: "1"},
		oidIfType + "101":             {Value: "6"},
		oidIfType + "102":             {Value: "6"},
		// Both ports are configured on VLAN 31.
		oidDot1qPvid + "1": {Value: "31"},
		oidDot1qPvid + "2": {Value: "31"},
		// A catalog exists, so the default-PVID refusal is not in play.
		oidDot1qVlanStaticName + "31": {Value: "USERS"},
		// Only port 1 is currently transmitting untagged on it.
		oidDot1qVlanCurrentEgressPorts + "0.31":   {Value: portMask(1)},
		oidDot1qVlanCurrentUntaggedPorts + "0.31": {Value: portMask(1)},
	}

	vm := NewVlanMapper(logger, config.Options{})
	vm.PostMap(all, registry, &config.Defaults{})

	if got := ifaces[102]; got.UntaggedVlan == nil || got.UntaggedVlan.Vid == nil || *got.UntaggedVlan.Vid != 31 {
		t.Errorf("et2 is configured on VLAN 31 and merely not forwarding: got %+v", got.UntaggedVlan)
	}
}

// dot1qVlanTimeMark is a TimeFilter over TimeTicks, so it restarts after a
// little under 497 days of uptime. A row changed just before the wrap holds a
// mark near the ceiling while one changed just after holds a small one: plain
// magnitude picks the older row, and the VLAN's membership reverts to a stale
// snapshot whenever two rows straddle it.
func TestMarkIsNewer_HandlesTheTimeTicksWrap(t *testing.T) {
	const ceiling = 1<<32 - 1
	for _, tc := range []struct {
		what string
		a, b int
		want bool
	}{
		{"ordinary ascending", 2831, 2828, true},
		{"ordinary descending", 2828, 2831, false},
		{"equal", 2828, 2828, false},
		{"just after the wrap beats just before", 2000, ceiling - 1000, true},
		{"just before the wrap loses to just after", ceiling - 1000, 2000, false},
		{"zero beats the ceiling", 0, ceiling, true},
	} {
		if got := markIsNewer(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: markIsNewer(%d, %d) = %v, want %v", tc.what, tc.a, tc.b, got, tc.want)
		}
	}
}

// The same thing through the merge: the post-wrap row's mask must win.
func TestVlanMapper_BuildGenericRows_LatestAcrossTheTimeMarkWrap(t *testing.T) {
	vm := NewVlanMapper(slog.New(slog.NewTextHandler(os.Stderr, nil)), config.Options{})
	const nearCeiling = 1<<32 - 1000

	all := ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1": {Value: "101"},
		// The pre-wrap row is numerically huge but older.
		oidDot1qVlanCurrentEgressPorts + "4294966296.1": {Value: portMask(4)},
		// The post-wrap row is the current one.
		oidDot1qVlanCurrentEgressPorts + "2000.1": {Value: portMask(1, 2)},
	}
	_ = nearCeiling

	want := portMask(1, 2)
	for i := range 50 {
		if got := string(vm.buildGenericRows(all).VlanEgressPorts[1]); got != want {
			t.Fatalf("run %d: got %x, want the post-wrap mask %x", i, got, want)
		}
	}
}

// A row is catalog evidence only when a VLAN can be read out of it. A table
// answering nothing but an out-of-range index, or a suffix that will not
// parse, has named no VLAN however many rows it has — and counting it would
// bypass the default-PVID refusal and hand those ports back the access VLAN 1
// it exists to withhold.
func TestVlanCatalogPresent_RequiresARowThatNamesAVlan(t *testing.T) {
	for _, tc := range []struct {
		what string
		all  ObjectIDValueMap
		want bool
	}{
		{"nothing at all", ObjectIDValueMap{}, false},
		{"a static name for a real VLAN", ObjectIDValueMap{
			oidDot1qVlanStaticName + "10": {Value: "USERS"},
		}, true},
		{"a current mask for a real VLAN", ObjectIDValueMap{
			oidDot1qVlanCurrentEgressPorts + "0.10": {Value: portMask(1)},
		}, true},
		{"a current mask for the reserved 4095", ObjectIDValueMap{
			oidDot1qVlanCurrentEgressPorts + "0.4095": {Value: portMask(1)},
		}, false},
		{"a static row for VLAN 0", ObjectIDValueMap{
			oidDot1qVlanStaticRowStatus + "0": {Value: "1"},
		}, false},
		{"a suffix that will not parse", ObjectIDValueMap{
			oidDot1qVlanStaticName + "notanumber": {Value: "USERS"},
		}, false},
		{"a VTP name, whose id is the last element", ObjectIDValueMap{
			oidCiscoVtpVlanName + "1.20": {Value: "VOICE"},
		}, true},
		{"a VTP row for a reserved id", ObjectIDValueMap{
			oidCiscoVtpVlanName + "1.4095": {Value: "RESERVED"},
		}, false},
		{"a Juniper enterprise name, keyed by internal index", ObjectIDValueMap{
			oidJnxExVlanName + "99999": {Value: "VL156"},
		}, true},
		{"a Juniper enterprise row with no name", ObjectIDValueMap{
			oidJnxExVlanName + "17": {Value: ""},
		}, false},
	} {
		if got := vlanCatalogPresent(tc.all) || catalogFromWalk(t, tc.all); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.what, got, tc.want)
		}
	}
}

// End to end: a device whose only VLAN table row names no VLAN is, in
// substance, catalog-free, so the default PVID is still refused.
func TestVlanMapper_PostMap_AnUnusableCatalogRowDoesNotBypassTheRefusal(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewEntityRegistry(logger)
	ifaces := interfacesFor(registry, map[int]string{101: "gi1"})

	all := ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1": {Value: "101"},
		oidIfAdminStatus + "101":      {Value: "1"},
		oidIfType + "101":             {Value: "6"},
		oidDot1qPvid + "1":            {Value: "1"},
		// The device's only VLAN row, and it names no VLAN NetBox could hold.
		oidDot1qVlanCurrentEgressPorts + "0.4095": {Value: portMask(1)},
	}

	entities := NewVlanMapper(logger, config.Options{}).PostMap(all, registry, &config.Defaults{})

	for _, e := range entities {
		if v, ok := e.(*diode.VLAN); ok && v != nil && v.Vid != nil {
			t.Errorf("no VLAN may be emitted: got vid %d", *v.Vid)
		}
	}
	if got := ifaces[101]; got.Mode != nil || got.UntaggedVlan != nil {
		t.Errorf("gi1 must stay unclassified: mode=%v untagged=%+v", got.Mode, got.UntaggedVlan)
	}
}

// The two current-table columns are walked separately, so a VLAN that changes
// between the walks answers one column before the change and the other after.
// Taking each column's own newest row would combine halves of two snapshots and
// report a port as tagged where it is untagged, or the reverse.
func TestVlanMapper_BuildGenericRows_PairsTheColumnsAtOneTimeMark(t *testing.T) {
	vm := NewVlanMapper(slog.New(slog.NewTextHandler(os.Stderr, nil)), config.Options{})

	rows := vm.buildGenericRows(ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1": {Value: "101"},
		// Mark 100: the VLAN as it was, ports 1 and 2 egress, port 1 untagged.
		oidDot1qVlanCurrentEgressPorts + "100.10":   {Value: portMask(1, 2)},
		oidDot1qVlanCurrentUntaggedPorts + "100.10": {Value: portMask(1)},
		// Mark 200: it changed, and only the egress column caught it.
		oidDot1qVlanCurrentEgressPorts + "200.10": {Value: portMask(1, 2, 3)},
	})

	// Both masks must come from mark 100, the newest the columns share. Taking
	// each column's own newest would pair mark 200's egress with mark 100's
	// untagged.
	if got, want := string(rows.VlanEgressPorts[10]), portMask(1, 2); got != want {
		t.Errorf("egress: got %x, want the shared snapshot %x", got, want)
	}
	if got, want := string(rows.VlanUntaggedPorts[10]), portMask(1); got != want {
		t.Errorf("untagged: got %x, want %x", got, want)
	}

	// With more than one shared mark it has to be the NEWEST shared one, not
	// merely a shared one: an older snapshot is as wrong as a mismatched pair.
	twoShared := ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1":               {Value: "101"},
		oidDot1qVlanCurrentEgressPorts + "100.11":   {Value: portMask(1)},
		oidDot1qVlanCurrentUntaggedPorts + "100.11": {Value: portMask(1)},
		oidDot1qVlanCurrentEgressPorts + "300.11":   {Value: portMask(1, 2, 3)},
		oidDot1qVlanCurrentUntaggedPorts + "300.11": {Value: portMask(3)},
	}
	// Repeated because picking merely A shared mark rather than the NEWEST one
	// leaves the winner to map iteration order: a single pass agrees by luck
	// about half the time, which is a test that reports the defect as flaky.
	for i := range 50 {
		rows = vm.buildGenericRows(twoShared)
		if got, want := string(rows.VlanEgressPorts[11]), portMask(1, 2, 3); got != want {
			t.Fatalf("run %d egress: got %x, want the newest shared snapshot %x", i, got, want)
		}
		if got, want := string(rows.VlanUntaggedPorts[11]), portMask(3); got != want {
			t.Fatalf("run %d untagged: got %x, want the newest shared snapshot %x", i, got, want)
		}
	}
}

// A VLAN only one column mentions still contributes: there is no snapshot to
// share, so that column's newest row is the best available.
func TestVlanMapper_BuildGenericRows_OneColumnOnlyStillContributes(t *testing.T) {
	vm := NewVlanMapper(slog.New(slog.NewTextHandler(os.Stderr, nil)), config.Options{})

	rows := vm.buildGenericRows(ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1":             {Value: "101"},
		oidDot1qVlanCurrentEgressPorts + "100.20": {Value: portMask(1)},
		oidDot1qVlanCurrentEgressPorts + "200.20": {Value: portMask(1, 2)},
	})

	if got, want := string(rows.VlanEgressPorts[20]), portMask(1, 2); got != want {
		t.Errorf("egress: got %x, want the newest %x", got, want)
	}
	if _, ok := rows.VlanUntaggedPorts[20]; ok {
		t.Error("the untagged column said nothing about VLAN 20 and must not be invented")
	}
}

// markIsNewer is a wrap-aware comparison, not an ordering: over three marks
// spread more than half the space apart, each is "newer" than the next and the
// relation cycles. Folding it over a Go map then picks a different winner from
// run to run, which is the map-order dependence the snapshot resolution exists
// to remove. The marks are sorted first so the fold has one answer.
func TestVlanMapper_BuildGenericRows_ThreeMarksResolveTheSameWayEveryRun(t *testing.T) {
	vm := NewVlanMapper(slog.New(slog.NewTextHandler(os.Stderr, nil)), config.Options{})

	// Each of these is markIsNewer than the one before, and the first is
	// markIsNewer than the last.
	all := ObjectIDValueMap{
		oidDot1dBasePortIfIndex + "1":                   {Value: "101"},
		oidDot1qVlanCurrentEgressPorts + "0.1":          {Value: portMask(1)},
		oidDot1qVlanCurrentEgressPorts + "1400000000.1": {Value: portMask(2)},
		oidDot1qVlanCurrentEgressPorts + "2800000000.1": {Value: portMask(3)},
	}

	first := string(vm.buildGenericRows(all).VlanEgressPorts[1])
	for i := range 50 {
		if got := string(vm.buildGenericRows(all).VlanEgressPorts[1]); got != first {
			t.Fatalf("run %d: got %x, first run gave %x", i, got, first)
		}
	}
}

// A device that publishes its VLANs in a vendor catalog has named VLANs of its
// own, whichever MIB the catalog lives in. Counting only the ones Q-BRIDGE
// knows about would withhold every port on a Huawei switch whose VLANs are
// real and whose PVID column happens to answer the MIB default.
func TestVlanMapper_VlanCatalogPresent_CountsTheHuaweiCatalog(t *testing.T) {
	all := ObjectIDValueMap{oidHwVlanName + "120": {Value: "uplink"}}
	if !vlanCatalogPresent(all) {
		t.Error("a Huawei catalog row names a VLAN")
	}
	if vlanCatalogPresent(ObjectIDValueMap{oidHwVlanName + "9999": {Value: "x"}}) {
		t.Error("a row naming no VLAN NetBox could hold is not a catalog")
	}
}

// catalogFromWalk answers the catalog question the way buildGenericRows does,
// which is where the current table's contribution is decided: its rows are
// masks, so whether one names a VLAN depends on the snapshot that was resolved
// rather than on the rows as walked.
func catalogFromWalk(t *testing.T, all ObjectIDValueMap) bool {
	t.Helper()
	vm := NewVlanMapper(slog.New(slog.NewTextHandler(io.Discard, nil)), config.Options{})
	return vm.buildGenericRows(all).VlanCatalogPresent
}

// A current-table row that places no port in a VLAN is not a VLAN catalog.
// The merge already discards such a row as membership; counting it as the
// device naming a VLAN waives the default-PVID refusal, and what that emits
// is access VLAN 1 on every port, which the same row refutes.
func TestVlanMapper_VlanCatalogPresent_AnEmptyCurrentRowIsNotACatalog(t *testing.T) {
	zero := string(make([]byte, 8))
	all := ObjectIDValueMap{
		oidDot1qVlanCurrentEgressPorts + "0.1":   {Value: zero},
		oidDot1qVlanCurrentUntaggedPorts + "0.1": {Value: zero},
	}
	if catalogFromWalk(t, all) {
		t.Error("a row naming no port names no VLAN")
	}
	// One port in it and the device has told us the VLAN is real.
	all[oidDot1qVlanCurrentEgressPorts+"0.1"] = Value{Value: portMask(1)}
	if !catalogFromWalk(t, all) {
		t.Error("a row naming a port is a catalog entry")
	}
	// A static row still counts however empty, since the VLAN is configured.
	if !vlanCatalogPresent(ObjectIDValueMap{oidDot1qVlanStaticEgressPorts + "7": {Value: zero}}) {
		t.Error("a configured VLAN is named whether or not a port is in it")
	}

	// A VLAN every port has since left: an older snapshot names ports, the
	// newest names none. The merge resolves the newest and drops the VLAN, so
	// the stale row must not go on licensing the default PVID either.
	stale := ObjectIDValueMap{
		oidDot1qVlanCurrentEgressPorts + "10.1":   {Value: portMask(1)},
		oidDot1qVlanCurrentUntaggedPorts + "10.1": {Value: portMask(1)},
		oidDot1qVlanCurrentEgressPorts + "20.1":   {Value: zero},
		oidDot1qVlanCurrentUntaggedPorts + "20.1": {Value: zero},
	}
	if catalogFromWalk(t, stale) {
		t.Error("the resolved snapshot names no port, so the device named no VLAN")
	}
}

// Each catalog source is read at the shape its own rows carry. A suffix with
// the wrong number of components is a row the readers reject, and taking a
// VLAN id off the end of one would count a malformed OID as a catalog and
// waive the default-PVID refusal on the strength of it.
func TestVlanMapper_VlanCatalogPresent_ChecksTheWholeIndex(t *testing.T) {
	mask := portMask(1)
	cases := []struct {
		name string
		oid  string
		val  string
		want bool
	}{
		// The current table is (timeMark, vlan): exactly two components.
		{"current, well formed", oidDot1qVlanCurrentEgressPorts + "0.10", mask, true},
		{"current, one component", oidDot1qVlanCurrentEgressPorts + "10", mask, false},
		{"current, three components", oidDot1qVlanCurrentEgressPorts + "0.10.1", mask, false},
		{"current, id out of range", oidDot1qVlanCurrentEgressPorts + "0.4095", mask, false},
		// The VTP catalog is (domain, vlan).
		{"vtp, well formed", oidCiscoVtpVlanName + "1.10", "voice", true},
		{"vtp, three components", oidCiscoVtpVlanName + "1.10.1", "voice", false},
		// The VLAN-keyed tables carry one component.
		{"static name, well formed", oidDot1qVlanStaticName + "10", "voice", true},
		{"static name, two components", oidDot1qVlanStaticName + "10.1", "voice", false},
		{"huawei, well formed", oidHwVlanName + "10", "uplink", true},
		{"huawei, two components", oidHwVlanName + "10.1", "uplink", false},
	}
	for _, c := range cases {
		all := ObjectIDValueMap{c.oid: {Value: c.val}}
		// The current table's contribution is decided during the merge, the
		// rest directly; both must reject a suffix of the wrong shape.
		got := vlanCatalogPresent(all) || catalogFromWalk(t, all)
		if got != c.want {
			t.Errorf("%s: catalog present = %v, want %v", c.name, got, c.want)
		}
	}
}
