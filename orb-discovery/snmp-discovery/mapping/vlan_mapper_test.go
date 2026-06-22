package mapping

import (
	"log/slog"
	"os"
	"strconv"
	"testing"

	"github.com/netboxlabs/diode-sdk-go/diode"
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
			Group:       "campus-vlans",
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
		VLAN: config.VLANDefaults{Group: "Lab VLAN Group"},
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
		VLAN: config.VLANDefaults{Group: "campus-vlans"},
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
		VLAN: config.VLANDefaults{Group: "campus-vlans"},
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
