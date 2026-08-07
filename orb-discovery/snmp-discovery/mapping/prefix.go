package mapping

import (
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// DerivePrefixes derives Prefix entities from the discovered IP addresses
// (the network of each address/len), matching device-discovery's behavior.
// One Prefix is emitted per unique (network, VRF) pair, sorted for
// deterministic output.
//
// Host prefixes (/32, /128) and IPv6 link-locals (fe80::/10) are skipped:
// the former only restates an address that is already emitted as an
// IPAddress, and the latter is per-link and not globally meaningful. The
// IPAddress entities themselves are untouched, so the addresses stay
// documented — only the derived Prefix is dropped. Host prefixes can be
// opted back in with emit_host_prefixes; link-locals cannot, by design.
//
// The prefix VRF follows device-discovery's precedence: an IP whose
// address was attached to a DISCOVERED VRF (vrfByAddress, produced by
// AttachVrfs) carries that VRF onto its prefix; every other prefix gets
// the defaults.prefix vrf / vrf_ipv4 / vrf_ipv6 resolution for its
// family. Note the prefix defaults are deliberately independent of the
// ip_address ones.
//
// The prefix VLAN is corroborated rather than derived: sviVlanByIfIndex
// (produced by ResolveSviVlans, keyed by ifIndex) and ifIndexByIface
// (mapper.InterfacesByIfIndex) are only consulted when
// options.PrefixVlanMode is "corroborated", and even then a prefix is
// only tagged when every contributing address resolves to the SAME
// VLAN. Any disagreement, or any contributing address with no VLAN,
// leaves the prefix untagged and logs a warning — see the vote
// accumulation below for why that check must span every address.
func DerivePrefixes(
	entities []diode.Entity,
	vrfByAddress map[string]*diode.VRF,
	sviVlanByIfIndex map[int]*diode.VLAN,
	ifIndexByIface map[*diode.Interface]int,
	defaults *config.Defaults,
	options *config.Options,
	logger *slog.Logger,
) []diode.Entity {
	type prefixSeed struct {
		network string
		vrf     *diode.VRF
	}
	seen := make(map[string]prefixSeed)
	// Candidate VLANs per prefix key. A prefix is only associated when
	// every address that formed it agrees, so this must be collected
	// across ALL contributing addresses before the first-wins collapse
	// below picks the surviving prefixSeed. Collecting only for the
	// first address per key would make the association depend on Go map
	// iteration order and flap between polls.
	type vlanVote struct {
		vlan     *diode.VLAN
		conflict bool
		total    int
	}
	votes := make(map[string]*vlanVote)
	corroborateVlan := options.PrefixVlanMode() == "corroborated" && len(sviVlanByIfIndex) > 0
	warnedNamelessVrf := false
	for _, e := range entities {
		ip, ok := e.(*diode.IPAddress)
		if !ok || ip.Address == nil {
			continue
		}
		addr := *ip.Address
		// IPv4-mapped IPv6 addresses are deliberately preserved in their
		// ::ffff: textual form upstream (RFC 4001 addrType=2), but
		// net.ParseCIDR reclassifies them to dotted-quad — the derived
		// "prefix" would be an IPv4 object that isn't even the NetBox
		// parent of its own (IPv6) address. Skip them.
		if strings.HasPrefix(strings.ToLower(addr), "::ffff:") {
			logger.Debug("prefix: skipping IPv4-mapped IPv6 address", "address", addr)
			continue
		}
		addrIP, network, err := net.ParseCIDR(addr)
		if err != nil {
			logger.Debug("prefix: unparseable IP address, skipping", "address", addr)
			continue
		}
		ones, bits := network.Mask.Size()
		// A zero-length mask comes from agent quirks (ipAdEntNetMask
		// 0.0.0.0 on loopback/unnumbered rows) — no SNMP-discovered
		// subnet can legitimately be the default route, and ingesting
		// 0.0.0.0/0 or ::/0 would parent the entire IPAM tree.
		if ones == 0 {
			logger.Debug("prefix: skipping zero-length network", "address", addr)
			continue
		}
		// IPv6 link-locals are per-link and not globally meaningful, so a
		// prefix per fe80:: address is churn.
		//
		// Judged on the ADDRESS, not the masked network. A mask of /8 or
		// wider moves the network out of the fe80::/10 bit pattern —
		// fe80::1/8 masks to fe00:: and fe80::1/1 to 8000:: — so testing
		// network.IP emitted a colossal container prefix for an address
		// that is plainly link-local. Agents do report nonsense masks;
		// that is why the zero-length guard above exists.
		//
		// Deliberately NOT gated on emit_host_prefixes: an fe80::x/128 is
		// a link-local that happens to carry host length, not a loopback
		// an operator wants tracked, so opting in to host prefixes must
		// not resurrect it. Gated on the family instead, because
		// IsLinkLocalUnicast also covers IPv4 169.254.0.0/16, an ordinary
		// network by mask that stays in scope.
		if addrIP.To4() == nil && addrIP.IsLinkLocalUnicast() {
			logger.Debug("prefix: skipping IPv6 link-local", "address", addr)
			continue
		}
		// A host prefix (/32, /128) only restates the address, which is
		// already emitted as an IPAddress entity — the derived prefix is a
		// duplicate of it under a different object type. Rows with no
		// usable mask also land here, so this covers those too. Operators
		// who track loopback /32s as prefixes can opt back in.
		if ones == bits && !options.HostPrefixEmissionEnabled() {
			logger.Debug("prefix: skipping host prefix", "address", addr)
			continue
		}
		family := "ipv4"
		if strings.Contains(addr, ":") {
			family = "ipv6"
		}
		vrf := vrfByAddress[addr]
		if vrf == nil && defaults != nil {
			var misconfigured bool
			vrf, misconfigured = prefixDefaultsVrf(&defaults.Prefix, family)
			if misconfigured && !warnedNamelessVrf {
				warnedNamelessVrf = true
				logger.Warn(
					"prefix VRF defaults dropped: name is empty but other VRF fields are set; " +
						"set defaults.prefix.vrf.name (or the vrf_ipv4 / vrf_ipv6 override's name) " +
						"to enable VRF emission on derived prefixes. " +
						"Logged once per target per discovery run.",
				)
			}
		}
		key := network.String() + "\x00" + vrfKey(vrf)
		// Vote accumulation happens for EVERY contributing address, not
		// only the one that wins the seen[key] first-wins guard below —
		// see the vlanVote doc comment above for why that ordering
		// matters.
		if corroborateVlan {
			var cand *diode.VLAN
			if iface, ok := ip.AssignedObject.(*diode.Interface); ok && iface != nil {
				if idx, known := ifIndexByIface[iface]; known {
					cand = sviVlanByIfIndex[idx]
				}
			}
			v := votes[key]
			if v == nil {
				v = &vlanVote{}
				votes[key] = v
			}
			v.total++
			switch {
			case cand == nil:
				v.conflict = true
			case v.vlan == nil && !v.conflict:
				v.vlan = cand
			case v.vlan != cand:
				v.conflict = true
			}
		}
		if _, dup := seen[key]; !dup {
			seen[key] = prefixSeed{network: network.String(), vrf: vrf}
		}
	}
	if len(seen) == 0 {
		return nil
	}

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	prefixes := make([]diode.Entity, 0, len(seen))
	for _, k := range keys {
		seed := seen[k]
		network := seed.network
		prefix := &diode.Prefix{Prefix: &network, Vrf: seed.vrf}
		if v := votes[k]; v != nil {
			if !v.conflict && v.vlan != nil {
				prefix.Vlan = v.vlan
			} else {
				logger.Warn("prefix vlan: contested or partial VLAN attribution; emitting no vlan",
					"prefix", network, "contributing_addresses", v.total)
			}
		}
		applyPrefixDefaults(prefix, defaults, options)
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

// prefixDefaultsVrf builds the defaults-derived VRF for a family, or nil.
// Mirrors the ip_address defaults semantics: a nameless resolution emits
// nothing; the second return flags that misconfiguration (sub-fields set
// but no name) so the caller can warn — the IP-side warning covers only
// the defaults.ip_address knobs.
func prefixDefaultsVrf(d *config.PrefixDefaults, family string) (*diode.VRF, bool) {
	params, _ := d.VrfForFamily(family)
	if params.Name == "" {
		return nil, !params.IsZero()
	}
	name := params.Name
	vrf := &diode.VRF{Name: &name}
	if params.Rd != "" {
		rd := params.Rd
		vrf.Rd = &rd
	}
	if params.Description != "" {
		desc := params.Description
		vrf.Description = &desc
	}
	if params.Comments != "" {
		comments := params.Comments
		vrf.Comments = &comments
	}
	if len(params.Tags) > 0 {
		tags := make([]*diode.Tag, 0, len(params.Tags))
		for _, t := range params.Tags {
			tagName := t
			tags = append(tags, &diode.Tag{Name: &tagName})
		}
		vrf.Tags = tags
	}
	return vrf, false
}

// vrfKey returns a stable dedupe key component for a VRF reference. The
// NUL delimiter cannot appear in decoded VRF names (the index decoder
// rejects control characters), so names can't collide with name+rd pairs.
func vrfKey(vrf *diode.VRF) string {
	if vrf == nil || vrf.Name == nil {
		return ""
	}
	key := *vrf.Name
	if vrf.Rd != nil {
		key += "\x00" + *vrf.Rd
	}
	return key
}

// applyPrefixDefaults applies the defaults.prefix block plus the scope
// resolution to a derived Prefix entity.
func applyPrefixDefaults(prefix *diode.Prefix, defaults *config.Defaults, options *config.Options) {
	if defaults == nil {
		return
	}
	d := defaults.Prefix
	if d.Description != "" {
		desc := d.Description
		prefix.Description = &desc
	}
	if d.Comments != "" {
		comments := d.Comments
		prefix.Comments = &comments
	}
	if d.Role != "" {
		role := d.Role
		prefix.Role = &diode.Role{Name: &role}
	}
	if d.Tenant != "" {
		tenant := d.Tenant
		prefix.Tenant = &diode.Tenant{Name: &tenant}
	}
	var tags []*diode.Tag
	for _, t := range d.Tags {
		tagName := t
		tags = append(tags, &diode.Tag{Name: &tagName})
	}
	for _, t := range defaults.Tags {
		tagName := t
		tags = append(tags, &diode.Tag{Name: &tagName})
	}
	if len(tags) > 0 {
		prefix.Tags = tags
	}
	applyPrefixScope(prefix, defaults, options)
}

// applyPrefixScope sets the Prefix scope. Explicit
// defaults.prefix.scope_* wins (location over site, being more specific);
// otherwise, when the propagate_defaults_to_prefix_scope option is on,
// defaults.site / defaults.location cascade in. NetBox Locations are
// unique within their parent site, so a Location scope carries the site
// when one is known.
func applyPrefixScope(prefix *diode.Prefix, defaults *config.Defaults, options *config.Options) {
	scopeSite := defaults.Prefix.ScopeSite
	scopeLocation := defaults.Prefix.ScopeLocation
	anyExplicit := scopeSite != "" || scopeLocation != ""
	if !anyExplicit && options.PrefixScopeCascadeEnabled() {
		scopeSite = defaults.Site
		scopeLocation = defaults.Location
	}
	if scopeLocation != "" {
		loc := &diode.Location{Name: &scopeLocation}
		if scopeSite != "" {
			site := scopeSite
			loc.Site = &diode.Site{Name: &site}
		}
		prefix.Scope = loc
		return
	}
	if scopeSite != "" {
		site := scopeSite
		prefix.Scope = &diode.Site{Name: &site}
	}
}
