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
// The prefix VRF follows device-discovery's precedence: an IP whose
// address was attached to a DISCOVERED VRF (vrfByAddress, produced by
// AttachVrfs) carries that VRF onto its prefix; every other prefix gets
// the defaults.prefix vrf / vrf_ipv4 / vrf_ipv6 resolution for its
// family. Note the prefix defaults are deliberately independent of the
// ip_address ones.
func DerivePrefixes(
	entities []diode.Entity,
	vrfByAddress map[string]*diode.VRF,
	defaults *config.Defaults,
	options *config.Options,
	logger *slog.Logger,
) []diode.Entity {
	type prefixSeed struct {
		network string
		vrf     *diode.VRF
	}
	seen := make(map[string]prefixSeed)
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
		_, network, err := net.ParseCIDR(addr)
		if err != nil {
			logger.Debug("prefix: unparseable IP address, skipping", "address", addr)
			continue
		}
		// A zero-length mask comes from agent quirks (ipAdEntNetMask
		// 0.0.0.0 on loopback/unnumbered rows) — no SNMP-discovered
		// subnet can legitimately be the default route, and ingesting
		// 0.0.0.0/0 or ::/0 would parent the entire IPAM tree.
		if ones, _ := network.Mask.Size(); ones == 0 {
			logger.Debug("prefix: skipping zero-length network", "address", addr)
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
