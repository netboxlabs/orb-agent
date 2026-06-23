// Package mapping — asset_tag.go: vetting + resolution for Device.asset_tag.
//
// OpenConfig defines no standard asset-tag leaf (unlike ENTITY-MIB's
// entPhysicalAssetID that snmp-discovery reads), so gnmi-discovery cannot
// auto-discover an asset tag zero-config. Instead defaults.asset_tag accepts
// either a literal value or a gNMI path reference (a value beginning with "/")
// resolved from the discovered model snapshot — mirroring snmp-discovery's
// "OID reference or literal" mechanism. Both forms pass through vetAssetTag.
//
// The vetting below is duplicated from snmp-discovery (a sibling module) rather
// than shared: the monorepo keeps the two backends as independent modules.
package mapping

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// assetTagMaxLen mirrors NetBox's dcim.Device.asset_tag column
// (CharField(max_length=50)). Over-long values are skipped rather than
// truncated so we never introduce silent uniqueness collisions.
const assetTagMaxLen = 50

// assetTagPlaceholders enumerates well-known not-really-an-asset-tag values
// devices report when no tag was provisioned. Matched exactly,
// case-insensitively, after trimming — never by prefix/substring, so real tags
// like "NA1234" pass. Deliberately conservative: a false positive silently
// drops a legitimate tag.
var assetTagPlaceholders = map[string]struct{}{
	"unknown":       {},
	"n/a":           {},
	"na":            {},
	"none":          {},
	"null":          {},
	"nil":           {},
	"default":       {},
	"unspecified":   {},
	"unassigned":    {},
	"not specified": {},
	"not available": {},
	"no asset tag":  {},
	"tbd":           {},
	"0":             {},
}

// validAssetTagText reports whether tag is well-formed UTF-8 with no control
// characters. A garbage value must not become Device.asset_tag — NetBox's
// unique, highest-precedence device matcher.
func validAssetTagText(tag string) bool {
	if !utf8.ValidString(tag) {
		return false
	}
	for _, r := range tag {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// vetAssetTag validates a candidate asset_tag value: well-formed printable
// UTF-8, not a known placeholder, within NetBox's 50-rune column. Returns
// ok=false with a short reason on rejection.
func vetAssetTag(tag string) (reason string, ok bool) {
	if !validAssetTagText(tag) {
		return "non-printable or invalid UTF-8 value", false
	}
	if _, placeholder := assetTagPlaceholders[strings.ToLower(tag)]; placeholder {
		return fmt.Sprintf("placeholder value %q", tag), false
	}
	if n := utf8.RuneCountInString(tag); n > assetTagMaxLen {
		return fmt.Sprintf("exceeds NetBox max length (%d > %d runes)", n, assetTagMaxLen), false
	}
	return "", true
}

// ResolveAssetTag turns a defaults.asset_tag value into a vetted asset tag.
// A value beginning with "/" is a gNMI path reference: it is resolved from the
// discovered model snapshot first, and — if the referenced leaf is not one of
// the subscribed paths — via the optional fetch callback (a targeted Get), so
// an operator can point at any leaf the device exposes (the curated subscription
// does not collect arbitrary component leaves). Any other value is a literal.
// Returns ("", false) when the value is empty, an unresolved reference, or fails
// vetting (placeholder / 50-rune cap / non-printable) — the caller then leaves
// Device.AssetTag unset. fetch may be nil (snapshot-only resolution).
func ResolveAssetTag(raw string, snap map[string]any, fetch func(path string) (string, bool)) (string, bool) {
	candidate := raw
	if strings.HasPrefix(raw, "/") {
		if v, ok := snap[raw]; ok {
			candidate = toStr(v)
		} else if fetch != nil {
			v, ok := fetch(raw)
			if !ok {
				return "", false
			}
			candidate = v
		} else {
			return "", false
		}
	}
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", false
	}
	if _, ok := vetAssetTag(candidate); !ok {
		return "", false
	}
	return candidate, true
}
