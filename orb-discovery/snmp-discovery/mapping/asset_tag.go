// Package mapping — asset_tag.go: shared asset_tag vetting used by both
// the SNMP-discovered chassis path (resolveAssetTags) and the operator
// defaults path (DeviceMapper.applyDefaults).
package mapping

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// assetTagMaxLen mirrors NetBox's dcim.Device.asset_tag column
// (CharField(max_length=50)). Resolved AssetTag values that exceed
// this length are warn-skipped rather than truncated so we don't
// introduce silent uniqueness collisions.
const assetTagMaxLen = 50

// assetTagPlaceholders enumerates well-known not-really-an-asset-tag
// values agents report when no tag was provisioned (vendor defaults,
// lazy golden-config stamps). Matched exactly, case-insensitively,
// after trimming — never by prefix/substring, so real tags like
// "NA1234" pass. The list is deliberately conservative: a false
// positive here silently drops a legitimate tag.
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

// validAssetTagText reports whether tag is well-formed UTF-8 with no
// control characters. SNMP OctetStrings are raw bytes; a garbage value
// must not become Device.asset_tag, NetBox's unique, highest-precedence
// device matcher.
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

// vetAssetTag validates a candidate asset_tag value against the
// constraints shared by every source — operator defaults and
// SNMP-discovered chassis rows alike: well-formed printable UTF-8,
// not a well-known placeholder, and within NetBox's 50-char column.
// Returns ok=false with a short human-readable reason for the
// caller's warn log. Source-specific rules (duplicate suppression,
// defaults collision) stay with the caller.
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
