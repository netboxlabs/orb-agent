package profiles

import (
	"sort"
	"strings"
)

// pathElem is one element of a gNMI path: its name and keys.
type pathElem struct {
	name string
	keys map[string]string
}

// parsePath splits an xpath-style gNMI path into elements. A module prefix
// on an element name ("openconfig-interfaces:interfaces") is dropped, so a
// JSON_IETF path and a PROTO path compare equal. Keys are "[k=v]" groups; a
// key value may contain "/" (interface names do), which is why the split
// happens outside brackets only.
func parsePath(p string) []pathElem {
	var elems []pathElem
	var cur strings.Builder
	depth := 0
	flush := func() {
		s := cur.String()
		cur.Reset()
		if s == "" {
			return
		}
		name, keyPart := s, ""
		if i := strings.IndexByte(s, '['); i >= 0 {
			name, keyPart = s[:i], s[i:]
		}
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[i+1:]
		}
		e := pathElem{name: name}
		if keyPart != "" {
			e.keys = parseKeys(keyPart)
		}
		elems = append(elems, e)
	}
	escaped := false
	for _, r := range p {
		switch {
		case escaped:
			// The character after a backslash is part of a key value whatever
			// it is: a bracket there is not a delimiter.
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
			cur.WriteRune(r)
		case r == '[':
			depth++
			cur.WriteRune(r)
		case r == ']':
			depth--
			cur.WriteRune(r)
		case r == '/' && depth == 0:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return elems
}

// parseKeys reads the "[k=v]" groups of one element. A backslash escapes the
// character after it, which is how the transport renders a bracket or a
// backslash inside a key value, and the escape is dropped so the value is the
// one the device wrote. A group without "=" is a key with an empty value.
func parseKeys(keyPart string) map[string]string {
	keys := map[string]string{}
	var k, v strings.Builder
	inGroup, inValue, escaped := false, false, false
	for _, r := range keyPart {
		switch {
		case escaped:
			if inValue {
				v.WriteRune(r)
			} else {
				k.WriteRune(r)
			}
			escaped = false
		case r == '\\':
			escaped = true
		case !inGroup:
			if r == '[' {
				inGroup, inValue = true, false
				k.Reset()
				v.Reset()
			}
		case r == ']':
			keys[k.String()] = v.String()
			inGroup, inValue = false, false
		case !inValue && r == '=':
			inValue = true
		case inValue:
			v.WriteRune(r)
		default:
			k.WriteRune(r)
		}
	}
	return keys
}

// pathKeyCounts is how many of a path's elements carry each key name, which is
// what a subscription's attributes may name as their source. A key the path does
// not carry is never reported by a match, so an attribute reading it would be
// silently dropped from every series. A key two elements carry is worse than
// absent: matchElems reports keys in one flat map, so the deeper element's value
// overwrites the shallower one and an attribute reading that name gets the wrong
// list's value with nothing to show for it.
func pathKeyCounts(p string) map[string]int {
	out := map[string]int{}
	for _, e := range parsePath(p) {
		for k := range e.keys {
			out[k]++
		}
	}
	return out
}

// wildcardKeys is the key names a path wildcards, sorted so a subscription that
// leaves two of them unpromoted always names the same one. A wildcard is what
// makes one subscription cover a whole list, and the key's value is the only
// thing that tells the elements apart: unless an attribute promotes it, every
// element of the list writes one shared series.
func wildcardKeys(p string) []string {
	var out []string
	for _, e := range parsePath(p) {
		for k, v := range e.keys {
			if v == "*" {
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// matchElems matches a pattern's elements against a path's of equal length.
// A pattern key value "*" accepts any value; a literal must match exactly;
// every key the path carries is reported.
//
// An element matches only when it carries exactly the keys the pattern
// declares, so a keyless pattern element matches a keyless update element
// alone. Accepting the keys a pattern leaves out would have a list written
// without its key match every element of that list, and since the pattern
// names no key there is nothing an attribute could promote, so each element
// would overwrite one shared series; validation cannot catch that, because the
// key it would have to demand is absent from the pattern. Refusing the match
// pushes the operator to write the key, which the wildcard rule then makes
// them promote.
func matchElems(pattern, path []pathElem) (map[string]string, bool) {
	if len(pattern) != len(path) {
		return nil, false
	}
	keys := map[string]string{}
	for i := range pattern {
		if pattern[i].name != path[i].name {
			return nil, false
		}
		// Every declared key is found on the path below, so equal counts make
		// the two key sets equal and an update carrying an extra key is no
		// longer a match.
		if len(pattern[i].keys) != len(path[i].keys) {
			return nil, false
		}
		for k, want := range pattern[i].keys {
			got, ok := path[i].keys[k]
			if !ok {
				return nil, false
			}
			if want != "*" && want != got {
				return nil, false
			}
		}
		for k, v := range path[i].keys {
			keys[k] = v
		}
	}
	return keys, true
}

// MatchPath reports whether path matches pattern element for element.
func MatchPath(pattern, path string) (map[string]string, bool) {
	return matchElems(parsePath(pattern), parsePath(path))
}

// SplitLeaf matches the leading elements of updatePath against
// subscriptionPath and returns the remainder as a "/"-joined leaf. The
// update must extend the subscription path by at least one element, and no
// element of the remainder may carry a key: a list below the subscription
// path has entries the leaf cannot tell apart, since a leaf is written
// without keys and an attribute promotes only the subscription path's, so
// every entry would write the one series. Such an update matches nothing,
// which is what tells the operator the list belongs in the subscription path.
func SplitLeaf(subscriptionPath, updatePath string) (string, map[string]string, bool) {
	pattern := parsePath(subscriptionPath)
	path := parsePath(updatePath)
	if len(path) <= len(pattern) {
		return "", nil, false
	}
	keys, ok := matchElems(pattern, path[:len(pattern)])
	if !ok {
		return "", nil, false
	}
	rest := make([]string, 0, len(path)-len(pattern))
	for _, e := range path[len(pattern):] {
		if len(e.keys) > 0 {
			return "", nil, false
		}
		rest = append(rest, e.name)
	}
	return strings.Join(rest, "/"), keys, true
}

// MatchPrefix reports whether deletedPath names an ancestor of, or exactly,
// the subscription path, with the keys the deleted path carries. A delete
// of a list element arrives as the element's path, shorter than every
// subscription under it. The empty path is the data-tree root, an ancestor
// of everything: a delete of it matches every subscription with no keys, so
// every series the subscription produced is withdrawn. Refusing it left an
// on_change series, which never goes stale, exported until the next
// reconnect.
func MatchPrefix(subscriptionPath, deletedPath string) (map[string]string, bool) {
	pattern := parsePath(subscriptionPath)
	path := parsePath(deletedPath)
	if len(path) == 0 {
		return nil, true
	}
	if len(path) > len(pattern) {
		return nil, false
	}
	return matchDeleteElems(pattern[:len(path)], path)
}

// matchDeleteElems is matchElems for a delete: an element of the deleted path
// that carries no key selects every instance of the keyed pattern element it
// names, which is how a target deletes a whole list, and contributes no key.
// An element that carries keys is held to the exact rule. Under the exact
// rule alone, a delete of the list was refused against its keyed pattern and
// withdrew none of the list's series, and an on_change one stood for ever.
func matchDeleteElems(pattern, path []pathElem) (map[string]string, bool) {
	if len(pattern) != len(path) {
		return nil, false
	}
	keys := map[string]string{}
	for i := range pattern {
		if pattern[i].name != path[i].name {
			return nil, false
		}
		if len(path[i].keys) == 0 {
			continue
		}
		got, ok := matchElems(pattern[i:i+1], path[i:i+1])
		if !ok {
			return nil, false
		}
		for k, v := range got {
			keys[k] = v
		}
	}
	return keys, true
}

// Depth is the number of elements in a path.
func Depth(path string) int {
	return len(parsePath(path))
}
