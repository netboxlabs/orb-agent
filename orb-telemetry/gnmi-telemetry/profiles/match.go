package profiles

import "strings"

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
			e.keys = map[string]string{}
			for _, kv := range strings.Split(strings.Trim(keyPart, "[]"), "][") {
				k, v, _ := strings.Cut(kv, "=")
				e.keys[k] = v
			}
		}
		elems = append(elems, e)
	}
	for _, r := range p {
		switch {
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

// pathKeys is the set of key names a path's elements carry, which is what a
// subscription's attributes may name as their source: a key the path does not
// carry is never reported by a match, so an attribute reading it would be
// silently dropped from every series.
func pathKeys(p string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, e := range parsePath(p) {
		for k := range e.keys {
			out[k] = struct{}{}
		}
	}
	return out
}

// matchElems matches a pattern's elements against a path's of equal length.
// A pattern key value "*" accepts any value; a literal must match exactly;
// every key the path carries is reported.
func matchElems(pattern, path []pathElem) (map[string]string, bool) {
	if len(pattern) != len(path) {
		return nil, false
	}
	keys := map[string]string{}
	for i := range pattern {
		if pattern[i].name != path[i].name {
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
// update must extend the subscription path by at least one element.
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
		rest = append(rest, e.name)
	}
	return strings.Join(rest, "/"), keys, true
}

// MatchPrefix reports whether deletedPath names an ancestor of, or exactly,
// the subscription path, with the keys the deleted path carries. A delete
// of a list element arrives as the element's path, shorter than every
// subscription under it.
func MatchPrefix(subscriptionPath, deletedPath string) (map[string]string, bool) {
	pattern := parsePath(subscriptionPath)
	path := parsePath(deletedPath)
	if len(path) == 0 || len(path) > len(pattern) {
		return nil, false
	}
	return matchElems(pattern[:len(path)], path)
}

// Depth is the number of elements in a path.
func Depth(path string) int {
	return len(parsePath(path))
}
