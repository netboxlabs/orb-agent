package redact

import (
	"cmp"
	"fmt"
	"math"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

// MaskedSecret is the value used to replace sensitive information in logs
const MaskedSecret = "********"

// sensitiveFieldPatterns contains lowercase exact field names that identify sensitive fields
var sensitiveFieldPatterns = []string{
	"client_secret",
	"clientsecret",
	"password",
	"private_key",
	"privatekey",
	"access_token",
	"accesstoken",
	"api_key",
	"apikey",
	"auth_token",
	"authtoken",
	"bearer",
	"jwt",
	"secret_id", // A Vault AppRole's credential
	"role_id",   // Its role: Vault accepts it alone for a role that binds no secret_id
	"secret",    // Exact match only
	"token",     // Exact match only
}

// sensitiveFieldSuffixes contains lowercase suffixes that indicate sensitive fields
var sensitiveFieldSuffixes = []string{
	"_secret",
	"_password",
	"_token",
	"_private_key",
	"_api_key",
	"_auth_key",
}

// sensitiveContainers names the fields whose every value is a credential but
// those of the fields listed, which name none. A Vault login's auth_args holds
// the login method's arguments: a method the lists above have no names for is
// still masked whole.
var sensitiveContainers = map[string][]string{
	"auth_args": {"mount_path", "username", "role", "service_account_file"},
}

// sensitiveFlagPatterns contains patterns for sensitive CLI flags
var sensitiveFlagPatterns = []string{
	"--diode-client-secret",
	"--client-secret",
	"--password",
	"--token",
	"--api-key",
	"--auth-token",
	"--private-key",
	"--bearer",
	"--jwt",
}

// sensitiveFlagSuffixes contains suffixes that indicate a sensitive flag
var sensitiveFlagSuffixes = []string{
	"-secret",
	"-password",
	"-token",
	"-private-key",
	"-api-key",
	"-auth-key",
}

// SensitiveData creates a deep copy of the input data and masks sensitive fields.
// It handles maps, structs, slices, and primitive types recursively.
// Returns the redacted copy suitable for logging - original data is never modified.
func SensitiveData(data any) any {
	if data == nil {
		return nil
	}

	val := reflect.ValueOf(data)
	return redactValue(val, "")
}

// redactValue recursively redacts values based on their type
func redactValue(val reflect.Value, fieldName string) any {
	if !val.IsValid() {
		return nil
	}

	// Handle pointers
	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return nil
		}
		elem := val.Elem()
		redacted := redactValue(elem, fieldName)
		// Return the redacted value directly, not wrapped in pointer
		return redacted
	}

	// Handle interfaces
	if val.Kind() == reflect.Interface {
		if val.IsNil() {
			return nil
		}
		return redactValue(val.Elem(), fieldName)
	}

	// Check if this field should be redacted
	if fieldName != "" && isSensitiveField(fieldName) {
		// Redact non-empty string values (preserve empty strings for debugging)
		if val.Kind() == reflect.String {
			if val.String() != "" {
				return MaskedSecret
			}
			return "" // Preserve empty strings
		}
		// Redact slices/arrays of strings (e.g., url.Values which is map[string][]string)
		if val.Kind() == reflect.Slice || val.Kind() == reflect.Array {
			return redactSliceSensitive(val)
		}
		// Redact numbers: YAML decodes a credential written as unquoted
		// digits into an untyped map, such as a Vault auth_args, as one.
		if isNumber(val.Kind()) {
			return MaskedSecret
		}
		// Keep a bool, such as wrapping_token: it holds no credential.
	}

	if keep, ok := sensitiveContainers[strings.ToLower(fieldName)]; ok && val.Kind() == reflect.Map {
		return redactContainer(val, keep)
	}

	switch val.Kind() {
	case reflect.Map:
		return redactMap(val)
	case reflect.Struct:
		return redactStruct(val)
	case reflect.Slice, reflect.Array:
		return redactSlice(val)
	case reflect.String:
		return URL(val.String())
	case reflect.Bool:
		return val.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return val.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return val.Uint()
	case reflect.Float32, reflect.Float64:
		return val.Float()
	default:
		// For unknown types, try to return the interface value
		if val.CanInterface() {
			return val.Interface()
		}
		return nil
	}
}

// redactMap handles redaction of map types
func redactMap(val reflect.Value) any {
	if val.IsNil() {
		return nil
	}

	keys := newMaskedKeys(val.Len())
	// Redact each value, passing the field name for sensitive field detection
	for _, entry := range sortedEntries(val, func(keyStr string, value reflect.Value) any {
		return redactValue(value, keyStr)
	}) {
		keys.put(entry.name, entry.value)
	}

	return keys.result
}

// mapEntry is a key of a map, its name as mapKey writes it, and its value,
// redacted.
type mapEntry struct {
	key   reflect.Value
	name  string
	value any
}

// sortedEntries returns the entries of the map val, each value as redact
// returns it for its key's name, in the order of their keys' names, then of
// their keys' types, then of their redacted values as compareRedacted orders
// them, for keys written the same: two entries whose redacted values are the
// same give the same result in either order. It takes each value as it
// ranges the map: a key not equal to itself, as a NaN, finds no value when
// looked up again.
func sortedEntries(val reflect.Value, redact func(name string, value reflect.Value) any) []mapEntry {
	entries := make([]mapEntry, 0, val.Len())
	iter := val.MapRange()
	for iter.Next() {
		name := mapKey(iter.Key())
		entries = append(entries, mapEntry{iter.Key(), name, redact(name, iter.Value())})
	}
	slices.SortFunc(entries, func(a, b mapEntry) int {
		if c := strings.Compare(a.name, b.name); c != 0 {
			return c
		}
		if c := strings.Compare(fmt.Sprintf("%T", keyValue(a.key)), fmt.Sprintf("%T", keyValue(b.key))); c != 0 {
			return c
		}
		return compareRedacted(reflect.ValueOf(a.value), reflect.ValueOf(b.value))
	})
	return entries
}

// compareRedacted orders a and b, two values as they are redacted, by their
// types, nested ones included, then by what they hold, and stops at the
// first part that differs. It reads them by reflection alone: no method of a
// type, as a String that writes two values the same, is called. A redacted
// value is a tree of maps, slices and what they hold, which no pointer leads
// back into; a channel in it is ordered by its address, the same for the
// same channel at every call, and a function by its code's, which two
// closures of one function literal share and print the same.
func compareRedacted(a, b reflect.Value) int {
	if !a.IsValid() || !b.IsValid() {
		return cmp.Compare(boolOrder(a.IsValid()), boolOrder(b.IsValid()))
	}
	if c := strings.Compare(a.Type().String(), b.Type().String()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Kind(), b.Kind()); c != 0 {
		return c
	}
	switch a.Kind() {
	case reflect.Interface:
		return compareRedacted(a.Elem(), b.Elem())
	case reflect.Slice, reflect.Array:
		for i := range min(a.Len(), b.Len()) {
			if c := compareRedacted(a.Index(i), b.Index(i)); c != 0 {
				return c
			}
		}
		return cmp.Compare(a.Len(), b.Len())
	case reflect.Map:
		as, bs := sortedPairs(a), sortedPairs(b)
		for i := range min(len(as), len(bs)) {
			if c := compareRedacted(as[i][0], bs[i][0]); c != 0 {
				return c
			}
			if c := compareRedacted(as[i][1], bs[i][1]); c != 0 {
				return c
			}
		}
		return cmp.Compare(len(as), len(bs))
	case reflect.String:
		return strings.Compare(a.String(), b.String())
	case reflect.Bool:
		return cmp.Compare(boolOrder(a.Bool()), boolOrder(b.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return cmp.Compare(a.Int(), b.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return cmp.Compare(a.Uint(), b.Uint())
	case reflect.Float32, reflect.Float64:
		return compareFloats(a.Float(), b.Float())
	case reflect.Complex64, reflect.Complex128:
		if c := compareFloats(real(a.Complex()), real(b.Complex())); c != 0 {
			return c
		}
		return compareFloats(imag(a.Complex()), imag(b.Complex()))
	case reflect.Chan, reflect.Func, reflect.Pointer, reflect.UnsafePointer:
		return cmp.Compare(a.Pointer(), b.Pointer())
	}
	return 0
}

// sortedPairs returns the keys and values of the map m, in the order
// compareRedacted puts its keys in, then its values.
func sortedPairs(m reflect.Value) [][2]reflect.Value {
	pairs := make([][2]reflect.Value, 0, m.Len())
	iter := m.MapRange()
	for iter.Next() {
		pairs = append(pairs, [2]reflect.Value{iter.Key(), iter.Value()})
	}
	slices.SortFunc(pairs, func(a, b [2]reflect.Value) int {
		if c := compareRedacted(a[0], b[0]); c != 0 {
			return c
		}
		return compareRedacted(a[1], b[1])
	})
	return pairs
}

// compareFloats orders a and b as numbers, then by their bits, which tell
// -0 from 0 and one NaN from another.
func compareFloats(a, b float64) int {
	if c := cmp.Compare(a, b); c != 0 {
		return c
	}
	return cmp.Compare(math.Float64bits(a), math.Float64bits(b))
}

// boolOrder returns 1 for true and 0 for false.
func boolOrder(b bool) int {
	if b {
		return 1
	}
	return 0
}

// keyValue returns what key, a map's key or value, holds behind its
// interface.
func keyValue(key reflect.Value) any {
	for key.Kind() == reflect.Interface && !key.IsNil() {
		key = key.Elem()
	}
	if key.CanInterface() {
		return key.Interface()
	}
	return nil
}

// maskedKeys puts values in a map under keys masked as URL masks one in a
// value. A key another one was masked into already gets " (2)", " (3)"...
// after it, so no entry of the map is lost. The next number of each masked
// key is kept, so that many keys masked into one cost no more than others.
type maskedKeys struct {
	result map[string]any
	next   map[string]int
}

// newMaskedKeys returns a maskedKeys for a map of n entries.
func newMaskedKeys(n int) *maskedKeys {
	return &maskedKeys{result: make(map[string]any, n), next: map[string]int{}}
}

// put sets v under key, masked.
func (m *maskedKeys) put(key string, v any) {
	masked := URL(key)
	k := masked
	if _, taken := m.result[k]; taken {
		n := max(m.next[masked], 2)
		for {
			k = fmt.Sprintf("%s (%d)", masked, n)
			n++
			if _, taken := m.result[k]; !taken {
				break
			}
		}
		m.next[masked] = n
	}
	m.result[k] = v
}

// mapKey returns a map key as a string, as written: its field name.
func mapKey(key reflect.Value) string {
	if key.Kind() == reflect.String {
		return key.String()
	}
	if key.CanInterface() {
		// Safely convert non-string keys using fmt.Sprintf
		if str, ok := key.Interface().(string); ok {
			return str
		}
		return fmt.Sprintf("%v", key.Interface())
	}
	// Fallback for unexported keys
	return fmt.Sprintf("%v", key)
}

// URL returns s with the user info of every URL it holds masked as ********,
// as a Vault address carries one for a proxy that asks for basic auth in
// front of Vault, or each URL of a list does. The user and the password are
// masked together: the user is half of the login, the whole of it when the
// password is empty, and can be a token. s is read as one URL; each of its
// words, between the separators a list puts between URLs, as one too; and so
// is each URL in a word, as one after another's query, from its scheme to
// the next URL or separator. What any reading masks is masked, so a password
// that holds a separator is still masked whole. A secret reference, as
// ${vault://mount/path/key}, is kept as written. Any other s is returned as
// it is.
func URL(s string) string {
	if !strings.Contains(s, "@") {
		return s
	}
	texts := []string{s}
	// s is read again with what looks like a reference as a run of x, so that
	// its :// and braces read as nothing a URL holds.
	if looks := referencePattern.FindAllStringIndex(s, -1); len(looks) > 0 {
		b := []byte(s)
		for _, ref := range looks {
			for i := ref[0]; i < ref[1]; i++ {
				b[i] = 'x'
			}
		}
		texts = append(texts, string(b))
	}
	// And with each tab as a space, which a URL parser takes in a password,
	// where it refuses a tab.
	if strings.IndexByte(s, '\t') >= 0 {
		n := len(texts)
		for _, t := range texts[:n] {
			texts = append(texts, strings.ReplaceAll(t, "\t", " "))
		}
	}
	// What any reading masks is masked.
	var spans []span
	for _, t := range texts {
		spans = append(spans, spansOf(t)...)
	}
	return maskSpans(s, withoutReferences(references(s), spans))
}

// spansOf returns where the user infos of t are: t read as one URL, each of
// its words read as one, and each URL in a word read as one.
func spansOf(t string) []span {
	spans := userInfoSpans(t, 0, false)
	word := 0
	for i := 0; i <= len(t); i++ {
		if i < len(t) && strings.IndexByte(urlSeparators, t[i]) < 0 {
			continue
		}
		if i > word && i-word < len(t) {
			spans = append(spans, userInfoSpans(t[word:i], word, true)...)
		}
		word = i + 1
	}
	for i := strings.Index(t, "//"); i >= 0; {
		if i+len("//") < len(t) && t[i+len("//")] == '/' {
			// An empty authority, as dns:/// writes, or a third /: the URL is
			// read from the next //.
			i++
			continue
		}
		// From its scheme and :, or from its // when it is written without.
		start := i
		if i > 0 && t[i-1] == ':' {
			start = i - 1
			for start > 0 && isSchemeByte(t[start-1]) {
				start--
			}
		}
		end, next := urlEnd(t, i, urlSeparators)
		if start > 0 {
			spans = append(spans, userInfoSpans(t[start:end], start, true)...)
			// And to the end of its word, as it is read alone: a password can
			// hold a ? or a #, which ends it above, where its last @ ends it.
			if whole, _ := urlEnd(t, i, wordSeparators); whole > end {
				spans = append(spans, userInfoSpans(t[start:whole], start, true)...)
			}
		}
		i = next
		if next < 0 {
			if j := strings.Index(t[end:], "//"); j >= 0 {
				i = end + j
			}
		}
	}
	// A user and a password right before an @, from the /, separator or @
	// before them, as a URL written without // in another's path holds them,
	// or a user before git's scp-like host:path. They are also read:
	//   - from the last / before them, in a path, through the @ and the
	//     separators a user info can hold; when that / ends a //, it starts
	//     an authority, so a user alone is masked as well, as a token is;
	//   - in a query or a fragment, from the first = after the last ?, # or &
	//     before them, which ends a parameter's name, or from that ?, # or &
	//     when no such = follows it, through the same but &, which separates
	//     values there;
	//   - in a flag's value, as in -Dhttp.proxy=user:pa==@host, from the first
	//     = after the last other separator before them, or after the start
	//     of the text, which ends the flag's name, or from that separator when
	//     a : comes before that =, through the = that base64's padding ends a
	//     password with.
	// Where each reading starts, and the last :, are kept from one @ to the
	// next, so the text is read in time in line with its length.
	from, inPath, inQuery, inFlag, colon := 0, -1, -1, -1, -1
	inAuthority := false
	for at := strings.IndexByte(t, '@'); at >= 0; {
		seg := t[from:at]
		if i := strings.LastIndexByte(seg, ':'); i >= 0 {
			colon = from + i
		}
		if i := strings.LastIndexAny(seg, "/"+pathSeparators); i >= 0 {
			inPath, inAuthority = -1, false
			if seg[i] == '/' {
				inPath = from + i + 1
				// A /// is read from its last //, as the URL that follows it.
				inAuthority = strings.HasSuffix(t[:inPath], "//")
			}
		}
		if i := strings.LastIndexAny(seg, "/&"+pathSeparators); i >= 0 {
			inQuery = -1
			if strings.IndexByte("?#&", seg[i]) >= 0 {
				inQuery = from + i + 1
				if eq, named := valueAt(seg[i+1:]); named {
					inQuery += eq + 1
				}
			}
		}
		if i := strings.LastIndexAny(seg, "/,;&'()"+pathSeparators); i >= 0 || from == 0 {
			inFlag = -1
			if eq, named := valueAt(seg[i+1:]); eq >= 0 && (i < 0 || seg[i] != '/') {
				inFlag = from + i + 1
				if named {
					inFlag += eq + 1
				}
			}
		}
		scp := scpHost(t[at+1:])
		begin := from + strings.LastIndexAny(seg, "/@"+urlSeparators) + 1
		for _, head := range [...]int{begin, inPath, inQuery, inFlag} {
			if head >= 0 && head <= begin && (colon >= head || head < at && (scp || head == inPath && inAuthority)) {
				spans = append(spans, span{head, at})
			}
		}
		from = at + 1
		next := strings.IndexByte(t[from:], '@')
		if next < 0 {
			break
		}
		at = from + next
	}
	return spans
}

// valueAt returns where the first = of s, a query's parameter or a flag, is,
// or -1, and whether it ends a name: no : comes before it, as a name holds
// none, where a user and a password before an = in the password hold one.
func valueAt(s string) (int, bool) {
	eq := strings.IndexByte(s, '=')
	colon := strings.IndexByte(s, ':')
	return eq, eq >= 0 && (colon < 0 || eq < colon)
}

// urlEnd returns where the URL whose // is at i in t ends: at the first of
// stops, or at the next URL, without its scheme, whose // it returns too, or
// -1.
func urlEnd(t string, i int, stops string) (end, next int) {
	end, next = i+len("//"), -1
	for end < len(t) && strings.IndexByte(stops, t[end]) < 0 && !strings.HasPrefix(t[end:], "//") {
		end++
	}
	if strings.HasPrefix(t[end:], "//") {
		next = end
		if end > i+len("//") && t[end-1] == ':' {
			end--
			for end > i+len("//") && isSchemeByte(t[end-1]) {
				end--
			}
		}
	}
	return end, next
}

// scpHost reports whether s, what follows an @, starts as git's scp-like
// host:path does: a host, a : and a path, which no separator starts.
func scpHost(s string) bool {
	colon := strings.IndexAny(s, ":/@"+urlSeparators)
	return colon > 0 && s[colon] == ':' && colon+1 < len(s) && strings.IndexByte(urlSeparators, s[colon+1]) < 0
}

// isSchemeByte reports whether c can be part of a URL's scheme.
func isSchemeByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
}

// urlSeparators are the bytes that can come between the URLs of a list, or
// after another URL's query, fragment or a value of its query.
const urlSeparators = pathSeparators + ",;=&'()"

// pathSeparators are the urlSeparators that a path or a user info can't hold:
// RFC 3986 lets both hold a , ; = & ' ( or ).
const pathSeparators = " \t\r\n|?#\"`<>[]{}"

// wordSeparators are the bytes that no URL holds, which a text puts between
// its words.
const wordSeparators = " \t\r\n\"`<>|"

// span is the bytes [from, to) of a text.
type span struct{ from, to int }

// userInfoSpans returns where the user info of t, read as one URL, is, in
// the text t starts at off in; word tells t is a word of that text.
func userInfoSpans(t string, off int, word bool) []span {
	at := userInfoAt(t)
	if at < 0 {
		return nil
	}
	// The user info starts after the // of a URL written without a scheme,
	// whatever follows, or after the scheme's ://.
	start := len("//")
	if !strings.HasPrefix(t, "//") {
		scheme := strings.Index(t, "://")
		if scheme < 0 {
			return opaqueSpans(t, at, off, word)
		}
		start = scheme + len("://")
	}
	if at < start {
		return nil
	}
	if u, err := url.Parse(t); err == nil && u.User != nil {
		// A parser reads its user info up to the last @ of its authority,
		// which ends at its first / ? or #.
		authority := t[start:]
		if end := strings.IndexAny(authority, "/?#"); end >= 0 {
			authority = authority[:end]
		}
		if a := strings.LastIndexByte(authority, '@'); a >= 0 {
			return []span{{off + start, off + start + a}}
		}
	}
	// No URL parser reads it, as when a password holds a / ? # % or a space
	// that is not escaped, or a parser reads its @ as part of a path, query
	// or fragment, as when a token given as the user holds a / ? or #. Where
	// its user info ends is a guess: everything between // and the last @ is
	// masked, even when the @ is a path's.
	return []span{{off + start, off + at}}
}

// opaqueSpans returns where the user info of t, a URL written without // and
// whose last @ is at, is, in the text t starts at off in. When the part
// before its last @ holds a :, as a user and a password do in
// user:password@host, or a token and x-oauth-basic in git's
// token:x-oauth-basic@host:path, all of that part is: a parser reads such a
// user, or token, as the URL's scheme, so a scheme written before it, as in
// https:user:password@host, is masked with it. What a parser reads as a
// scheme's opaque part, before its last @, is too. In git's scp-like
// user@host:path, which no parser reads, its user is; in a word, only when a
// path follows its :, as an e-mail address that ends a clause of a text, as
// in "write to ops@example.com: now", does not.
func opaqueSpans(t string, at, off int, word bool) []span {
	var spans []span
	if holdsUserInfo(t[:at]) {
		// In a text, the user starts after the separator before its :, as
		// after a flag's = in -Dhttp.proxy=user:password@host.
		from := strings.LastIndexAny(t[:strings.IndexByte(t, ':')], urlSeparators) + 1
		spans = append(spans, span{off + from, off + at})
	}
	if u, err := url.Parse(t); err == nil && u.Scheme != "" && strings.Contains(u.Opaque, "@") {
		if colon := strings.IndexByte(t, ':'); colon < at {
			spans = append(spans, span{off + colon + 1, off + at})
		}
	}
	if user, ok := scpUser(t); ok && (!word || t[strings.IndexByte(t, ':')+1:] != "") {
		spans = append(spans, span{off, off + len(user)})
	}
	return spans
}

// userInfoAt returns where the last @ of t is, which can end a user info, or
// -1. The @ of an image's digest, as in img@sha256:..., is one too: nothing
// tells it from git's user@host:path for a host named sha256.
func userInfoAt(t string) int {
	return strings.LastIndexByte(t, '@')
}

// referencePattern matches a secret reference, as ${vault://mount/path/key},
// as the agent's secrets managers match one: for the schemes they resolve,
// with a body of anything but a }, as a Vault path or field can hold.
// Anything else in ${...}, as ${https://user:password@host}, is no reference.
var referencePattern = regexp.MustCompile(`\$\{(?:vault|fleet|doppler|delinea|cyberark|dsv)://([^}]*)\}`)

// references returns where the secret references of s are, in order: those
// referencePattern matches with no @ in their body nor in the word their }
// ends. A body with an @ can be what a ${ that no } closed before a URL took
// in, up to a } further on, as in ${vault://kv/a/b,https://user:password@host},
// and nothing tells that from a name holding an @, as a Vault field or a
// CyberArk Safe can; an @ after the } can end a password that holds the }. Such
// a reference is masked as the rest of s is. That is only where s is reported
// or logged; the reference still resolves as written.
func references(s string) [][]int {
	var refs [][]int
	for _, ref := range referencePattern.FindAllStringSubmatchIndex(s, -1) {
		after := s[ref[1]:]
		if end := strings.IndexAny(after, urlSeparators); end >= 0 {
			after = after[:end]
		}
		if !strings.Contains(s[ref[2]:ref[3]], "@") && !strings.Contains(after, "@") {
			refs = append(refs, ref[:2])
		}
	}
	return refs
}

// withoutReferences returns spans with the secret references refs, in order,
// taken out of them: a reference is not its value, and is kept as written.
// The spans are merged first, so that each reference is taken out of the few
// it overlaps, however many spans cover it.
func withoutReferences(refs [][]int, spans []span) []span {
	if len(refs) == 0 {
		return spans
	}
	var kept []span
	r := 0
	for _, sp := range merged(spans) {
		for r < len(refs) && refs[r][1] <= sp.from {
			r++
		}
		from := sp.from
		for _, ref := range refs[r:] {
			if ref[0] >= sp.to {
				break
			}
			if from < ref[0] {
				kept = append(kept, span{from, ref[0]})
			}
			from = max(from, ref[1])
		}
		if from < sp.to {
			kept = append(kept, span{from, sp.to})
		}
	}
	return kept
}

// merged returns spans in order, those that overlap or touch made one, and
// those that cover no byte left out.
func merged(spans []span) []span {
	slices.SortFunc(spans, func(a, b span) int { return a.from - b.from })
	var runs []span
	for _, sp := range spans {
		switch {
		case sp.from >= sp.to:
		case len(runs) > 0 && sp.from <= runs[len(runs)-1].to:
			runs[len(runs)-1].to = max(runs[len(runs)-1].to, sp.to)
		default:
			runs = append(runs, sp)
		}
	}
	return runs
}

// maskSpans returns s with each run of bytes the spans cover replaced by
// ********.
func maskSpans(s string, spans []span) string {
	runs := merged(spans)
	if len(runs) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, run := range runs {
		b.WriteString(s[last:run.from])
		b.WriteString(MaskedSecret)
		last = run.to
	}
	b.WriteString(s[last:])
	return b.String()
}

// Endpoint returns s, a value its caller knows is a URL or a host address,
// as a collector's or a secrets manager's is, with the user info it carries
// masked as ********. Written from its scheme's :// or from its //, it is
// masked as URL masks it, but for an empty authority, as gRPC's dns:/// and
// unix:/// write one, whose third / it keeps. Written without //,
// everything before its last @ is masked, a user alone too: URL keeps a user
// alone with no : after it, as it can't tell it from the name of an e-mail
// address in the strings SensitiveData masks.
func Endpoint(s string) string {
	if startsWithScheme(s) {
		if rest := s[strings.Index(s, "://")+len("://"):]; strings.HasPrefix(rest, "/") {
			return s[:len(s)-len(rest)+1] + Endpoint(rest[1:])
		}
		return URL(s)
	}
	if strings.HasPrefix(s, "//") {
		return URL(s)
	}
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return s
	}
	return MaskedSecret + s[at:]
}

// startsWithScheme reports whether s starts with a scheme and its ://.
func startsWithScheme(s string) bool {
	end := strings.Index(s, "://")
	if end <= 0 {
		return false
	}
	for i, c := range s[:end] {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// holdsUserInfo reports whether head, what a URL written without // has
// before its last @, holds a user and a password: a :, with no space, which
// makes it a text, and no / before it, which makes it a path.
func holdsUserInfo(head string) bool {
	colon := strings.IndexByte(head, ':')
	return colon >= 0 && !strings.ContainsAny(head, " \t\r\n") && !strings.Contains(head[:colon], "/")
}

// scpUser returns the user of s when git reads s as scp-like user@host:path:
// what comes before the last @ before its first :, when no / does and it is
// not empty. A space there makes s a text, which SensitiveData keeps, rather
// than an address.
func scpUser(s string) (string, bool) {
	head, _, ok := strings.Cut(s, ":")
	at := strings.LastIndex(head, "@")
	if !ok || at <= 0 || strings.ContainsAny(head, "/ \t\r\n") {
		return "", false
	}
	return head[:at], true
}

// isString reports whether val holds a string, through any pointer or
// interface.
func isString(val reflect.Value) bool {
	for val.IsValid() && (val.Kind() == reflect.Pointer || val.Kind() == reflect.Interface) {
		if val.IsNil() {
			return false
		}
		val = val.Elem()
	}
	return val.IsValid() && val.Kind() == reflect.String
}

// redactContainer masks every value of a sensitive container's map but those
// of the fields named in keep, which are redacted as anywhere else.
func redactContainer(val reflect.Value, keep []string) any {
	if val.IsNil() {
		return nil
	}

	keys := newMaskedKeys(val.Len())
	for _, entry := range sortedEntries(val, func(keyStr string, value reflect.Value) any {
		// A login reads a field under its exact name, and as a string.
		if slices.Contains(keep, keyStr) && isString(value) {
			return redactValue(value, keyStr)
		}
		return maskLeaves(value)
	}) {
		keys.put(entry.name, entry.value)
	}

	return keys.result
}

// maskLeaves masks every string and number in val, nested or listed, and
// keeps empty strings, bools and the shape of its maps and slices.
func maskLeaves(val reflect.Value) any {
	if !val.IsValid() {
		return nil
	}

	switch val.Kind() {
	case reflect.Pointer, reflect.Interface:
		if val.IsNil() {
			return nil
		}
		return maskLeaves(val.Elem())
	case reflect.String:
		if val.String() == "" {
			return ""
		}
		return MaskedSecret
	case reflect.Bool:
		return val.Bool()
	case reflect.Map:
		if val.IsNil() {
			return nil
		}
		keys := newMaskedKeys(val.Len())
		for _, entry := range sortedEntries(val, func(_ string, value reflect.Value) any { return maskLeaves(value) }) {
			keys.put(entry.name, entry.value)
		}
		return keys.result
	case reflect.Slice, reflect.Array:
		if val.Kind() == reflect.Slice && val.IsNil() {
			return nil
		}
		result := make([]any, val.Len())
		for i := range val.Len() {
			result[i] = maskLeaves(val.Index(i))
		}
		return result
	default:
		// A number, or anything else a credential could be held in.
		return MaskedSecret
	}
}

// isNumber reports whether kind is an integer or a float.
func isNumber(kind reflect.Kind) bool {
	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// redactStruct handles redaction of struct types
func redactStruct(val reflect.Value) any {
	typ := val.Type()
	result := make(map[string]any, val.NumField())

	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		fieldValue := val.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Get the field name from tags or use the struct field name
		fieldName := field.Name
		if jsonTag := field.Tag.Get("json"); jsonTag != "" && jsonTag != "-" {
			// Parse json tag (handle "name,omitempty" format)
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" {
				fieldName = parts[0]
			}
		} else if yamlTag := field.Tag.Get("yaml"); yamlTag != "" && yamlTag != "-" {
			// Parse yaml tag
			parts := strings.Split(yamlTag, ",")
			if parts[0] != "" {
				fieldName = parts[0]
			}
		}

		// Redact the field value
		result[fieldName] = redactValue(fieldValue, fieldName)
	}

	return result
}

// redactSliceSensitive handles redaction of slice/array values for sensitive fields
// It masks all string elements since the field itself is sensitive (e.g., url.Values)
func redactSliceSensitive(val reflect.Value) any {
	if val.Kind() == reflect.Slice && val.IsNil() {
		return nil
	}

	length := val.Len()
	result := make([]any, length)

	for i := 0; i < length; i++ {
		elem := val.Index(i)
		// Mask string elements in sensitive slices
		if elem.Kind() == reflect.String {
			result[i] = MaskedSecret
		} else {
			result[i] = redactValue(elem, "")
		}
	}

	return result
}

// redactSlice handles redaction of slice and array types
func redactSlice(val reflect.Value) any {
	if val.Kind() == reflect.Slice && val.IsNil() {
		return nil
	}

	length := val.Len()
	result := make([]any, length)

	for i := 0; i < length; i++ {
		elem := val.Index(i)
		result[i] = redactValue(elem, "")
	}

	return result
}

// isSensitiveField checks if a field name matches sensitive patterns
func isSensitiveField(fieldName string) bool {
	lower := strings.ToLower(fieldName)

	// Check exact matches first (to avoid false positives like "token_url")
	for _, pattern := range sensitiveFieldPatterns {
		if lower == pattern {
			return true
		}
	}

	// Check suffixes (e.g., "my_custom_secret" matches "_secret")
	for _, suffix := range sensitiveFieldSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}

	return false
}

// Args creates a copy of command-line arguments with sensitive values masked.
// It detects sensitive flags (like --client-secret) and masks their values.
// Returns a new slice - the original is never modified.
func Args(args []string) []string {
	if args == nil {
		return nil
	}

	// Create a copy of the slice
	result := make([]string, len(args))
	copy(result, args)

	// Scan for sensitive flags and mask the following value
	for i := 0; i < len(result); i++ {
		if isSensitiveArg(result[i]) {
			// Mask the next argument if it exists
			if i+1 < len(result) {
				result[i+1] = MaskedSecret
				i++ // Skip the next iteration since we just processed it
			}
		}
	}

	return result
}

// isSensitiveArg checks if a CLI argument is a sensitive flag
func isSensitiveArg(arg string) bool {
	lower := strings.ToLower(arg)

	// Check exact matches
	for _, pattern := range sensitiveFlagPatterns {
		if lower == pattern {
			return true
		}
	}

	// Check suffixes
	for _, suffix := range sensitiveFlagSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}

	return false
}
