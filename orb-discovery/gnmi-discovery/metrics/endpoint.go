package metrics

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The login a collector URL carries is read and masked here as the agent
// reads and masks it in the lines it relays (agent/redact/login.go), so the
// two agree on every line.

// maskedLogin replaces the login of a collector URL where a line writes it.
const maskedLogin = "********"

// MaskedEndpoint returns endpoint, a collector URL or host:port, with the
// login it carries, as grpc://user:password@host:port or
// user:password@host:port, masked as ********, for a line that reports it.
// The exporter is given endpoint as written.
func MaskedEndpoint(endpoint string) string {
	return maskLogin(endpoint, endpoint)
}

// maskLogin returns text with the login endpoint carries masked wherever
// text writes it, in every form loginForms returns.
func maskLogin(text, endpoint string) string {
	return maskForms(text, loginForms(endpoint))
}

// loginForms returns the forms in which a text can write the login that
// endpoint carries, the longest first, or nil when it carries none (see
// login). The forms are:
//   - the login as written, and without a gRPC resolver's scheme written
//     before it without //, as dns:user:password@host, which gRPC strips;
//   - each of those percent-decoded, whole and its user and password each:
//     as a path and as a query, and leniently, keeping an invalid %XX, as a
//     gRPC client decodes the address before it writes it in an error;
//   - a decoded form that is not UTF-8 also as Latin-1, as Python's gRPC
//     writes it, and with each invalid byte as U+FFFD, as the agent relays a
//     line that holds one;
//   - each of those quoted as Go's %q and %+q, and as JSON quotes a string,
//     with <, > and & escaped and not, and with every rune past ASCII
//     escaped, as Python's json.dumps writes it.
func loginForms(endpoint string) []string {
	var plain []string
	for _, written := range writtenLogins(endpoint) {
		plain = append(plain, written)
		user, password, hasPassword := strings.Cut(written, ":")
		for _, unescape := range []func(string) (string, error){url.PathUnescape, url.QueryUnescape, lenientUnescape} {
			if decoded, err := unescape(written); err == nil {
				plain = append(plain, decoded)
			}
			decoded := unescapedOrAsIs(unescape, user)
			if hasPassword {
				decoded += ":" + unescapedOrAsIs(unescape, password)
			}
			plain = append(plain, decoded)
		}
	}
	for _, p := range slices.Clone(plain) {
		if !utf8.ValidString(p) {
			plain = append(plain, latin1(p), string([]rune(p)))
		}
	}
	forms := slices.Clone(plain)
	for _, p := range plain {
		forms = append(forms, quoted(p), quotedASCII(p), jsonQuoted(p, false), jsonQuoted(p, true), jsonQuotedASCII(p))
	}
	return longestFirst(forms)
}

// maskForms returns text with each of logins, as loginForms returns them,
// masked as ******** wherever text writes it before an @. A
// user and a password are masked wherever they come, after a log format's
// :, a digit or an ANSI colour code too. A user alone, as a token, is masked
// only where it starts a word: after the start of the text, a space, a
// quote, a bracket, a ,, a =, a / or an escaped line break, so it is not
// masked inside a longer user, as ops is in noc-ops@host. The longest are
// masked first, so no part of one that holds a shorter one is left.
func maskForms(text string, logins []string) string {
	for _, l := range longestFirst(logins) {
		text = maskForm(text, l)
	}
	return text
}

// maskForm returns text with login masked where it comes before an @, and,
// for a user alone, where it also starts a word.
func maskForm(text, login string) string {
	if login == "" {
		return text
	}
	needle := login + "@"
	anywhere := strings.Contains(login, ":")
	var b strings.Builder
	last := 0
	for i := 0; i < len(text); {
		j := strings.Index(text[i:], needle)
		if j < 0 {
			break
		}
		j += i
		if !anywhere && !startsWord(text, j) {
			i = j + 1
			continue
		}
		b.WriteString(text[last:j])
		b.WriteString(maskedLogin)
		last = j + len(login)
		i = j + len(needle)
	}
	if last == 0 {
		return text
	}
	b.WriteString(text[last:])
	return b.String()
}

// startsWord reports whether a login found at i in text starts a word: no
// byte a login holds comes right before it, or an escaped line break, \n,
// \r or \t, as JSON writes one, does.
func startsWord(text string, i int) bool {
	if i == 0 || !isLoginByte(text[i-1]) {
		return true
	}
	return i >= 2 && text[i-2] == '\\' && strings.IndexByte("nrt", text[i-1]) >= 0
}

// isLoginByte reports whether c can be part of a user or a password as an
// address writes it: a letter, a digit, a % that escapes a byte, or one of
// - . _ ~ ! $ & * + ; :, which RFC 3986 lets a user info hold. The others it
// lets one hold, ' ( ) , and =, also separate words in a text.
func isLoginByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("%-._~!$&*+;:", c) >= 0
}

// grpcResolvers are the schemes of the gRPC resolvers a target can name
// without //, as dns:host:port: gRPC strips the scheme before it writes the
// address.
var grpcResolvers = []string{"dns:", "unix:", "unix-abstract:", "vsock:", "ipv4:", "ipv6:", "passthrough:"}

// writtenLogins returns the login s carries as written (see login), and,
// when s is written without // after a gRPC resolver's scheme, the login
// without that scheme too, or nil when s carries none.
func writtenLogins(s string) []string {
	written, bare := login(s)
	if written == "" {
		return nil
	}
	logins := []string{written}
	if bare {
		for _, scheme := range grpcResolvers {
			if len(written) > len(scheme) && strings.EqualFold(written[:len(scheme)], scheme) {
				logins = append(logins, written[len(scheme):])
			}
		}
	}
	return logins
}

// login returns the user info s, a value its caller knows is a URL or a host
// address, carries as written, or "", and whether s is written without //.
// s is read trimmed, as a URL parser reads it. Written from a scheme's :// or
// from //, its login is what its authority, up to its first / ? or #, holds
// before its last @, after the third / of an empty authority, as gRPC's
// dns:/// writes one, whatever its path, query or fragment hold and whether
// or not a parser reads it; or, when the authority holds no @, as when a
// password holds an unescaped /, what comes before its last @. Written
// without //, as user:password@host:port, it is everything before the last
// @, a // or :// in the password included, as Endpoint masks it.
func login(s string) (string, bool) {
	s = strings.TrimSpace(s)
	start := 0
	switch {
	case startsWithScheme(s):
		start = strings.Index(s, "://") + len("://")
	case strings.HasPrefix(s, "//"):
		start = len("//")
	}
	if start > 0 {
		for start < len(s) && s[start] == '/' {
			start++
		}
		authority := s[start:]
		if end := strings.IndexAny(authority, "/?#"); end >= 0 {
			authority = authority[:end]
		}
		if at := strings.LastIndex(authority, "@"); at >= 0 {
			return authority[:at], false
		}
	}
	at := strings.LastIndex(s, "@")
	if at <= start {
		return "", false
	}
	return s[start:at], start == 0
}

// lenientUnescape returns s with each valid %XX decoded and every other %
// kept, as a gRPC client decodes an address. It never fails.
func lenientUnescape(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			v, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b.WriteByte(byte(v))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String(), nil
}

// isHex reports whether c is a hexadecimal digit.
func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// latin1 returns s with each byte read as the rune of the same number, as
// Latin-1 reads it.
func latin1(s string) string {
	r := make([]rune, len(s))
	for i := 0; i < len(s); i++ {
		r[i] = rune(s[i])
	}
	return string(r)
}

// unescapedOrAsIs returns s unescaped, or s when it does not unescape.
func unescapedOrAsIs(unescape func(string) (string, error), s string) string {
	if u, err := unescape(s); err == nil {
		return u
	}
	return s
}

// quotedASCII returns s as Go's %+q quotes it, without the quotes.
func quotedASCII(s string) string {
	q := strconv.QuoteToASCII(s)
	return q[1 : len(q)-1]
}

// jsonQuoted returns s as JSON quotes it, without the quotes: with <, > and &
// escaped, as encoding/json writes them by default, or as they are, as
// log/slog's JSON handler writes them.
func jsonQuoted(s string, escapeHTML bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(s); err != nil {
		return s
	}
	q := strings.TrimSuffix(b.String(), "\n")
	return q[1 : len(q)-1]
}

// jsonQuotedASCII returns s as Python's json.dumps quotes it by default,
// without the quotes: as JSON does, with every rune past ASCII written as
// \uXXXX, or as a surrogate pair past U+FFFF.
func jsonQuotedASCII(s string) string {
	var b strings.Builder
	for _, r := range jsonQuoted(s, false) {
		switch {
		case r < utf8.RuneSelf:
			b.WriteRune(r)
		case r > 0xFFFF:
			r -= 0x10000
			fmt.Fprintf(&b, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

// longestFirst returns forms without the empty ones and those repeated, the
// longest first.
func longestFirst(forms []string) []string {
	var out []string
	for _, f := range forms {
		if f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	slices.SortStableFunc(out, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	return out
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

// quoted returns s as Go's %q quotes it, without the quotes.
func quoted(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}
