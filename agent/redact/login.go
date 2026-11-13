package redact

import (
	"bytes"
	"cmp"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
)

// Logins returns the login that the value of each flag of args naming an
// endpoint or a target carries, in every form LoginForms returns, the
// longest first. A process given such a URL can write its address, login
// included, in a line of its own, as a gRPC client does for an address it
// cannot dial; the agent masks the logins where a line it relays writes
// them (see MaskLogins).
func Logins(args []string) []string {
	var forms []string
	for i := 0; i+1 < len(args); i++ {
		if !isEndpointArg(args[i]) {
			continue
		}
		i++
		forms = append(forms, LoginForms(args[i])...)
	}
	return longestFirst(forms)
}

// LoginForms returns the forms in which a text can write the login that s,
// a value its caller knows is a URL or a host address, carries, the longest
// first, or nil when it carries none. The login is what Endpoint masks of s
// trimmed, as a URL parser trims it. The forms are the login as written;
// percent-decoded as a path and as a query, whole and its user and password
// each, as a gRPC client decodes the address it is given before it writes it
// in an error; and each of those quoted as Go's %q and JSON quote a string.
func LoginForms(s string) []string {
	written := login(strings.TrimSpace(s))
	if written == "" {
		return nil
	}
	plain := []string{written}
	user, password, hasPassword := strings.Cut(written, ":")
	for _, unescape := range []func(string) (string, error){url.PathUnescape, url.QueryUnescape} {
		if decoded, err := unescape(written); err == nil {
			plain = append(plain, decoded)
		}
		decoded := unescapedOrAsIs(unescape, user)
		if hasPassword {
			decoded += ":" + unescapedOrAsIs(unescape, password)
		}
		plain = append(plain, decoded)
	}
	forms := slices.Clone(plain)
	for _, p := range plain {
		forms = append(forms, quoted(p), jsonQuoted(p, false), jsonQuoted(p, true))
	}
	return longestFirst(forms)
}

// MaskLogins returns text with each of logins, as Logins and LoginForms
// return them, masked as ******** wherever text writes it as an address
// does: before an @, and at the start of a word, after the start of the text,
// a space, a quote, a bracket, a ,, a =, a / or an escaped line break, so a
// login is not masked inside a longer user, as ops is in noc-ops@host. The
// longest are masked first, so no part of one that holds a shorter one is
// left.
func MaskLogins(text string, logins []string) string {
	for _, l := range longestFirst(logins) {
		text = maskLogin(text, l)
	}
	return text
}

// maskLogin returns text with login masked where it starts a word before an @.
func maskLogin(text, login string) string {
	if login == "" {
		return text
	}
	needle := login + "@"
	var b strings.Builder
	last := 0
	for i := 0; i < len(text); {
		j := strings.Index(text[i:], needle)
		if j < 0 {
			break
		}
		j += i
		if !startsWord(text, j) {
			i = j + 1
			continue
		}
		b.WriteString(text[last:j])
		b.WriteString(MaskedSecret)
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

// login returns the user info s, a value its caller knows is a URL or a host
// address, carries as written: the part of it Endpoint masks, or "" when
// Endpoint masks none, or more than one.
func login(s string) string {
	masked := Endpoint(s)
	from := strings.Index(masked, MaskedSecret)
	if masked == s || from < 0 {
		return ""
	}
	tail := masked[from+len(MaskedSecret):]
	if strings.Contains(tail, MaskedSecret) {
		return ""
	}
	return s[from : len(s)-len(tail)]
}

// unescapedOrAsIs returns s unescaped, or s when it does not unescape.
func unescapedOrAsIs(unescape func(string) (string, error), s string) string {
	if u, err := unescape(s); err == nil {
		return u
	}
	return s
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
