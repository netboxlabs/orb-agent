package metrics

import (
	"cmp"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// maskedLogin replaces the login of a collector URL where a line writes it.
const maskedLogin = "********"

// MaskedEndpoint returns endpoint, a collector URL or host:port, with the
// login it carries, as grpc://user:password@host:port or
// user:password@host:port, masked as ********, for a line that reports it.
// The exporter is given endpoint as written.
func MaskedEndpoint(endpoint string) string {
	return maskLogin(endpoint, endpoint)
}

// maskLogin returns text with the login endpoint carries masked wherever text
// writes it as an address does: before an @, at the start of a word, so a
// user alone is not masked inside a longer user, as ops is in noc-ops@host;
// as written, percent-decoded, as a gRPC client writes the address in its
// errors, or quoted as %q quotes it. The longest form is masked first, so no
// part of one is left.
func maskLogin(text, endpoint string) string {
	for _, form := range loginForms(endpoint) {
		text = maskForm(text, form)
	}
	return text
}

// loginForms returns the forms in which a text can write the login endpoint
// carries, the longest first: as written; percent-decoded as a path and as a
// query, whole and its user and password each; and each of those quoted as
// %q quotes it.
func loginForms(endpoint string) []string {
	login := endpointLogin(endpoint)
	if login == "" {
		return nil
	}
	plain := []string{login}
	user, password, hasPassword := strings.Cut(login, ":")
	for _, unescape := range []func(string) (string, error){url.PathUnescape, url.QueryUnescape} {
		if decoded, err := unescape(login); err == nil {
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
		q := strconv.Quote(p)
		forms = append(forms, q[1:len(q)-1])
	}
	var out []string
	for _, f := range forms {
		if f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	slices.SortStableFunc(out, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	return out
}

// endpointLogin returns the login endpoint carries, as written, or "". The
// endpoint is read trimmed, as a URL parser reads it. Written from a
// scheme's :// or from //, its login is what its authority holds before its
// last @, after the third / of an empty authority, as gRPC's dns:/// writes
// one; or, when no parser reads its authority's user info, as when a password
// holds an unescaped /, what comes before its last @. Written without //, as
// user:password@host:port, it is everything before the last @, a // or a ://
// in the password included.
func endpointLogin(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	start := 0
	if i := strings.Index(endpoint, "://"); i > 0 && isScheme(endpoint[:i]) {
		start = i + len("://")
	} else if strings.HasPrefix(endpoint, "//") {
		start = len("//")
	}
	if start > 0 {
		for start < len(endpoint) && endpoint[start] == '/' {
			start++
		}
		if u, err := url.Parse(endpoint); err == nil && u.User != nil {
			authority := endpoint[start:]
			if end := strings.IndexAny(authority, "/?#"); end >= 0 {
				authority = authority[:end]
			}
			if at := strings.LastIndex(authority, "@"); at >= 0 {
				return authority[:at]
			}
		}
	}
	at := strings.LastIndex(endpoint, "@")
	if at <= start {
		return ""
	}
	return endpoint[start:at]
}

// isScheme reports whether s is a URL's scheme.
func isScheme(s string) bool {
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return s != ""
}

// maskForm returns text with form masked where it starts a word before an @.
func maskForm(text, form string) string {
	needle := form + "@"
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
		b.WriteString(maskedLogin)
		last = j + len(form)
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
// \r or \t, does.
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

// unescapedOrAsIs returns s unescaped, or s when it does not unescape.
func unescapedOrAsIs(unescape func(string) (string, error), s string) string {
	if u, err := unescape(s); err == nil {
		return u
	}
	return s
}
