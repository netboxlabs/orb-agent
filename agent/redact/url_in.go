package redact

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// URLIn returns text with the user info of rawURL masked as ******** wherever
// text writes that URL, as an error about it can. It finds the URL as it is
// written, and quoted as Go's %q quotes it; and, when a parser reads the URL,
// its user info as it is written, as Go writes a parsed URL (escaped), as
// go-git writes it again into the URL it requests (path-escaped), as
// net/http's errors write it (with the password replaced by ***), as git
// writes the user it asks a password for (escaped as git escapes it, or
// decoded) and as git writes a URL it refuses for its plaintext credentials
// (with the password replaced by <redacted>). It finds the user of git's
// scp-like user@host:path also as go-git writes it again, as
// ssh://user@host/path. The user and the password are masked together. text
// is returned as it is when rawURL carries no user info.
func URLIn(text, rawURL string) string {
	masked := URL(rawURL)
	if masked == rawURL {
		return text
	}
	if u, err := url.Parse(rawURL); err == nil && u.User != nil {
		written := writtenUserInfo(rawURL)
		infos := []string{written}
		if _, ok := u.User.Password(); ok {
			// git writes the URL it refuses for its plaintext credentials as
			// it is written, with <redacted> for the password.
			writtenUser, _, _ := strings.Cut(written, ":")
			infos = append(infos, writtenUser+":<redacted>")
		}
		users := []*url.Userinfo{u.User}
		if rebuilt, err := url.Parse("//" + pathEscaped(u.User) + "@host"); err == nil && rebuilt.User != nil {
			users = append(users, rebuilt.User)
		}
		for _, ui := range users {
			user := ui.Username()
			infos = append(infos, ui.String(), user, gitEscaped(user))
			if _, ok := ui.Password(); ok {
				infos = append(infos, user+":***")
			}
		}
		for _, info := range infos {
			for _, form := range []string{info, quoted(info)} {
				text = strings.ReplaceAll(text, "//"+form+"@", "//"+MaskedSecret+"@")
			}
		}
	} else if user, ok := scpUser(rawURL); ok {
		// ssh writes user@host when it is refused, and go-git writes an
		// scp-like URL again as ssh://user@host/path, with the user
		// path-escaped.
		head, _, _ := strings.Cut(rawURL, ":")
		host := head[len(user):]
		for _, form := range []string{user, url.PathEscape(user)} {
			text = strings.ReplaceAll(text, form+host, MaskedSecret+host)
		}
	}
	// A URL no parser reads, or one written without //, which a parser reads
	// as a scheme and an opaque part, is masked as URL masks it.
	text = strings.ReplaceAll(text, rawURL, masked)
	return strings.ReplaceAll(text, quoted(rawURL), quoted(masked))
}

// writtenUserInfo returns the user info of a URL a parser reads, as it is
// written: what its authority holds before its last @.
func writtenUserInfo(rawURL string) string {
	rest := rawURL[strings.Index(rawURL, "://")+len("://"):]
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		rest = rest[:end]
	}
	return rest[:max(strings.LastIndex(rest, "@"), 0)]
}

// pathEscaped returns ui as go-git writes it into the URL it requests: user
// and password path-escaped, which leaves a : as it is, and no password when
// it is empty.
func pathEscaped(ui *url.Userinfo) string {
	s := url.PathEscape(ui.Username())
	if password, _ := ui.Password(); password != "" {
		s += ":" + url.PathEscape(password)
	}
	return s
}

// gitEscaped returns s as git escapes a user in a URL it writes: every byte
// but a letter, a digit and - . _ ~ as %XX.
func gitEscaped(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("-._~", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// quoted returns s as Go's %q quotes it, without the quotes.
func quoted(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}
