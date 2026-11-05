package redact

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// longRun is the shortest head or tail of a value that Values masks on its
// own. A backend that truncates a value it quotes keeps its head, its tail or
// both (yaml.v3 the first 7 bytes of a string over 10; pydantic the first 25
// and the last 24), so only those count. A run from the middle of a value is
// more likely the error's own words, and masking it would tell anyone who
// knows the error's text that the value contains them; a head or tail shorter
// than longRun tells little and is as likely the error's own.
const longRun = 7

// Values returns s with values masked: every occurrence of one of them, or of
// one escaped as Go or JSON quote it, is replaced by MaskedSecret, and so is
// every head or tail of one longRun bytes or longer. A value shorter than
// longRun is masked only where it is a word of its own, so a short value
// such as "0" leaves the digits of the error's numbers alone. A backend's
// error can quote a policy's data, whose secret references are resolved by
// then, whole, truncated or escaped; the agent passes such text through
// Values before it logs or reports it. Empty values are ignored.
func Values(s string, values []string) string {
	return mask(s, values, false)
}

// CutValues is Values for s cut from a longer text: a value the cut runs
// through is masked too, however few of its first bytes s ends with.
func CutValues(s string, values []string) string {
	return mask(s, values, true)
}

func mask(s string, values []string, cut bool) string {
	var forms []string
	for _, v := range values {
		for _, f := range quotedForms(v) {
			if !slices.Contains(forms, f) {
				forms = append(forms, f)
			}
		}
	}
	if len(forms) == 0 || s == "" {
		return s
	}

	// start[i] is where the earliest masked run ending at s[i] begins, or
	// len(s) when none ends there.
	start := make([]int, len(s))
	for i := range start {
		start[i] = len(s)
	}
	found := false
	for _, v := range forms {
		// run[j] is the length of the longest run of s ending at s[i] that
		// ends at v[j-1] too; prev holds it for s[i-1].
		prev, run := make([]int, len(v)+1), make([]int, len(v)+1)
		for i := range len(s) {
			longest := 0
			for j := 1; j <= len(v); j++ {
				if s[i] != v[j-1] {
					run[j] = 0
					continue
				}
				n := prev[j-1] + 1
				run[j] = n
				// A run as long as j reaches back to v's first byte: s ends
				// at i with v's head of j bytes. One that ends at v's last
				// byte is a tail, the whole of v when it is as long as v.
				head, tail := n >= j, j == len(v)
				switch {
				case tail && n == len(v) && (n >= longRun || standsAlone(s, i-n+1, i, v)):
					longest = max(longest, n)
				case tail && n >= longRun:
					longest = max(longest, n)
				case head && (j >= longRun || cut && i == len(s)-1):
					longest = max(longest, j)
				}
			}
			if longest > 0 {
				start[i] = min(start[i], i-longest+1)
				found = true
			}
			prev, run = run, prev
		}
	}
	if !found {
		return s
	}

	// A byte is masked when a run that ends at it or after it begins at or
	// before it.
	masked := make([]bool, len(s))
	earliest := len(s)
	for i := len(s) - 1; i >= 0; i-- {
		earliest = min(earliest, start[i])
		masked[i] = earliest <= i
	}
	// Runs are of bytes: widen each to whole characters, so no part of one is
	// left behind and the text stays valid UTF-8.
	for i := 1; i < len(s); i++ {
		if masked[i-1] && !utf8.RuneStart(s[i]) {
			masked[i] = true
		}
	}
	for i := len(s) - 2; i >= 0; i-- {
		if masked[i+1] && !utf8.RuneStart(s[i+1]) {
			masked[i] = true
		}
	}

	var b strings.Builder
	for i := 0; i < len(s); {
		if !masked[i] {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteString(MaskedSecret)
		for i < len(s) && masked[i] {
			i++
		}
	}
	return b.String()
}

// standsAlone reports whether s[from:to+1], an occurrence of v, is a word of
// its own: on each side, either v's own edge is no word byte or the byte
// beside it in s is not one.
func standsAlone(s string, from, to int, v string) bool {
	startsWord := !isWordByte(v[0]) || from == 0 || !isWordByte(s[from-1])
	endsWord := !isWordByte(v[len(v)-1]) || to == len(s)-1 || !isWordByte(s[to+1])
	return startsWord && endsWord
}

// quotedForms returns v as an error can quote it: as it is, escaped as Go
// quotes a string (%q and strconv's errors; only ASCII, as %+q and Python's
// json.dumps do), and escaped as JSON, with the HTML escaping Go's encoder
// applies by default and without, as in a JSON body kept whole.
func quotedForms(v string) []string {
	if v == "" {
		return nil
	}
	forms := []string{v}
	add := func(quoted string) {
		if inner := strings.TrimSuffix(strings.TrimPrefix(quoted, `"`), `"`); !slices.Contains(forms, inner) {
			forms = append(forms, inner)
		}
	}
	add(strconv.Quote(v))
	add(strconv.QuoteToASCII(v))
	if b, err := json.Marshal(v); err == nil {
		add(string(b))
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) == nil {
		add(strings.TrimSuffix(b.String(), "\n"))
	}
	return forms
}

// isWordByte reports whether c is part of a word: an ASCII letter or digit,
// or an underscore.
func isWordByte(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}
