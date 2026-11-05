package redact

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A run of a value is masked wherever it is from longRun bytes, and from
// minFragment bytes (or the whole of a shorter value) only where it is a word
// of its own. Backends that truncate a value they quote keep a long run of it
// (yaml.v3 the first 7 bytes of a string over 10), while a short run inside a
// word is more likely the error's own text: masking it would hide the words
// that say what is wrong, a short value like "0" every digit 0.
const (
	minFragment = 4
	longRun     = 7
)

// Values returns s with values masked: every run of s that is also a run of
// one of them, or of one escaped as Go or JSON quote it, is replaced by
// MaskedSecret when it is long enough (see longRun and minFragment). A
// backend's error can quote a policy's data, whose secret references are
// resolved by then, whole, truncated or escaped; the agent passes such text
// through Values before it logs or reports it. Empty values are ignored.
func Values(s string, values []string) string {
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
		least := min(len(v), minFragment)
		// run[j] is the length of the longest run of s ending at s[i] that
		// ends at v[j-1] too; prev holds it for s[i-1].
		prev, run := make([]int, len(v)+1), make([]int, len(v)+1)
		for i := range len(s) {
			longest := 0
			endsWord := i+1 == len(s) || !isWordByte(s[i+1])
			for j := 1; j <= len(v); j++ {
				if s[i] != v[j-1] {
					run[j] = 0
					continue
				}
				n := prev[j-1] + 1
				run[j] = n
				switch {
				case n >= longRun:
					longest = max(longest, n)
				case n >= least && endsWord:
					// The longest of its runs that starts a word.
					for l := n; l >= least; l-- {
						if from := i - l + 1; from == 0 || !isWordByte(s[from-1]) {
							longest = max(longest, l)
							break
						}
					}
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

// quotedForms returns v as an error can quote it: as it is, escaped as Go
// quotes a string (%q, strconv's errors), and escaped as JSON, with the HTML
// escaping Go's encoder applies by default (gin's JSON answers) and without.
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
