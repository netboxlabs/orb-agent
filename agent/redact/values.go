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
// Values before it logs or reports it. Empty values are ignored. A value of
// several lines is also masked line by line; see maskLines.
func Values(s string, values []string) string {
	return mask(s, values, false)
}

// CutValues is Values for s cut from a longer text: a value the cut runs
// through is masked too, however few of its first bytes s ends with.
func CutValues(s string, values []string) string {
	return mask(s, values, true)
}

// LongestForm returns the length of the longest form of values that Values
// masks: how far past a point in a text a value masked there can reach.
func LongestForm(values []string) int {
	longest := 0
	for _, f := range maskedForms(values) {
		longest = max(longest, len(f))
	}
	return longest
}

// maskedForms returns the forms of values that mask matches, each once.
func maskedForms(values []string) []string {
	var forms []string
	for _, v := range values {
		for _, f := range append(quotedForms(v), splitHeads(v)...) {
			if !slices.Contains(forms, f) {
				forms = append(forms, f)
			}
		}
	}
	return forms
}

// maskLines replaces, in s, each line of a value of several lines, a private
// key say, wherever it occurs whole, as it is or escaped as Go or JSON quote
// it: a backend that prints such a value prints it line by line, so no line
// of its output holds the whole value. A line is trimmed of the spaces and
// carriage return around it, as an indented dump prints it, and only one of
// longRun bytes or more counts: a shorter one, a brace say, is more likely
// the text's own.
func maskLines(s string, values []string) string {
	for _, v := range values {
		if !strings.Contains(v, "\n") {
			continue
		}
		for line := range strings.SplitSeq(v, "\n") {
			if line = strings.TrimSpace(line); len(line) < longRun {
				continue
			}
			for _, f := range quotedForms(line) {
				s = strings.ReplaceAll(s, f, MaskedSecret)
			}
		}
	}
	return s
}

func mask(s string, values []string, cut bool) string {
	s = maskLines(s, values)
	start := runStarts(s, maskedForms(values), cut)
	if start == nil {
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

// runStarts returns, for each byte of s, where the earliest run of s that
// mask masks and that ends at that byte begins, or len(s) when none ends
// there: the whole of a form, as long as longRun or a word of its own; a
// head or tail of one as long as longRun; and, in a cut text, a head of any
// length at its end. It returns nil when no run is masked.
func runStarts(s string, forms []string, cut bool) []int {
	if len(forms) == 0 || s == "" {
		return nil
	}
	start := make([]int, len(s))
	for i := range start {
		start[i] = len(s)
	}
	found := false
	// Each scan takes time in proportion to s and v, so a long value in a
	// long text costs no more than reading both; the scans of every form
	// fill the same runs.
	heads, tails, rs := make([]int, len(s)), make([]int, len(s)), reversed(s)
	for _, v := range forms {
		headRuns(heads, s, v)
		tailRuns(tails, rs, v)
		for i := range len(s) {
			// A tail as long as v is the whole of v. The longest head or
			// tail ending at s[i] is the one to mask when any is: one that
			// is shorter is shorter than longRun too.
			longest := 0
			if n := tails[i]; n >= longRun || n == len(v) && standsAlone(s, i-n+1, i, v) {
				longest = n
			}
			if n := heads[i]; n >= longRun || n > 0 && cut && i == len(s)-1 {
				longest = max(longest, n)
			}
			if longest > 0 {
				start[i] = min(start[i], i-longest+1)
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	return start
}

// standsAlone reports whether s[from:to+1], an occurrence of v, is a word of
// its own: on each side, either v's own edge is no word byte or the byte
// beside it in s is not one.
func standsAlone(s string, from, to int, v string) bool {
	startsWord := !isWordByte(v[0]) || from == 0 || !isWordByte(s[from-1])
	endsWord := !isWordByte(v[len(v)-1]) || to == len(s)-1 || !isWordByte(s[to+1])
	return startsWord && endsWord
}

// headRuns sets runs[i] to the length of the longest head of v that ends at
// s[i], found as Knuth-Morris-Pratt finds v in s.
func headRuns(runs []int, s, v string) {
	// back[j] is the length of the longest head of v that is a tail of
	// v[:j+1] and shorter than it: how much of a head is still matched when
	// the byte after v[:j+1] is not the next in v.
	back := make([]int, len(v))
	for j, n := 1, 0; j < len(v); j++ {
		for n > 0 && v[j] != v[n] {
			n = back[n-1]
		}
		if v[j] == v[n] {
			n++
		}
		back[j] = n
	}
	n := 0
	for i := range len(s) {
		if n == len(v) {
			n = back[n-1]
		}
		for n > 0 && s[i] != v[n] {
			n = back[n-1]
		}
		if s[i] == v[n] {
			n++
		}
		runs[i] = n
	}
}

// tailRuns sets runs[i] to the length of the longest tail of v that ends at
// the byte of s at i, rs being s read backwards. Read backwards, that is the
// longest head of v that starts there, found with the Z algorithm.
func tailRuns(runs []int, rs []byte, v string) {
	rv := reversed(v)
	// z[k] is the length of the longest head of rv that starts at rv[k];
	// rv[l:r] is the head that reaches furthest found so far.
	z := make([]int, len(rv))
	for k, l, r := 1, 0, 0; k < len(rv); k++ {
		n := 0
		if k < r {
			n = min(z[k-l], r-k)
		}
		for k+n < len(rv) && rv[k+n] == rv[n] {
			n++
		}
		z[k] = n
		if k+n > r {
			l, r = k, k+n
		}
	}
	for p, l, r := 0, 0, 0; p < len(rs); p++ {
		n := 0
		if p < r {
			n = min(z[p-l], r-p)
		}
		for p+n < len(rs) && n < len(rv) && rs[p+n] == rv[n] {
			n++
		}
		runs[len(rs)-1-p] = n
		if p+n > r {
			l, r = p, p+n
		}
	}
}

// reversed returns s with its bytes in reverse order.
func reversed(s string) []byte {
	b := []byte(s)
	slices.Reverse(b)
	return b
}

// splitHeads returns v's heads cut inside a character, as a backend quotes
// them that cuts a value by bytes (yaml.v3 quotes a long value's first 7) and
// answers in JSON: encoding/json replaces each byte of the cut character with
// U+FFFD. Only cuts within v's first longRun bytes count: one further in
// follows a head of longRun bytes or more, which mask masks on its own, and
// a form for each would cost a pass over the text per byte of every
// character in v.
func splitHeads(v string) []string {
	var heads []string
	for i := 0; i < len(v) && i < longRun; {
		_, size := utf8.DecodeRuneInString(v[i:])
		for k := 1; k < size; k++ {
			heads = append(heads, v[:i]+strings.Repeat(string(utf8.RuneError), k))
		}
		i += size
	}
	return heads
}

// quotedForms returns v as an error can quote it: as it is, escaped as Go
// quotes a string (%q and strconv's errors; only ASCII, as %+q does, and as
// Python's json.dumps does for characters below U+10000), and escaped as JSON,
// with the HTML escaping Go's encoder applies by default and without, as in a
// JSON body kept whole.
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
