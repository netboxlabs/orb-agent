package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
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
// one escaped as Go, JSON or Python quote it, is replaced by MaskedSecret, and
// so is every head or tail of one longRun bytes or longer. A value shorter
// than longRun is masked only where it is a word of its own, so a short value
// such as "0" leaves the digits of the error's numbers alone, and not in the
// error's own wording (see errorWording): a short value that is one of its
// words, such as "int", is masked only where the error quotes it, so the
// error stays readable and does not show which word the value is. A quoted
// value is always a word of its own: no quote is a word byte. A value of
// several lines, a private key say, is also masked line by line, as a
// backend that prints it line by line quotes it: each of its lines of
// longRun bytes or more, trimmed of the spaces around it, wherever it occurs
// whole. A backend's error can quote a policy's data, whose secret references
// are resolved by then, whole, truncated or escaped; the agent passes such
// text through Values before it logs or reports it. Empty values are ignored.
func Values(s string, values []string) string {
	return NewMasker(values).Mask(s)
}

// CutValues is Values for s cut from a longer text that goes on with after: a
// value, or a line of one, the cut runs through is masked too, however few of
// its first bytes s ends with. A value runs through the cut when after goes
// on with it to a head of longRun bytes, or to the whole of a shorter value
// that is a word of its own; a line when after goes on with the rest of it.
// First bytes of a value that after does not go on with are the text's own,
// as the type that ends a YAML error's line. With after empty, it masks as
// Values does.
func CutValues(s, after string, values []string) string {
	return NewMasker(values).MaskCut(s, after)
}

// LongestForm returns the length of the longest form of values that Values
// masks: how far past a point in a text a value masked there can reach.
func LongestForm(values []string) int {
	return NewMasker(values).LongestForm()
}

// Masker masks a set of values in texts, as Values does. Building one finds
// the forms of the values Values matches and readies each to be searched
// for, which takes time and memory in proportion to the values; masking a
// text with it then takes time in proportion to the text times the number of
// forms, and allocates in proportion to the text alone. A caller that masks
// many texts with the same values, a backend's output line by line, builds
// one and keeps it. A Masker is not changed once built, so texts can be
// masked with it concurrently.
type Masker struct {
	// forms are masked whole, by a head or by a tail; lines, the lines of
	// values of several lines, only whole.
	forms, lines []form
	longest      int
}

// form is a text a Masker searches for, with what the searches need: back
// for the heads of it a text holds, and rv and z for the tails.
type form struct {
	v string
	// back[j] is the length of the longest head of v that is a tail of
	// v[:j+1] and shorter than it: how much of a head is still matched when
	// the byte after v[:j+1] is not the next in v.
	back []int32
	// rv is v read backwards, and z[k] the length of the longest head of rv
	// that starts at rv[k].
	rv []byte
	z  []int32
}

// NewMasker returns a Masker for values.
func NewMasker(values []string) *Masker {
	m := &Masker{}
	seen := make(map[string]bool)
	for _, v := range values {
		for _, f := range append(quotedForms(v), splitHeads(v)...) {
			if !seen[f] {
				seen[f] = true
				m.forms = append(m.forms, newForm(f))
				m.longest = max(m.longest, len(f))
			}
		}
	}
	seen = make(map[string]bool)
	for _, v := range values {
		if !strings.Contains(v, "\n") {
			continue
		}
		for line := range strings.SplitSeq(v, "\n") {
			if line = strings.TrimSpace(line); len(line) < longRun {
				continue
			}
			for _, f := range quotedForms(line) {
				if !seen[f] {
					seen[f] = true
					m.lines = append(m.lines, newForm(f))
				}
			}
		}
	}
	return m
}

func newForm(v string) form {
	f := form{v: v, back: make([]int32, len(v)), rv: reversed(v), z: make([]int32, len(v))}
	for j, n := 1, int32(0); j < len(v); j++ {
		for n > 0 && v[j] != v[n] {
			n = f.back[n-1]
		}
		if v[j] == v[n] {
			n++
		}
		f.back[j] = n
	}
	// rv[l:r] is the head of rv that reaches furthest found so far.
	rv := f.rv
	for k, l, r := 1, 0, 0; k < len(rv); k++ {
		n := 0
		if k < r {
			n = min(int(f.z[k-l]), r-k)
		}
		for k+n < len(rv) && rv[k+n] == rv[n] {
			n++
		}
		f.z[k] = int32(n)
		if k+n > r {
			l, r = k, k+n
		}
	}
	return f
}

// LongestForm returns the length of the longest form of the Masker's values
// that it masks, as the function LongestForm does.
func (m *Masker) LongestForm() int {
	return m.longest
}

// Mask returns s with the Masker's values masked, as Values does.
func (m *Masker) Mask(s string) string {
	return m.mask(s, false, "")
}

// MaskCut returns s, cut from a longer text that goes on with after, with the
// Masker's values masked, as CutValues does.
func (m *Masker) MaskCut(s, after string) string {
	return m.mask(s, true, after)
}

func (m *Masker) mask(s string, cut bool, after string) string {
	start := m.runStarts(s, cut, after)
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
// there: the whole of a form, as long as longRun or a word of its own outside
// the error's wording; a head or tail of one as long as longRun; the whole of
// a line; and, in a text cut before after, a head at its end of a form or a
// line that runs through the cut (see cutHead and cutLineHead). It returns
// nil when no run is masked.
func (m *Masker) runStarts(s string, cut bool, after string) []int {
	if len(m.forms) == 0 && len(m.lines) == 0 || s == "" {
		return nil
	}
	start := make([]int, len(s))
	for i := range start {
		start[i] = len(s)
	}
	found := false
	// In a cut text, the error's wording, and whether a value at the cut is
	// a word of its own, are told from the text past the cut too, as far as
	// is within reach (see pastCut).
	text := s
	if cut {
		text = s + pastCut(after)
	}
	textWording := errorWording(text)
	heads := make([]int, len(s))
	if len(m.forms) > 0 {
		// Each scan takes time in proportion to s, so a long value in a long
		// text costs no more than reading both; the scans of every form fill
		// the same runs.
		tails, rs := make([]int, len(s)), reversed(s)
		for i := range m.forms {
			f := &m.forms[i]
			f.headRuns(heads, s)
			f.tailRuns(tails, rs)
			for i := range len(s) {
				// A tail as long as v is the whole of v. The longest head or
				// tail ending at s[i] is the one to mask when any is: one that
				// is shorter is shorter than longRun too.
				longest := 0
				if n := tails[i]; n >= longRun || n == len(f.v) && shortMasked(text, i-n+1, i, f.v, textWording) {
					longest = n
				}
				if n := heads[i]; n >= longRun {
					longest = max(longest, n)
				}
				if longest > 0 {
					start[i] = min(start[i], i-longest+1)
					found = true
				}
			}
			if cut {
				if n := cutHead(s, after, f.v, text, textWording); n > 0 {
					start[len(s)-1] = min(start[len(s)-1], len(s)-n)
					found = true
				}
			}
		}
	}
	for i := range m.lines {
		f := &m.lines[i]
		for from := 0; ; {
			k := strings.Index(s[from:], f.v)
			if k < 0 {
				break
			}
			at := from + k
			end := at + len(f.v) - 1
			start[end] = min(start[end], at)
			found = true
			from = at + 1
		}
		if cut {
			f.headRuns(heads, s)
			if n := f.cutLineHead(heads[len(s)-1], after); n > 0 {
				start[len(s)-1] = min(start[len(s)-1], len(s)-n)
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	return start
}

// shortMasked reports whether s[from:to+1], an occurrence of v shorter than
// longRun, is masked: where it is a word of its own that no byte of the
// error's wording (wording, from errorWording) is part of.
func shortMasked(s string, from, to int, v string, wording []bool) bool {
	return standsAlone(s, from, to, v) && !slices.Contains(wording[from:to+1], true)
}

// errorWordingPatterns match the wording of the errors a refusal can carry
// that the agent can tell apart from a policy's values: yaml.v3's decode
// errors. A type error is a line of its own, indented, that ends with a Go
// type (submatch 1 is its wording), and its only value is the one it quotes
// in backticks (submatch 2): the same words inside another message, or text
// after the type on its line, as in a JSON body kept whole, are not the
// decoder's, so the pattern does not match there and every short value in
// them stays masked. yaml.v3 quotes at most 10 bytes of the value, as they
// are, so a new line in them runs the type error on to the next line, and
// two type errors are never one.
var errorWordingPatterns = []*regexp.Regexp{
	regexp.MustCompile(`yaml: unmarshal errors:`),
	regexp.MustCompile(`yaml: line \d+: `),
	regexp.MustCompile("(?m)^[ \\t]*(line \\d+: cannot unmarshal !!\\S+ (?:`((?s:.{0,10}))` )?into (?:[\\w.*\\[\\]]|interface \\{\\}|struct \\{\\})+)$"),
}

// errorWording returns, for each byte of s, whether it is part of the
// error's own wording, where a short value that is a word of its own is not
// masked: those words are the error's, not the policy's.
func errorWording(s string) []bool {
	wording := make([]bool, len(s))
	for _, re := range errorWordingPatterns {
		for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
			from, to, slotFrom, slotTo := m[0], m[1], -1, -1
			if len(m) == 6 {
				from, to, slotFrom, slotTo = m[2], m[3], m[4], m[5]
			}
			for i := from; i < to; i++ {
				wording[i] = i < slotFrom || i >= slotTo
			}
		}
	}
	return wording
}

// standsAlone reports whether s[from:to+1], an occurrence of v, is a word of
// its own: on each side, either v's own edge is no word byte or the byte
// beside it in s is not one.
func standsAlone(s string, from, to int, v string) bool {
	startsWord := !isWordByte(v[0]) || from == 0 || !isWordByte(s[from-1])
	endsWord := !isWordByte(v[len(v)-1]) || to == len(s)-1 || !isWordByte(s[to+1])
	return startsWord && endsWord
}

// maxCutReach bounds how much of the text past a cut is read to tell the
// error's wording the cut runs through.
const maxCutReach = 256

// pastCut returns as much of after, the text past a cut, as is read to tell
// the error's wording the cut runs through: maxCutReach bytes, and when after
// goes on past them, a byte no word or type holds, so a YAML type error cut
// there is not taken whole.
func pastCut(after string) string {
	if len(after) > maxCutReach {
		return after[:maxCutReach] + "\x00"
	}
	return after
}

// cutHead returns the length of the longest head of v shorter than longRun
// that s ends with and that runs through the cut before after: after goes on
// with it to a head of v longRun bytes long, or to the whole of a shorter v
// that is a word of its own there, outside the error's wording. text is s and
// what pastCut reads of after, and wording is the error's wording in it. It
// returns 0 for none. A longer head is masked wherever it ends.
func cutHead(s, after, v, text string, wording []bool) int {
	need := min(len(v), longRun)
	for n := min(need-1, len(s)); n > 0; n-- {
		if !strings.HasSuffix(s, v[:n]) || !strings.HasPrefix(after, v[n:need]) {
			continue
		}
		if at := len(s) - n; len(v) < longRun && !shortMasked(text, at, at+len(v)-1, v, wording) {
			continue
		}
		return n
	}
	return 0
}

// cutLineHead returns the length of the longest head of f's text, a line of
// a value, that a cut text ends with and that after goes on with to the
// whole line, a line being masked only whole; 0 for none. n is the longest
// head of it the cut text ends with; the shorter ones are its borders.
func (f *form) cutLineHead(n int, after string) int {
	if n == len(f.v) {
		n = int(f.back[n-1])
	}
	for ; n > 0; n = int(f.back[n-1]) {
		if strings.HasPrefix(after, f.v[n:]) {
			return n
		}
	}
	return 0
}

// headRuns sets runs[i] to the length of the longest head of f's text that
// ends at s[i], found as Knuth-Morris-Pratt finds it in s.
func (f *form) headRuns(runs []int, s string) {
	v, back := f.v, f.back
	n := 0
	for i := range len(s) {
		if n == len(v) {
			n = int(back[n-1])
		}
		for n > 0 && s[i] != v[n] {
			n = int(back[n-1])
		}
		if s[i] == v[n] {
			n++
		}
		runs[i] = n
	}
}

// tailRuns sets runs[i] to the length of the longest tail of f's text that
// ends at the byte of s at i, rs being s read backwards. Read backwards, that
// is the longest head of the text read backwards that starts there, found
// with the Z algorithm.
func (f *form) tailRuns(runs []int, rs []byte) {
	rv, z := f.rv, f.z
	for p, l, r := 0, 0, 0; p < len(rs); p++ {
		n := 0
		if p < r {
			n = min(int(z[p-l]), r-p)
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
// Python's json.dumps does for characters below U+10000), escaped as JSON,
// with the HTML escaping Go's encoder applies by default and without, as in a
// JSON body kept whole, and escaped as Python's repr does (pydantic's
// input_value).
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
	for _, escapeSingle := range []bool{true, false} {
		for _, keepUnassigned := range []bool{false, true} {
			if repr := pythonRepr(v, escapeSingle, keepUnassigned); !slices.Contains(forms, repr) {
				forms = append(forms, repr)
			}
		}
	}
	return forms
}

// assigned are the categories of every character Go's Unicode tables assign:
// unicode.C also holds the code points they don't, so its parts are named.
var assigned = []*unicode.RangeTable{unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs}

// pythonRepr returns v escaped as Python's repr escapes it. repr escapes a
// single quote when it quotes the string in single quotes: always when the
// string also holds a double quote, which a text holding v can, and never when
// it holds only single quotes, which it then quotes in double quotes. So the
// caller asks for both, escapeSingle saying which. It escapes a backslash, \n,
// \r and \t by name, and a character it does not print by its code: \xNN,
// \uNNNN or \UNNNNNNNN. Python prints what Go's unicode.IsPrint does, the
// space alone among spaces, for the characters both their Unicode versions
// assign. A newer Python prints characters Go's tables don't assign yet, which
// keepUnassigned keeps as they are. A byte that is no UTF-8, which no Python
// string holds, is kept.
func pythonRepr(v string, escapeSingle, keepUnassigned bool) string {
	var b strings.Builder
	for i, r := range v {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\'' && escapeSingle:
			b.WriteString(`\'`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == utf8.RuneError && !strings.HasPrefix(v[i:], string(utf8.RuneError)):
			b.WriteByte(v[i])
		case unicode.IsPrint(r), keepUnassigned && !unicode.In(r, assigned...):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	return b.String()
}

// isWordByte reports whether c is part of a word: an ASCII letter or digit,
// or an underscore.
func isWordByte(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}
