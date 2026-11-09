package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// encodedJSON encodes v as Go's encoding/json does by default, escaping <, >
// and & in strings, and checks the encoding escaped something, so the case
// tests an escaped value.
func encodedJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "u003c") {
		t.Fatalf("%s escapes nothing", b)
	}
	return string(b)
}

// encodedJSONNoHTML encodes v as a JSON encoder without HTML escaping does,
// and checks it escaped a control character.
func encodedJSONNoHTML(t *testing.T, v any) string {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "u0001") || strings.Contains(b.String(), "u003c") {
		t.Fatalf("%s is not the encoding wanted", b.String())
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// jsonRoundTrip returns s as a backend's JSON answer carries it: encoded by
// encoding/json, which replaces each byte of an invalid UTF-8 sequence with
// U+FFFD, and decoded, as the agent reads the answer. It checks s had such a
// sequence, so the case tests a value cut inside a character.
func jsonRoundTrip(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var decoded string
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded == s {
		t.Fatalf("%q has no byte to replace", s)
	}
	return decoded
}

// TestValues masks a policy's resolved values in a backend's error text,
// whole, truncated and escaped as backends quote them, and leaves the error's
// own words readable, including those a value happens to contain.
func TestValues(t *testing.T) {
	const long = "Pl41n-r3solved-credential-7f3a"
	const typeErr = "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `k3Y-9xQz` into int"
	// Each value's forms other than the one quoted share no head or tail of
	// longRun bytes with it, so only that form masks it.
	goQuoted := "é\x01bcdefgh\x01é"
	jsonControl := "<a\x01bcdefgh\x01>"
	for _, tc := range []struct {
		name   string
		text   string
		values []string
		want   string
	}{
		{
			name:   "a value quoted whole",
			text:   typeErr,
			values: []string{"k3Y-9xQz"},
			want:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `********` into int",
		},
		{
			name:   "the first 7 bytes yaml.v3 quotes of a value over 10",
			text:   "line 4: cannot unmarshal !!str `Pl41n-r...` into int",
			values: []string{long},
			want:   "line 4: cannot unmarshal !!str `********...` into int",
		},
		{
			name:   "a head and a tail, as a truncated repr quotes them",
			text:   "input_value='Pl41n-r3sol...ential-7f3a'",
			values: []string{long},
			want:   "input_value='********...********'",
		},
		{
			name:   "every occurrence of every value",
			text:   "a=k3Y-9xQz b=Sec0nd-v4l c=k3Y-9xQz",
			values: []string{"k3Y-9xQz", "Sec0nd-v4l"},
			want:   "a=******** b=******** c=********",
		},
		{
			// yaml.v3 quotes the first 7 bytes, which end inside "€"; gin's
			// JSON answer replaces each of its 2 bytes there with U+FFFD.
			name:   "the first 7 bytes of a value, cut inside a character and sent as JSON",
			text:   "line 4: cannot unmarshal !!str `" + jsonRoundTrip(t, "Hello€world123"[:7]) + "...` into int",
			values: []string{"Hello€world123"},
			want:   "line 4: cannot unmarshal !!str `********...` into int",
		},
		{
			// The first 11 bytes are a head of longRun or more, masked as
			// such; the U+FFFD that stand for the cut character are none of
			// its bytes.
			name:   "the first bytes of a value, cut inside a character past its first 7",
			text:   "quoted `" + jsonRoundTrip(t, "Hello-world€tail"[:13]) + "...`",
			values: []string{"Hello-world€tail"},
			want:   "quoted `********��...`",
		},
		{
			name:   "a tail of exactly 7 bytes",
			text:   "ends with al-7f3a!",
			values: []string{long},
			want:   "ends with ********!",
		},
		{
			name:   "a head of exactly 7 bytes, inside a word",
			text:   "idPl41n-rx",
			values: []string{long},
			want:   "id********x",
		},
		{
			name:   "a head of more than 7 bytes, inside a word",
			text:   "prefixPl41n-r3solvedsuffix",
			values: []string{long},
			want:   "prefix********suffix",
		},
		{
			name:   "a head of 6 bytes is left",
			text:   "found Pl41n- here",
			values: []string{long},
			want:   "found Pl41n- here",
		},
		{
			// A run from the middle of a value is no truncation of it, and
			// masking the error's words it contains would tell anyone who
			// knows the error's text that the value contains them.
			name:   "the error's own words in the middle of a value are left",
			text:   typeErr,
			values: []string{"Caroline#2024", "Pinto.horse", "xx-unmarshal-yy"},
			want:   typeErr,
		},
		{
			name:   "a run from the middle of a value is left, even 7 bytes or more",
			text:   "unknown option r3solved-cred",
			values: []string{long},
			want:   "unknown option r3solved-cred",
		},
		{
			name:   "a short value, where it is a word of its own",
			text:   "community ab9 refused",
			values: []string{"ab9"},
			want:   "community ******** refused",
		},
		{
			name:   "a short value inside a number or a word is left",
			text:   "400 yaml: unmarshal errors:\n  line 10: cannot unmarshal !!str `0` into bool; public_key unset",
			values: []string{"0", "public"},
			want:   "400 yaml: unmarshal errors:\n  line 10: cannot unmarshal !!str `********` into bool; public_key unset",
		},
		{
			name:   "a short value that is a word of the YAML error is masked only where it is quoted",
			text:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `int` into int",
			values: []string{"int"},
			want:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `********` into int",
		},
		{
			name:   "a short value that is the YAML error's line word",
			text:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `line` into int",
			values: []string{"line"},
			want:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `********` into int",
		},
		{
			// The secret sits in a field the error does not quote: masking
			// the error's words would claim the error quotes it, and show
			// which word it is.
			name:   "the words of a YAML error about another field are left",
			text:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `three` into int",
			values: []string{"int", "line", "str", "into", "yaml", "4", "errors", "cannot"},
			want:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `three` into int",
		},
		{
			name:   "a YAML type error for a value that is no scalar is left",
			text:   "400 yaml: unmarshal errors:\n  line 7: cannot unmarshal !!map into []string",
			values: []string{"map", "string", "7"},
			want:   "400 yaml: unmarshal errors:\n  line 7: cannot unmarshal !!map into []string",
		},
		{
			name:   "a YAML syntax error's prefix is left",
			text:   "400 yaml: line 3: did not find expected key",
			values: []string{"yaml", "line", "3"},
			want:   "400 yaml: line 3: did not find expected key",
		},
		{
			// The wording ends with the type: what follows on the line is
			// not the decoder's.
			name:   "a short value after a YAML type error on its line is masked",
			text:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `three` into int; community abc rejected",
			values: []string{"abc"},
			want:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `three` into int; community ******** rejected",
		},
		{
			name:   "a short value quoted after a YAML type error on its line is masked",
			text:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!seq into string; got `abc` into x",
			values: []string{"abc"},
			want:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!seq into string; got `********` into x",
		},
		{
			name:   "a short value in a JSON body that carries a YAML error is masked",
			text:   `400 {"error":"yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str ` + "`three`" + ` into int","input":"abc"}`,
			values: []string{"abc"},
			want:   `400 {"error":"yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str ` + "`three`" + ` into int","input":"********"}`,
		},
		{
			name:   "a short value after a carriage return is masked",
			text:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `three` into int\r abc",
			values: []string{"abc"},
			want:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `three` into int\r ********",
		},
		{
			name:   "a YAML type error into a map type is left",
			text:   "400 yaml: unmarshal errors:\n  line 7: cannot unmarshal !!seq into map[string]interface {}",
			values: []string{"map", "string"},
			want:   "400 yaml: unmarshal errors:\n  line 7: cannot unmarshal !!seq into map[string]interface {}",
		},
		{
			name:   "a short value after text like a YAML type error inside another message is masked",
			text:   "400 p1: Invalid: line 1: cannot unmarshal !!str into abc",
			values: []string{"abc"},
			want:   "400 p1: Invalid: line 1: cannot unmarshal !!str into ********",
		},
		{
			// Only its first byte is outside the wording: it is not a word
			// of the error's own, but neither is it the value quoted.
			name:   "a short value that runs into the YAML error's wording is left",
			text:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `three` into int",
			values: []string{" line"},
			want:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `three` into int",
		},
		{
			name:   "a short value holding the type error's own words, quoted",
			text:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `` into` into int",
			values: []string{"` into"},
			want:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `********` into int",
		},
		{
			name:   "a status code is no wording of its own here",
			text:   "400 target sw1: port 400 is not allowed",
			values: []string{"400"},
			want:   "******** target sw1: port ******** is not allowed",
		},
		{
			name:   "a short value a backend echoes unquoted is still masked",
			text:   "400 core: invalid policy: policy-level: invalid security level abc",
			values: []string{"abc"},
			want:   "400 core: invalid policy: policy-level: invalid security level ********",
		},
		{
			name:   "a short value in single quotes",
			text:   "Input should be a valid integer [type=int_parsing, input_value='lab', input_type=str]",
			values: []string{"lab"},
			want:   "Input should be a valid integer [type=int_parsing, input_value='********', input_type=str]",
		},
		{
			name:   "a value Python quotes with both kinds of quote in it",
			text:   `Input should be a valid integer [type=int_parsing, input_value='a\'b"c', input_type=str]`,
			values: []string{`a'b"c`},
			want:   `Input should be a valid integer [type=int_parsing, input_value='********', input_type=str]`,
		},
		{
			name:   "a value Python quotes with control characters escaped",
			text:   `[input_value='a\'b"\x01\x7f', input_type=str]`,
			values: []string{"a'b\"\x01\x7f"},
			want:   `[input_value='********', input_type=str]`,
		},
		{
			name:   "a value Python quotes with characters it does not print escaped",
			text:   `[input_value='p\'w"\xa0\u200b\n', input_type=str]`,
			values: []string{"p'w\"\u00a0\u200b\n"},
			want:   `[input_value='********', input_type=str]`,
		},
		{
			name:   "a value Python quotes with a backslash and a tab",
			text:   `[input_value='a\'b"\\\t', input_type=str]`,
			values: []string{"a'b\"\\\t"},
			want:   `[input_value='********', input_type=str]`,
		},
		{
			name:   "a short value Python quotes with a character it does not print past U+00FF",
			text:   `[input_value='a\'"\u200b', input_type=str]`,
			values: []string{"a'\"\u200b"},
			want:   `[input_value='********', input_type=str]`,
		},
		{
			name:   "a short value Python quotes with a newline",
			text:   `[input_value='a\'"\n', input_type=str]`,
			values: []string{"a'\"\n"},
			want:   `[input_value='********', input_type=str]`,
		},
		{
			name:   "a short value Python quotes with a tab",
			text:   `[input_value='a\'"\t', input_type=str]`,
			values: []string{"a'\"\t"},
			want:   `[input_value='********', input_type=str]`,
		},
		{
			name:   "a short value Python quotes with a backslash",
			text:   `[input_value='a\'"\\', input_type=str]`,
			values: []string{"a'\"\\"},
			want:   `[input_value='********', input_type=str]`,
		},
		{
			name:   "a long value Python quotes with both kinds of quote in it",
			text:   `[input_value='it\'s "x" k3Y', input_type=str]`,
			values: []string{`it's "x" k3Y`},
			want:   `[input_value='********', input_type=str]`,
		},
		{
			name:   "a short value Python quotes in double quotes, with a single quote and a control character in it",
			text:   `[input_value="a'\x07", input_type=str]`,
			values: []string{"a'\x07"},
			want:   `[input_value="********", input_type=str]`,
		},
		{
			name:   "a short value Python quotes in double quotes, with a single quote and a character it does not print in it",
			text:   `[input_value="it's\xa0", input_type=str]`,
			values: []string{"it's "},
			want:   `[input_value="********", input_type=str]`,
		},
		{
			name:   "a long value Python quotes in double quotes, with a single quote and a control character in it",
			text:   `[input_value="it's\x07 k3Y!x", input_type=str]`,
			values: []string{"it's\x07 k3Y!x"},
			want:   `[input_value="********", input_type=str]`,
		},
		{
			name:   "a short value at the start of the text",
			text:   "ab9 refused",
			values: []string{"ab9"},
			want:   "******** refused",
		},
		{
			// The value's own first byte is no letter or digit, so it
			// starts a word wherever it is.
			name:   "a short value whose first byte is punctuation, glued to a word",
			text:   "x-abc refused",
			values: []string{"-abc"},
			want:   "x******** refused",
		},
		{
			name:   "a short value whose last byte is punctuation, glued to a word",
			text:   "abc-x refused",
			values: []string{"abc-"},
			want:   "********x refused",
		},
		{
			name:   "a value quoted as Go quotes it",
			text:   `strconv.Atoi: parsing "9\"8\\7\"6": invalid syntax`,
			values: []string{`9"8\7"6`},
			want:   `strconv.Atoi: parsing "********": invalid syntax`,
		},
		{
			name:   "a value with control characters and accents, quoted as Go's %q quotes it",
			text:   fmt.Sprintf("strconv.Atoi: parsing %q: invalid syntax", goQuoted),
			values: []string{goQuoted},
			want:   `strconv.Atoi: parsing "********": invalid syntax`,
		},
		{
			name:   "a value quoted with only ASCII, as Python's json.dumps does",
			text:   "invalid value " + strconv.QuoteToASCII("pässwörd-1"),
			values: []string{"pässwörd-1"},
			want:   `invalid value "********"`,
		},
		{
			name:   "a value in a JSON body, HTML characters escaped as Go's encoder does",
			text:   "400 " + encodedJSON(t, map[string]string{"message": "bad community a<b>&c-d3f"}),
			values: []string{"a<b>&c-d3f"},
			want:   `400 {"message":"bad community ********"}`,
		},
		{
			name:   "a value in a JSON body encoded without HTML escaping",
			text:   "400 " + encodedJSONNoHTML(t, map[string]string{"message": "bad " + jsonControl}),
			values: []string{jsonControl},
			want:   `400 {"message":"bad ********"}`,
		},
		{
			// The head ends inside "ü", whose first byte "ä" shares: the
			// whole character is masked, so the text stays valid UTF-8.
			name:   "a head ending inside a multi-byte character",
			text:   "Pl41n-rü!",
			values: []string{"Pl41n-räum"},
			want:   "********!",
		},
		{
			// The tail starts at the second byte of "Ĥ", which "ä" shares.
			name:   "a tail starting inside a multi-byte character",
			text:   "x Ĥ-passw0rd y",
			values: []string{"ä-passw0rd"},
			want:   "x ******** y",
		},
		{
			name:   "an empty value masks nothing",
			text:   "line 4: cannot unmarshal",
			values: []string{""},
			want:   "line 4: cannot unmarshal",
		},
		{
			name: "no values",
			text: "line 4: cannot unmarshal",
			want: "line 4: cannot unmarshal",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Values(tc.text, tc.values); got != tc.want {
				t.Errorf("Values(%q, %q)\n got %q\nwant %q", tc.text, tc.values, got, tc.want)
			}
		})
	}
}

// TestCutValues masks a value the end of a cut text runs through, from its
// first byte, which Values leaves: in a text that is not cut, a value's first
// bytes at its end are the text's own.
func TestCutValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want string
	}{
		{"a cut after the value's first byte", "refused: xk", "refused: x********"},
		{"a cut after the value's first 6 bytes", "refused: k3Y-9x", "refused: ********"},
		{"a value whole before the cut", "refused: k3Y-9xQz, then", "refused: ********, then"},
		{"no value at the cut", "refused: xx", "refused: xx"},
		{"a short head before the cut", "refused: k3 then xx", "refused: k3 then xx"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CutValues(tc.text, []string{"k3Y-9xQz"}); got != tc.want {
				t.Errorf("CutValues(%q)\n got %q\nwant %q", tc.text, got, tc.want)
			}
		})
	}
	if got := Values("refused: xk", []string{"k3Y-9xQz"}); got != "refused: xk" {
		t.Errorf("Values masks the end of a text that is not cut: %q", got)
	}
}

// TestSplitHeadsCutWithinTheFirstLongRunBytes keeps the forms of a value cut
// inside a character to those Values needs: a cut further in leaves a head of
// longRun bytes or more before it, which Values masks on its own. A value of
// many multibyte characters would otherwise give a form per byte of each,
// each as long as the value before it.
func TestSplitHeadsCutWithinTheFirstLongRunBytes(t *testing.T) {
	// "密" is 3 bytes: the cuts inside its occurrences at bytes 0, 3 and 6.
	heads := splitHeads(strings.Repeat("密", 341))
	if len(heads) != 6 {
		t.Errorf("%d heads, want 6", len(heads))
	}
	for _, h := range heads {
		if kept := strings.TrimRight(h, string(utf8.RuneError)); len(kept) >= longRun {
			t.Errorf("a head cut after %d whole bytes: %q", len(kept), h)
		}
	}
	// "€" starts at byte 7, after a head of longRun bytes.
	if heads := splitHeads("abcdefg€"); len(heads) != 0 {
		t.Errorf("heads cut after the first longRun bytes: %q", heads)
	}
}

// TestValuesWorkGrowsWithTheTextAndTheValue masks a long value quoted whole in
// a text as long within a bound that comparing each byte of one with each
// byte of the other would take far longer than: a backend can echo a policy
// holding a certificate bundle into its error. A value of one byte repeated
// matches itself at every offset, the most work for a scan that is not
// linear.
func TestValuesWorkGrowsWithTheTextAndTheValue(t *testing.T) {
	v := strings.Repeat("a", 256<<10)
	rest := strings.Repeat(" x", 4<<10)
	done := make(chan string, 1)
	go func() { done <- Values("invalid policy: "+v+rest, []string{v}) }()
	select {
	case got := <-done:
		if got != "invalid policy: "+MaskedSecret+rest {
			t.Errorf("the value is not masked whole: %.80q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("masking a 256 KiB value took more than 5 s")
	}
}

// TestRunStartsFollowTheirDefinition checks runStarts, which finds the runs to
// mask in one pass per form, against trying every run of the text. Texts are
// built from the values' own pieces over small alphabets, so heads, tails and
// whole values overlap and repeat.
func TestRunStartsFollowTheirDefinition(t *testing.T) {
	r := rand.New(rand.NewSource(825))
	alphabets := [][]rune{[]rune("ab"), []rune("ab_ "), []rune("aab-"), []rune("a1_.€é"), []rune("ab密"), []rune("ab`'\" "), []rune("int 4")}
	// Pieces of the wording errorWording knows, so values meet it.
	wording := []string{"400 ", "yaml: unmarshal errors:\n  ", "line 4: cannot unmarshal !!str `", "` into int", "yaml: line 4: "}
	word := func(alphabet []rune, n int) string {
		var b strings.Builder
		for range n {
			b.WriteRune(alphabet[r.Intn(len(alphabet))])
		}
		return b.String()
	}
	for range 20000 {
		alphabet := alphabets[r.Intn(len(alphabets))]
		var values []string
		for range 1 + r.Intn(3) {
			values = append(values, word(alphabet, r.Intn(14)))
		}
		var b strings.Builder
		for range r.Intn(6) {
			if r.Intn(4) == 0 {
				b.WriteString(word(alphabet, r.Intn(8)))
				continue
			}
			if r.Intn(5) == 0 {
				b.WriteString(wording[r.Intn(len(wording))])
				continue
			}
			v := values[r.Intn(len(values))]
			from, to := 0, len(v)
			if r.Intn(2) == 0 {
				from = r.Intn(len(v) + 1)
			}
			if r.Intn(2) == 0 {
				to = from + r.Intn(len(v)-from+1)
			}
			b.WriteString(v[from:to])
		}
		s, forms := b.String(), maskedForms(values)
		for _, cut := range []bool{false, true} {
			if got, want := runStarts(s, forms, cut), runStartsByDefinition(s, forms, cut); !slices.Equal(got, want) {
				t.Fatalf("runStarts(%q, %q, %v)\n got %v\nwant %v", s, forms, cut, got, want)
			}
		}
	}
}

// runStartsByDefinition is runStarts by trying every run of s that ends at
// each byte, from the longest.
func runStartsByDefinition(s string, forms []string, cut bool) []int {
	if len(forms) == 0 || s == "" {
		return nil
	}
	start := make([]int, len(s))
	for i := range start {
		start[i] = len(s)
	}
	found := false
	for _, v := range forms {
		for i := range len(s) {
			for from := max(0, i-len(v)+1); from <= i; from++ {
				run := s[from : i+1]
				whole := run == v && (len(run) >= longRun ||
					standsAlone(s, from, i, v) && !slices.Contains(errorWording(s)[from:i+1], true))
				tail := len(run) >= longRun && strings.HasSuffix(v, run)
				head := strings.HasPrefix(v, run) && (len(run) >= longRun || cut && i == len(s)-1)
				if whole || tail || head {
					start[i] = min(start[i], from)
					found = true
				}
			}
		}
	}
	if !found {
		return nil
	}
	return start
}

// TestErrorWording marks the error's own wording, byte by byte, apart from
// the value a YAML type error quotes.
func TestErrorWording(t *testing.T) {
	for _, tc := range []struct {
		text, wording string // wording: '^' under each byte that is wording
	}{
		{
			text:    "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `int` into int",
			wording: "    ^^^^^^^^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^^^^^^^",
		},
		{
			text:    "yaml: line 3: did not find expected key",
			wording: "^^^^^^^^^^^^^^                         ",
		},
		{
			text:    "\n  line 7: cannot unmarshal !!map into []string",
			wording: "   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^",
		},
		{
			// Only a line of its own: inside another message it is not
			// the decoder's.
			text:    "Invalid: line 1: cannot unmarshal !!str into abc",
			wording: "                                                ",
		},
		{
			text:    "line 4: cannot unmarshal !!str `a` into int; more",
			wording: "                                                 ",
		},
	} {
		var got strings.Builder
		for _, w := range errorWording(tc.text) {
			if w {
				got.WriteByte('^')
			} else {
				got.WriteByte(' ')
			}
		}
		if got.String() != tc.wording {
			t.Errorf("errorWording(%q)\n got %q\nwant %q", tc.text, got.String(), tc.wording)
		}
	}
}
