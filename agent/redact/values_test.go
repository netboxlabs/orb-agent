package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
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
			// The value's own first byte is no letter or digit, so it
			// starts a word wherever it is.
			name:   "a short value whose edge is punctuation, glued to a word",
			text:   "x-abc refused",
			values: []string{"-abc"},
			want:   "x******** refused",
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
