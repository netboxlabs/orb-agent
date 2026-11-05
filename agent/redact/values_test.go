package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

// encodedJSON encodes v as a backend's API does (gin's JSON answers use
// encoding/json, which escapes <, > and & in strings), and checks the
// encoding escaped something, so the case tests an escaped value.
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

// TestValues masks a policy's resolved values in a backend's error text,
// whole, truncated and escaped as backends quote them, and leaves the words
// that say what is wrong readable.
func TestValues(t *testing.T) {
	const long = "Pl41n-r3solved-credential-7f3a"
	for _, tc := range []struct {
		name   string
		text   string
		values []string
		want   string
	}{
		{
			name:   "a value quoted whole",
			text:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `k3Y-9xQz` into int",
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
			name:   "a run of 7 bytes or more, inside a word",
			text:   "prefixPl41n-r3solvedsuffix",
			values: []string{long},
			want:   "prefix********suffix",
		},
		{
			name:   "a run of exactly 7 bytes, inside a word",
			text:   "idPl41n-rx",
			values: []string{long},
			want:   "id********x",
		},
		{
			name:   "a run of 4 bytes that is a word of its own",
			text:   "unknown option cred",
			values: []string{long},
			want:   "unknown option ********",
		},
		{
			name:   "a run of 4 to 6 bytes inside a word is left",
			text:   "missing authentication; the value must be set",
			values: []string{"authkey-2024!", "SuperSecretValue42"},
			want:   "missing authentication; the value must be set",
		},
		{
			name:   "a run of 3 bytes is left",
			text:   "line 7: bad value",
			values: []string{"xyz-lin-q"},
			want:   "line 7: bad value",
		},
		{
			name:   "a value shorter than 4 bytes, where it is a word of its own",
			text:   "community ab9 refused",
			values: []string{"ab9"},
			want:   "community ******** refused",
		},
		{
			name:   "a value shorter than 4 bytes inside a number is left",
			text:   "400 yaml: unmarshal errors:\n  line 10: cannot unmarshal !!str `0` into bool",
			values: []string{"0"},
			want:   "400 yaml: unmarshal errors:\n  line 10: cannot unmarshal !!str `********` into bool",
		},
		{
			name:   "a value quoted as Go quotes it",
			text:   `strconv.Atoi: parsing "9\"8\\7\"6": invalid syntax`,
			values: []string{`9"8\7"6`},
			want:   `strconv.Atoi: parsing "********": invalid syntax`,
		},
		{
			name:   "a value in a JSON body, HTML characters escaped as Go's encoder does",
			text:   "400 " + encodedJSON(t, map[string]string{"message": "bad community a<b>&c-d3f"}),
			values: []string{"a<b>&c-d3f"},
			want:   `400 {"message":"bad community ********"}`,
		},
		{
			// The run of bytes in common ends inside "ü", whose first byte
			// "ä" shares: the whole character is masked, so the text stays
			// valid UTF-8.
			name:   "a run ending inside a multi-byte character",
			text:   "abcdü!",
			values: []string{"abcdä"},
			want:   "********!",
		},
		{
			// The run starts at the second byte of "Ĥ", which "ä" shares.
			name:   "a run starting inside a multi-byte character",
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
