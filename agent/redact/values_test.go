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
	"unicode"
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

// ddIntParsing is device-discovery's refusal of a string in a field that
// takes an integer, as the agent writes the JSON body it answers with.
const ddIntParsing = "[map[error:Input should be a valid integer, unable to parse string as an integer field:policies.p1.scope.0.timeout type:int_parsing]]"

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
			// Python's repr quotes a value holding both quotes in single
			// quotes, escaping those; no Go or JSON form escapes them so.
			name:   "a value with both quotes, as Python's repr quotes it",
			text:   `bad password 'Ab\'c"de\'f"gh\'i"jk'`,
			values: []string{`Ab'c"de'f"gh'i"jk`},
			want:   `bad password '********'`,
		},
		{
			// No Go or JSON form holds \x01 beside an unescaped double quote.
			name:   "a value with both quotes and a control character, as Python's repr quotes it",
			text:   `bad password 'a\'b"c\x01defgh'`,
			values: []string{"a'b\"c\x01defgh"},
			want:   `bad password '********'`,
		},
		{
			name:   "a value with a no-break space, as Python's repr escapes it",
			text:   `bad password 'ab\xa0cdefgh'`,
			values: []string{"ab\u00a0cdefgh"},
			want:   `bad password '********'`,
		},
		{
			name:   "a value with a next-line character, as Python's repr escapes it",
			text:   `bad password 'secret\x85xy'`,
			values: []string{"secret\u0085xy"},
			want:   `bad password '********'`,
		},
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
			// The value is masked where the error quotes it; inside the
			// error's words, masking it would show which run of them it is.
			name:   "a value of longRun bytes that is a run of the YAML error's words is masked only where it is quoted",
			text:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `marshal` into int",
			values: []string{"marshal"},
			want:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `********` into int",
		},
		{
			name:   "a long value's head that is a run of the YAML error's words is left there",
			text:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `three` into int",
			values: []string{"unmarshal errors: and more"},
			want:   "400 yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `three` into int",
		},
		{
			name:   "a long value that runs on past the YAML error's words is masked",
			text:   "400 yaml: unmarshal errors:x9Qz-tail",
			values: []string{"errors:x9Qz-tail"},
			want:   "400 yaml: unmarshal ********",
		},
		{
			// device-discovery refuses a field of the wrong type with
			// pydantic's message, which quotes nothing of the input.
			name:   "a short value that is a word of device-discovery's type error is left",
			text:   "403 " + ddIntParsing,
			values: []string{"a", "valid", "type", "integer"},
			want:   "403 " + ddIntParsing,
		},
		{
			// A message of a validator of device-discovery's own can quote
			// the value: it is not wording the agent knows.
			name:   "a short value in device-discovery's message of its own is masked",
			text:   "403 [map[error:Value error, sw1: position and face go together; set both field:policies.p1.scope.0 type:value_error]]",
			values: []string{"sw1"},
			want:   "403 [map[error:Value error, ********: position and face go together; set both field:policies.p1.scope.0 type:value_error]]",
		},
		{
			name:   "a short value is masked in device-discovery's message of its own, and left in its type error",
			text:   "403 [" + ddIntParsing[1:len(ddIntParsing)-1] + " map[error:Value error, a: position and face go together; set both field:policies.p1.scope.1 type:value_error]]",
			values: []string{"a"},
			want:   "403 [" + ddIntParsing[1:len(ddIntParsing)-1] + " map[error:Value error, ********: position and face go together; set both field:policies.p1.scope.1 type:value_error]]",
		},
		{
			// The field is a path of names, indices and keys, with no space
			// in it but in a name the agent can't tell from the message.
			name:   "a short value in device-discovery's type error for a policy whose name has a space is masked",
			text:   "403 [map[error:Input should be a valid integer, unable to parse string as an integer field:policies.my policy.scope.0.timeout type:int_parsing]]",
			values: []string{"a"},
			want:   "403 [map[error:Input should be ******** valid integer, unable to parse string as an integer field:policies.my policy.scope.0.timeout type:int_parsing]]",
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
			// yaml.v3 quotes a value of up to 10 bytes whole, new lines and all.
			name:   "a short value that is a word of a YAML type error quoting a value with a new line",
			text:   "yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `a\nb` into int",
			values: []string{"a\nb", "int"},
			want:   "yaml: unmarshal errors:\n  line 4: cannot unmarshal !!str `********` into int",
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
			name:   "a short value with a single quote in a text Python quotes in single quotes",
			text:   `[input_value='pw="it\'s"', input_type=str]`,
			values: []string{"it's"},
			want:   `[input_value='pw="********"', input_type=str]`,
		},
		{
			// U+1C89 is in Unicode 16, which Python 3.14 prints and Go 1.26's
			// Unicode 15 tables don't assign.
			name:   "a short value Python quotes with a character newer than Go's Unicode tables",
			text:   `[input_value='\x07` + "Ᲊ" + `', input_type=str]`,
			values: []string{"\x07Ᲊ"},
			want:   `[input_value='********', input_type=str]`,
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

// TestValuesMaskEachLineOfAValueOfSeveralLines masks a value of several
// lines, such as a private key, in a text that quotes one of its lines, as a
// backend that prints the value line by line does: each line of longRun bytes
// or more, wherever it occurs whole. A shorter line, such as a brace, is
// left, since it is more likely the text's own.
func TestValuesMaskEachLineOfAValueOfSeveralLines(t *testing.T) {
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\r\n" +
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\r\n" +
		"QyNTUxOQAAACDx2Vn4zP0kq8c1+Lr6aQe2J0nRyWnLnYc4mJk1rVgk2wAAAJgH5w7lB+cO\r\n" +
		"-----END OPENSSH PRIVATE KEY-----\r\n"
	doc := "{\n  \"private_key\": \"v3ry-l0ng-s3cret\"\n}"
	for _, tc := range []struct {
		name, text, value, want string
	}{
		{
			name:  "a middle line, indented as a YAML dump prints it",
			text:  "    QyNTUxOQAAACDx2Vn4zP0kq8c1+Lr6aQe2J0nRyWnLnYc4mJk1rVgk2wAAAJgH5w7lB+cO",
			value: key,
			want:  "    ********",
		},
		{
			name:  "a line inside other text",
			text:  "bad key material b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW at line 2",
			value: key,
			want:  "bad key material ******** at line 2",
		},
		{
			name:  "a line of longRun bytes or more, and not a brace",
			text:  `{"level":"info","private_key": "v3ry-l0ng-s3cret"}`,
			value: doc,
			want:  `{"level":"info",********}`,
		},
		{
			name:  "the whole value, its short line with it",
			text:  "creds: user\nlong-password-1 end",
			value: "user\nlong-password-1",
			want:  "creds: ******** end",
		},
		{
			name:  "the whole value escaped as JSON, its short line with it",
			text:  `creds: "user\nlong-password-1"`,
			value: "user\nlong-password-1",
			want:  `creds: "********"`,
		},
		{
			name:  "a line that occurs twice, overlapping",
			text:  "ababababab",
			value: "first line\nabababab\nlast line",
			want:  "********",
		},
		{
			name:  "a middle line with quotes, escaped as JSON",
			text:  `{"msg":"middle \"quoted\" line"}`,
			value: "first line\nmiddle \"quoted\" line\nlast line",
			want:  `{"msg":"********"}`,
		},
		{
			// The line as it is ends at the first of the two backslashes JSON
			// escapes it with; the escaped line takes both, so the JSON line
			// a backend's adapter parses stays valid.
			name:  "a line ending in a backslash, in a JSON log line",
			text:  `{"msg":"line","text":"first-line-abc \\"}`,
			value: "first-line-abc \\\nsecond-line-def",
			want:  `{"msg":"line","text":"********"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Values(tc.text, []string{tc.value}); got != tc.want {
				t.Errorf("Values(%q)\n got %q\nwant %q", tc.text, got, tc.want)
			}
		})
	}
}

// TestCutValues masks a value the end of a cut text runs through, from its
// first byte, which Values leaves: in a text that is not cut, a value's first
// bytes at its end are the text's own. The text past the cut tells whether a
// value runs through it.
func TestCutValues(t *testing.T) {
	for _, tc := range []struct {
		name   string
		text   string
		after  string
		values []string
		want   string
	}{
		{"a cut after the value's first byte", "refused: xk", "3Y-9xQz", nil, "refused: x********"},
		{"a cut after the value's first 6 bytes", "refused: k3Y-9x", "Qz", nil, "refused: ********"},
		{"a cut inside a head the error shortens", "input_value='k3Y", "-9xQ...'", nil, "input_value='********"},
		{"a value whole before the cut", "refused: k3Y-9xQz, then", "", nil, "refused: ********, then"},
		{"a truncated value's tail the cut runs through", "input_value='Pl41n-r3sol...ential", "-7f3a'", []string{"Pl41n-r3solved-credential-7f3a"}, "input_value='********...********"},
		{"a run from the middle of a value at the cut, the text going on otherwise", "unknown option r3solved-cred", "ential and more", []string{"Pl41n-r3solved-credential-7f3a"}, "unknown option r3solved-cred"},
		{"no value at the cut", "refused: xx", "x", nil, "refused: xx"},
		{"a short head before the cut", "refused: k3 then xx", "x", nil, "refused: k3 then xx"},
		{"the value's first byte, the text going on otherwise", "into int", "\n  line 5", nil, "into int"},
		{"the value's first bytes, the text ending before a head of longRun", "refused: xk3", "Y", nil, "refused: xk3"},
		{"a short value the cut runs through", "refused: t", "0k\n", []string{"t0k"}, "refused: ********"},
		{"a short value the cut runs through inside a word", "into int", "0k\n", []string{"t0k"}, "into int"},
		{"a short value the cut runs through, followed by a word", "refused: t", "0kx", []string{"t0k"}, "refused: t"},
		{"a short value the cut runs through in the error's wording", "invalid: yaml: li", "ne 3: did not find expected key", []string{"line"}, "invalid: yaml: li"},
		{"a long value the cut runs through in the error's wording", "400 yaml: unmar", "shal errors:\n  line 4: cannot unmarshal !!str `three` into int", []string{"marshal"}, "400 yaml: unmar"},
		// Before the cut, the head is all the error's wording; the text past
		// the cut goes on with the value, as the whole text masks it.
		{"a long value's head of the error's wording that runs on past the cut", "400 yaml: unmarshal errors:", "x9Qz-tail", []string{"errors:x9Qz-tail"}, "400 yaml: unmarshal ********"},
		{"a short value the cut runs through where a type error quotes it", "  line 4: cannot unmarshal !!str `li", "ne` into int\n", []string{"line"}, "  line 4: cannot unmarshal !!str `********"},
		{"a short value with new lines the cut runs through", "x a\nb", "\nc rest", []string{"a\nb\nc"}, "x ********"},
		{"a short value whole at the cut that the text goes on with as a word", "refused: t0k", "t0k more", []string{"t0k"}, "refused: t0k"},
		{"a short value that is a word of a type error quoting a value with a new line, cut after it", "  line 4: cannot unmarshal !!str `a\nb` into int", "\n  line 5: cannot unmarshal !!str `x` into int", []string{"int"}, "  line 4: cannot unmarshal !!str `a\nb` into int"},
		{"a short value with a new line the cut runs through, no line ending near", "x a\nb", "c rest" + strings.Repeat("y", maxCutReach), []string{"a\nbc"}, "x ********"},
		// Past maxCutReach, the line may go on as no type error does.
		{"a short value the cut runs through where a line too long to tell quotes it", "  line 4: cannot unmarshal !!str `li", "ne` into int" + strings.Repeat("x", maxCutReach) + " and more", []string{"line"}, "  ******** 4: cannot unmarshal !!str `********"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := tc.values
			if values == nil {
				values = []string{"k3Y-9xQz"}
			}
			if got := CutValues(tc.text, tc.after, values); got != tc.want {
				t.Errorf("CutValues(%q, %q)\n got %q\nwant %q", tc.text, tc.after, got, tc.want)
			}
			if got, want := CutValues(tc.text, "", values), Values(tc.text, values); got != want {
				t.Errorf("CutValues(%q) with nothing after\n got %q\nwant %q, as Values", tc.text, got, want)
			}
		})
	}
	if got := Values("refused: xk", []string{"k3Y-9xQz"}); got != "refused: xk" {
		t.Errorf("Values masks the end of a text that is not cut: %q", got)
	}
	// A line of a value of several lines the cut runs through, as a bound on
	// a refusal that quotes the value whole cuts it.
	multi := strings.Repeat("A", 20) + "\nZq9xW3rT7yU1iO5pL2kJ\nEND"
	if got := CutValues("refused: "+strings.Repeat("A", 20)+" Zq9xW3rT7y", "U1iO5pL2kJ END", []string{multi}); got != "refused: ******** ********" {
		t.Errorf("CutValues leaves the first bytes of a line at the cut: %q", got)
	}
	// A line is masked only whole: past the cut, the text goes on otherwise.
	if got := CutValues("refused: Zq9xW3rT7y", " and more", []string{multi}); got != "refused: Zq9xW3rT7y" {
		t.Errorf("CutValues masks the first bytes of a line the text does not go on with: %q", got)
	}
	// A line the cut runs through that is the error's own wording is not a
	// value there.
	wordingLine := "x9Qz\nyaml: unmarshal errors:\nend"
	if got := CutValues("400 yaml: unmar", "shal errors:\n  line 4: cannot unmarshal !!str `three` into int", []string{wordingLine}); got != "400 yaml: unmar" {
		t.Errorf("CutValues masks a line of the error's wording the cut runs through: %q", got)
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

// TestValuesWorkGrowsWithTheTextInTheErrorWording masks a long value made of
// the error's wording in a long text of it within the same bound: whether a
// run is all wording is told in constant time, not by reading the run, which
// at every byte of the text would take time in proportion to the text times
// the value.
func TestValuesWorkGrowsWithTheTextInTheErrorWording(t *testing.T) {
	const w = "yaml: unmarshal errors:"
	text, v := strings.Repeat(w, 20000), strings.Repeat(w, 4000)
	done := make(chan string, 1)
	go func() { done <- Values(text, []string{v}) }()
	select {
	case got := <-done:
		if got != text {
			t.Errorf("the error's own wording is masked: %.80q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("masking a 92 KiB value of the error's wording in 460 KiB of it took more than 5 s")
	}
}

// TestRunStartsFollowTheirDefinition checks runStarts, which finds the runs to
// mask in one pass per form, against trying every run of the text. Texts are
// built from the values' own pieces over small alphabets, so heads, tails and
// whole values overlap and repeat.
func TestRunStartsFollowTheirDefinition(t *testing.T) {
	r := rand.New(rand.NewSource(825))
	alphabets := [][]rune{[]rune("ab"), []rune("ab_ "), []rune("aab-"), []rune("a1_.€é"), []rune("ab密"), []rune("ab`'\" "), []rune("int 4"), []rune("ab\n "), []rune("aab\n")}
	// Pieces of the wording errorWording knows, so values meet it.
	wording := []string{
		"400 ", "yaml: unmarshal errors:\n  ", "line 4: cannot unmarshal !!str `", "` into int", "yaml: line 4: ",
		"map[error:Input should be a valid boolean field:p.a type:bool_type]",
	}
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
			if r.Intn(4) == 0 {
				// A run of the wording, so a long value meets it too.
				w := wording[r.Intn(len(wording))]
				from := r.Intn(len(w))
				values = append(values, w[from:from+r.Intn(len(w)-from+1)])
				continue
			}
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
		// The text past a cut goes on with a value, or with anything; when
		// with a value, the text before can end inside it, so the cut runs
		// through a head of it, a run from its middle or the whole of it.
		after := word(alphabet, r.Intn(8))
		if v := values[r.Intn(len(values))]; r.Intn(2) == 0 {
			k := r.Intn(len(v) + 1)
			if r.Intn(2) == 0 {
				b.WriteString(v[r.Intn(k+1):k])
			}
			after = v[k:] + after
		}
		s, m := b.String(), NewMasker(values)
		forms, lines := formValues(m), lineValues(m)
		if got, want := m.runStarts(s, false, ""), runStartsByDefinition(s, forms, lines, false, ""); !slices.Equal(got, want) {
			t.Fatalf("runStarts(%q, %q, %q)\n got %v\nwant %v", s, forms, lines, got, want)
		}
		if got, want := m.runStarts(s, true, after), runStartsByDefinition(s, forms, lines, true, after); !slices.Equal(got, want) {
			t.Fatalf("runStarts(%q, %q, %q) cut before %q\n got %v\nwant %v", s, forms, lines, after, got, want)
		}
	}
}

// runStartsByDefinition is runStarts by trying every run of s that ends at
// each byte, from the longest. A line of a value of several lines is masked
// only whole, or as a head at the end of a text cut before after that after
// goes on with to the whole line. No run that is all the error's wording is
// masked, nor a line.
func runStartsByDefinition(s string, forms, lines []string, cut bool, after string) []int {
	if len(forms) == 0 && len(lines) == 0 || s == "" {
		return nil
	}
	start := make([]int, len(s))
	for i := range start {
		start[i] = len(s)
	}
	found := false
	// In a cut text, the error's wording, and whether a value is a word of
	// its own, are told from the text it was cut from.
	text := s
	if cut {
		text = s + after
	}
	wording := errorWording(text)
	for _, v := range forms {
		for i := range len(s) {
			for from := max(0, i-len(v)+1); from <= i; from++ {
				run := s[from : i+1]
				long := len(run) >= longRun && !allWording(wording, from, i)
				whole := run == v && (long ||
					len(run) < longRun && standsAlone(text, from, i, v) && !slices.Contains(wording[from:i+1], true))
				tail := long && strings.HasSuffix(v, run) || cut && i == len(s)-1 && tailRunsThrough(s, after, from, v)
				head := strings.HasPrefix(v, run) && (long || cut && i == len(s)-1 && runsThrough(s, after, from, v))
				if whole || tail || head {
					start[i] = min(start[i], from)
					found = true
				}
			}
		}
	}
	for _, v := range lines {
		for i := range len(s) {
			for from := max(0, i-len(v)+1); from <= i; from++ {
				run := s[from : i+1]
				line := run == v || cut && i == len(s)-1 && strings.HasPrefix(v, run) && strings.HasPrefix(after, v[len(run):])
				if line && !allWording(wording, from, from+len(v)-1) {
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

// tailRunsThrough reports whether s[from:] is the first bytes of a tail of v,
// longRun bytes or more and not all the error's wording, that runs through
// the cut between s and after: in the text they make, it ends past the cut.
func tailRunsThrough(s, after string, from int, v string) bool {
	text := s + after
	wording := errorWording(text)
	for n := len(s) - from + 1; n <= len(v) && from+n <= len(text); n++ {
		if n >= longRun && text[from:from+n] == v[len(v)-n:] && !allWording(wording, from, from+n-1) {
			return true
		}
	}
	return false
}

// runsThrough reports whether the head of v at s[from:] runs through the cut
// between s and after: in the text they make, v goes on past the cut to a
// head of longRun bytes or more that is not all the error's wording, or to
// the whole of a shorter v that is a word of its own there, outside the
// error's wording.
func runsThrough(s, after string, from int, v string) bool {
	text := s + after
	wording := errorWording(text)
	// n is how far the text goes on with v from there.
	n := 0
	for from+n < len(text) && n < len(v) && text[from+n] == v[n] {
		n++
	}
	if from+n <= len(s) {
		return false // the head ends before the cut
	}
	if len(v) < longRun {
		return n == len(v) && standsAlone(text, from, from+n-1, v) && !slices.Contains(wording[from:from+n], true)
	}
	return n >= longRun && !allWording(wording, from, from+n-1)
}

// allWording reports whether every byte from from to to is the error's
// wording, read byte by byte; past the text, none is.
func allWording(wording []bool, from, to int) bool {
	return to < len(wording) && !slices.Contains(wording[from:to+1], false)
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
		{
			// yaml.v3 quotes a value of up to 10 bytes whole, new lines and
			// all.
			text:    "  line 4: cannot unmarshal !!str `a\nb` into int",
			wording: "  " + strings.Repeat("^", 32) + "   " + strings.Repeat("^", 10),
		},
		{
			// A longer value it cuts to its first 7 bytes and "...".
			text:    "  line 4: cannot unmarshal !!str `a\nbcdef...` into int",
			wording: "  " + strings.Repeat("^", 32) + strings.Repeat(" ", 10) + strings.Repeat("^", 10),
		},
		{
			text:    "  line 4: cannot unmarshal !!str `012345678\na` into int",
			wording: strings.Repeat(" ", len("  line 4: cannot unmarshal !!str `012345678\na` into int")),
		},
		{
			// device-discovery's type errors, as the agent writes them: each
			// element whose message pydantic gives for a type, and no other.
			text:    "[map[error:Input should be a valid integer, unable to parse string as an integer field:policies.p1.scope.0.timeout type:int_parsing] map[error:Value error, sw1: bad face field:policies.p1.scope.1 type:value_error] map[error:Field required field:policies.p1.scope.2.hostname type:missing]]",
			wording: " " + strings.Repeat("^", len("map[error:Input should be a valid integer, unable to parse string as an integer field:policies.p1.scope.0.timeout type:int_parsing]")) + strings.Repeat(" ", len(" map[error:Value error, sw1: bad face field:policies.p1.scope.1 type:value_error] ")) + strings.Repeat("^", len("map[error:Field required field:policies.p1.scope.2.hostname type:missing]")) + " ",
		},
		{
			text:    "  line 4: cannot unmarshal !!str `a` into int\n  line 5: cannot unmarshal !!str `b` into int",
			wording: "  " + strings.Repeat("^", 32) + " " + strings.Repeat("^", 10) + "   " + strings.Repeat("^", 32) + " " + strings.Repeat("^", 10),
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

// The Python forms were checked character by character against the agent
// image's Python 3.14 (Unicode 16) with Go's Unicode 15 tables. A form keeps a
// character Go's tables don't assign as it is, as Python prints it. Nothing
// covers the other way: a Go that knows a newer Unicode than Python prints a
// character Python escapes. Check the forms again before changing this.
func TestPythonFormsAssumeGoUnicode15(t *testing.T) {
	if unicode.Version != "15.0.0" {
		t.Errorf("Go's Unicode tables are %s: check pythonRepr against the agent image's Python", unicode.Version)
	}
}

// formValues returns the texts of m's forms.
func formValues(m *Masker) []string {
	var vs []string
	for _, f := range m.forms {
		vs = append(vs, f.v)
	}
	return vs
}

// lineValues returns the texts of m's lines.
func lineValues(m *Masker) []string {
	var vs []string
	for _, f := range m.lines {
		vs = append(vs, f.v)
	}
	return vs
}

// TestCutMasksWhatTheWholeTextMasks cuts texts that quote values whole,
// truncated as pydantic and yaml.v3 quote them, by a tail alone, run into
// another value or into the error's wording, at every kind of place: every
// byte before the cut that masking the whole text masks, MaskCut masks too.
// Values are also drawn from the wording, so a run of it meets the cut.
func TestCutMasksWhatTheWholeTextMasks(t *testing.T) {
	r := rand.New(rand.NewSource(909))
	wording := []string{
		"yaml: unmarshal errors:\n  ", "line 4: cannot unmarshal !!str `", "` into int\n", "yaml: line 4: ",
		"map[error:Input should be a valid boolean field:p.a type:bool_type]",
		"[map[error:Field required field:policies.p1.scope.0.hostname type:missing] ",
	}
	alphabets := []string{"abcdefghijklmnopqrstuvwxyz0123456789-", "ab", "aab-", "ab密é", "aab\n ", "int marshal"}
	lengths := []int{3, 6, 7, 8, 24, 25, 49, 50, 300}
	value := func(alphabet string, n int) string {
		var b strings.Builder
		rs := []rune(alphabet)
		for b.Len() < n {
			b.WriteRune(rs[r.Intn(len(rs))])
		}
		return b.String()
	}
	for range 4000 {
		alphabet := alphabets[r.Intn(len(alphabets))]
		var values []string
		for range 1 + r.Intn(3) {
			if r.Intn(3) == 0 {
				w := wording[r.Intn(len(wording))]
				from := r.Intn(len(w))
				if v := w[from:from+r.Intn(len(w)-from+1)] + value(alphabet, r.Intn(2)*r.Intn(10)); v != "" {
					values = append(values, v)
				}
				continue
			}
			values = append(values, value(alphabet, lengths[r.Intn(len(lengths))]))
		}
		if len(values) == 0 {
			continue
		}
		var b strings.Builder
		for range 1 + r.Intn(5) {
			if r.Intn(2) == 0 {
				b.WriteString(wording[r.Intn(len(wording))])
			} else {
				b.WriteString(value("xyz _.'\n", r.Intn(10)))
			}
			v := values[r.Intn(len(values))]
			switch r.Intn(5) {
			case 0:
				if len(v) > 50 {
					b.WriteString("input_value='" + v[:25] + "..." + v[len(v)-24:] + "'")
				} else {
					b.WriteString("`" + v + "`")
				}
			case 1:
				b.WriteString(v)
			case 2:
				b.WriteString(v[r.Intn(len(v)):])
			case 3:
				b.WriteString(v[:r.Intn(len(v)+1)])
			case 4:
				w := values[r.Intn(len(values))]
				b.WriteString(v[r.Intn(len(v)):] + w[:1+r.Intn(len(w))])
			}
		}
		text, m := b.String(), NewMasker(values)
		if text == "" {
			continue
		}
		whole := maskedBytes(m, text, false, "")
		for range 10 {
			c := 1 + r.Intn(len(text))
			for c < len(text) && !utf8.RuneStart(text[c]) {
				c--
			}
			if c <= 0 || c >= len(text) {
				continue
			}
			cut := maskedBytes(m, text[:c], true, text[c:])
			for i := range c {
				if whole[i] && !cut[i] {
					t.Fatalf("byte %d is masked in the whole text, not cut at %d: %q, values %q\nwhole: %q\n  cut: %q",
						i, c, text, values, m.Mask(text), m.MaskCut(text[:c], text[c:]))
				}
			}
		}
	}
}

// maskedBytes returns which bytes of s, cut before after when cut is set,
// m masks.
func maskedBytes(m *Masker, s string, cut bool, after string) []bool {
	masked := make([]bool, len(s))
	start := m.runStarts(s, cut, after)
	if start == nil {
		return masked
	}
	earliest := len(s)
	for i := len(s) - 1; i >= 0; i-- {
		earliest = min(earliest, start[i])
		masked[i] = earliest <= i
	}
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
	return masked
}
