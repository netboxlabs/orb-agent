package redact

import "testing"

// TestValues masks a policy's resolved values in a backend's error text,
// whole and in the truncated forms backends quote them in, and leaves the
// rest of the text readable.
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
			name:   "the first 7 characters yaml.v3 quotes of a longer value",
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
			name:   "a run of 4 characters of a value",
			text:   "unknown option cred",
			values: []string{long},
			want:   "unknown option ********",
		},
		{
			name:   "a run of 3 characters of a value is left",
			text:   "line 7: bad value",
			values: []string{"xyz-lin-q"},
			want:   "line 7: bad value",
		},
		{
			name:   "a value shorter than 4 characters, where it appears whole",
			text:   "community ab9 refused",
			values: []string{"ab9"},
			want:   "community ******** refused",
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
