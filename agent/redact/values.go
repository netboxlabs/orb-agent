package redact

import (
	"strings"
	"unicode/utf8"
)

// minFragment is the shortest run of a longer value that Values masks. A
// backend that truncates a value it quotes still quotes a run of it (yaml.v3
// quotes the first 7 characters of a string over 10), and a shorter run left
// in the text tells little about the value while keeping the rest readable.
const minFragment = 4

// Values returns s with values masked: every run of s that is also a run of
// one of them, minFragment bytes or longer or the whole value, is replaced by
// MaskedSecret. A backend's error can quote a policy's data, whose secret
// references are resolved by then, whole or truncated; the agent passes such
// text through Values before it logs or reports it. Empty values are ignored.
func Values(s string, values []string) string {
	// start[i] is where the earliest masked run ending at s[i] begins, or
	// len(s) when none ends there.
	start := make([]int, len(s))
	for i := range start {
		start[i] = len(s)
	}
	found := false
	for _, v := range values {
		if v == "" {
			continue
		}
		least := min(len(v), minFragment)
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
				run[j] = prev[j-1] + 1
				longest = max(longest, run[j])
			}
			if longest >= least {
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
