package redact

import (
	"testing"
)

func TestURLIn(t *testing.T) {
	for name, tc := range map[string]struct{ text, rawURL, want string }{
		"as it is written": {
			text:   "cloning https://user:pass@host/repo.git failed",
			rawURL: "https://user:pass@host/repo.git",
			want:   "cloning https://********@host/repo.git failed",
		},
		"as it is written, with escapes Go writes in another case": {
			text:   "cloning https://tok%2fen:x-oauth-basic@host/repo.git",
			rawURL: "https://tok%2fen:x-oauth-basic@host/repo.git",
			want:   "cloning https://********@host/repo.git",
		},
		"escaped, as Go writes a parsed URL": {
			text:   `unexpected requesting "https://us%2Fer:p%40ss@host/repo.git/info/refs" status code: 500`,
			rawURL: "https://us%2Fer:p%40ss@host/repo.git",
			want:   `unexpected requesting "https://********@host/repo.git/info/refs" status code: 500`,
		},
		"with *** for its password, as net/http writes it": {
			text:   `Get "https://us/er:***@host/repo.git/info/refs": connection refused`,
			rawURL: "https://us%2Fer:pass@host/repo.git",
			want:   `Get "https://********@host/repo.git/info/refs": connection refused`,
		},
		"quoted, as net/http's errors quote it": {
			text:   `Get "https://a\"b:***@host/repo.git/info/refs": connection refused`,
			rawURL: "https://a%22b:pass@host/repo.git",
			want:   `Get "https://********@host/repo.git/info/refs": connection refused`,
		},
		"escaped, as git writes the user it asks a password for": {
			text:   "fatal: could not read Password for 'https://to%2Bk%3D@host': terminal prompts disabled",
			rawURL: "https://to+k=@host/repo.git",
			want:   "fatal: could not read Password for 'https://********@host': terminal prompts disabled",
		},
		"as go-git writes it again, path-escaped, into the URL it requests": {
			// go-git leaves the user's : unescaped, so the request URL splits
			// the user info at it.
			text:   `unexpected requesting "http://a:b%3Apass@host/repo.git/info/refs" status code: 500`,
			rawURL: "http://a%3Ab:pass@host/repo.git",
			want:   `unexpected requesting "http://********@host/repo.git/info/refs" status code: 500`,
		},
		"decoded, as a git that does not escape it writes the user it asks a password for": {
			text:   "fatal: could not read Password for 'https://a/b@host': terminal prompts disabled",
			rawURL: "https://a%2Fb@host/repo.git",
			want:   "fatal: could not read Password for 'https://********@host': terminal prompts disabled",
		},
		"quoted, when no parser reads it": {
			text:   `parse "https://user:a \"b@host/repo.git": net/url: invalid userinfo`,
			rawURL: `https://user:a "b@host/repo.git`,
			want:   `parse "https://********@host/repo.git": net/url: invalid userinfo`,
		},
		"written without //, with a quote": {
			text:   `cloning https:user:a"b@host/repo.git failed`,
			rawURL: `https:user:a"b@host/repo.git`,
			want:   "cloning https:********@host/repo.git failed",
		},
		"written without //": {
			text:   "cloning https:user:pass@host/repo.git failed",
			rawURL: "https:user:pass@host/repo.git",
			want:   "cloning https:********@host/repo.git failed",
		},
		"with <redacted> for its password, as git writes it when it refuses credentials in a URL": {
			text:   "fatal: URL 'https://to%2fken:<redacted>@host/repo.git' uses plaintext credentials",
			rawURL: "https://to%2fken:pass@host/repo.git",
			want:   "fatal: URL 'https://********@host/repo.git' uses plaintext credentials",
		},
		"scp-like, as it is written": {
			text:   "cloning canaryTOKEN@github.com:org/repo.git failed",
			rawURL: "canaryTOKEN@github.com:org/repo.git",
			want:   "cloning ********@github.com:org/repo.git failed",
		},
		"scp-like, as go-git writes it again as an ssh URL": {
			text:   "reading ssh://canaryTOKEN@github.com/org/repo.git failed",
			rawURL: "canaryTOKEN@github.com:org/repo.git",
			want:   "reading ssh://********@github.com/org/repo.git failed",
		},
		"scp-like, as go-git writes it again with its user path-escaped": {
			text:   "reading ssh://canary%2CTOKEN@github.com/org/repo.git failed",
			rawURL: "canary,TOKEN@github.com:org/repo.git",
			want:   "reading ssh://********@github.com/org/repo.git failed",
		},
		"scp-like, as ssh writes the user it logs in as, not escaped": {
			text:   "canary,TOKEN@ssh.dev.azure.com: Permission denied (password,publickey).",
			rawURL: "canary,TOKEN@ssh.dev.azure.com:v3/org/proj/repo",
			want:   "********@ssh.dev.azure.com: Permission denied (password,publickey).",
		},
		"a URL with no user info": {
			text:   "cloning https://host/repo.git failed",
			rawURL: "https://host/repo.git",
			want:   "cloning https://host/repo.git failed",
		},
		"a user that is a word of the text": {
			text:   "system git clone of ssh://git@host/repo.git failed",
			rawURL: "ssh://git@host/repo.git",
			want:   "system git clone of ssh://********@host/repo.git failed",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := URLIn(tc.text, tc.rawURL); got != tc.want {
				t.Errorf("URLIn(%q, %q)\n got %q\nwant %q", tc.text, tc.rawURL, got, tc.want)
			}
		})
	}
}
