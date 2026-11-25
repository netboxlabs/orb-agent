package redact

import (
	"reflect"
	"strings"
	"testing"
)

// TestLogins_ReturnsEveryFormOfEachEndpointArgsLogin returns the login each
// endpoint or target flag's value carries in every form a line can write it:
// as written, trimmed; percent-decoded, as a gRPC client decodes the address
// it is given; and quoted, as Go's %q and JSON quote it. The longest come
// first, so that one form found inside a longer one is masked with it.
func TestLogins_ReturnsEveryFormOfEachEndpointArgsLogin(t *testing.T) {
	got := Logins([]string{
		"--otel-endpoint", " grpc://canary-user:canary%40pass@127.0.0.1:4317 ",
		"--host", "ops@example.com",
		"--diode-target", "grpc://127.0.0.1:8080",
		"--otel-endpoint",
	})
	want := []string{"canary-user:canary%40pass", "canary-user:canary@pass"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Logins() = %q, want %q", got, want)
	}
	if got := Logins(nil); got != nil {
		t.Errorf("Logins(nil) = %q, want nil", got)
	}

	got = Logins([]string{"--diode-target", `canary-user:canary"pass\x@127.0.0.1:4317`})
	want = []string{`canary-user:canary\"pass\\x`, `canary-user:canary"pass\x`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Logins() of a login holding a quote and a backslash = %q, want %q", got, want)
	}
}

// A collector URL's login can be percent-encoded, as a password holding an @
// has to be. The gRPC client decodes the address it is given and writes the
// login decoded in its errors, which the Python exporter logs on every export
// it fails: the line below is one, as the exporter printed it.
func TestMaskLogins_MasksALoginPercentDecoded(t *testing.T) {
	line := "WARNING: opentelemetry.exporter.otlp.proto.grpc.exporter: Transient error StatusCode.UNAVAILABLE" +
		" encountered while exporting metrics to canary-user:canary%40pass@127.0.0.1:1, retrying in 0.93s." +
		" Error details: errors resolving canary-user:canary@pass@127.0.0.1:1: [field:hostname lookup error:" +
		"address lookup failed for canary-user:canary@pass@127.0.0.1:1: Misformatted domain name]"
	got := MaskLogins(line, Logins([]string{"--otel-endpoint", "grpc://canary-user:canary%40pass@127.0.0.1:1"}))
	if strings.Contains(got, "canary") || strings.Contains(got, "pass@") {
		t.Errorf("MaskLogins() left the login in %q", got)
	}
	if strings.Count(got, MaskedSecret+"@127.0.0.1:1") != 3 {
		t.Errorf("MaskLogins() = %q, want the address masked three times", got)
	}
}

// A login is masked only where it starts a word: a user alone, as a token,
// is not masked inside a longer user of another address. Logins that overlap
// are masked longest first, so no part of one is left.
func TestMaskLogins_MasksAWholeLoginLongestFirst(t *testing.T) {
	logins := Logins([]string{"--otel-endpoint", "grpc://ops@collector:4317"})
	line := `{"msg":"device contact noc-ops@example.com, ssh ops@10.0.0.1","target":"ops@h","x":'ops@h',a=ops@h,(ops@h),[ops@h],\nops@h`
	want := `{"msg":"device contact noc-ops@example.com, ssh ********@10.0.0.1","target":"********@h","x":'********@h',a=********@h,(********@h),[********@h],\n********@h`
	if got := MaskLogins(line, logins); got != want {
		t.Errorf("MaskLogins() = %q, want %q", got, want)
	}

	logins = Logins([]string{
		"--diode-target", "grpc://canary-user:canary@collector:8080",
		"--otel-endpoint", "grpc://canary-user:canary%40pass@collector:4317",
	})
	line = "errors resolving canary-user:canary@pass@collector:4317, ingest to canary-user:canary@collector:8080"
	want = "errors resolving ********@collector:4317, ingest to ********@collector:8080"
	if got := MaskLogins(line, logins); got != want {
		t.Errorf("MaskLogins() = %q, want %q", got, want)
	}
}

// A login holding a quote or a backslash is written escaped in a JSON line
// and in an error that quotes it with %q.
func TestMaskLogins_MasksALoginEscaped(t *testing.T) {
	logins := Logins([]string{"--otel-endpoint", `canary-user:canary"pass\x@collector:4317`})
	line := `{"error":"otel endpoint \"canary-user:canary\"pass\\x@collector:4317\" is invalid"}`
	want := `{"error":"otel endpoint \"********@collector:4317\" is invalid"}`
	if got := MaskLogins(line, logins); got != want {
		t.Errorf("MaskLogins() = %q, want %q", got, want)
	}
}

// A password written with a raw %, as a random one can hold, is decoded by
// the gRPC client leniently: a valid %XX is decoded and an invalid one is
// kept. A decoded byte that is not UTF-8 is written as the byte by grpc-go,
// which the agent's relay turns into U+FFFD, and as Latin-1 by Python's
// gRPC, as the worker's exporter logged it (the first line below, as the
// agent relayed it from a real run).
func TestMaskLogins_MasksALoginDecodedLenientlyOrNotUTF8(t *testing.T) {
	for _, tc := range []struct{ line, endpoint string }{
		{
			"Transient error StatusCode.UNAVAILABLE encountered while exporting metrics to canary-user:canary%F3pass@127.0.0.1:14317," +
				" retrying in 0.98s. Error details: errors resolving canary-user:canaryópass@127.0.0.1:14317:" +
				" [field:hostname lookup error:address lookup failed for canary-user:canaryópass@127.0.0.1:14317: Misformatted domain name]",
			"grpc://canary-user:canary%F3pass@127.0.0.1:14317",
		},
		{
			"rpc error: code = Unavailable desc = invalid target address canary-user:canary\xf3pass@127.0.0.1:14317," +
				" error info: address canary-user:canary\xf3pass@127.0.0.1:14317:443: too many colons in address",
			"canary-user:canary%F3pass@127.0.0.1:14317",
		},
		{
			string([]rune("invalid target address canary-user:canary\xf3pass@127.0.0.1:14317")),
			"canary-user:canary%F3pass@127.0.0.1:14317",
		},
		{
			"ERROR: grpc._cython.cygrpc: Invalid encoding on b'errors resolving canary-user:canary\\xf3pass@127.0.0.1:14317'",
			"grpc://canary-user:canary%F3pass@127.0.0.1:14317",
		},
		{
			"errors resolving canary-user:canary%zz@pass@127.0.0.1:14317",
			"grpc://canary-user:canary%zz%40pass@127.0.0.1:14317",
		},
	} {
		got := MaskLogins(tc.line, Logins([]string{"--otel-endpoint", tc.endpoint}))
		if strings.Contains(got, "canary") || !strings.Contains(got, MaskedSecret+"@127.0.0.1:14317") {
			t.Errorf("MaskLogins(%q) = %q, want the login masked", tc.line, got)
		}
	}
}

// A user and a password are masked wherever a line writes them before an @,
// whatever comes before them: a log format's ":", a "." or "-" of a longer
// word, a digit, an ANSI colour, or JSON's escaped <. Only a user alone, as
// a token, must start a word, so another user that ends in it is kept.
func TestMaskLogins_MasksAUserAndAPasswordWhereverTheyAre(t *testing.T) {
	logins := Logins([]string{"--otel-endpoint", "grpc://user:pass@h:4317"})
	for _, line := range []string{
		"INFO:device_discovery.client:user:pass@h:4317 unreachable",
		"target:user:pass@h:4317",
		"addr.user:pass@h",
		"x-user:pass@h",
		"x_user:pass@h",
		"1user:pass@h",
		"\x1b[31muser:pass@h:4317\x1b[0m",
		"dial %22user:pass@h",
		`{"msg":"\u003cuser:pass@h\u003e"}`,
		"x@user:pass@h",
	} {
		if got := MaskLogins(line, logins); strings.Contains(got, "user:pass") {
			t.Errorf("MaskLogins(%q) = %q, want the login masked", line, got)
		}
	}
	if got := MaskLogins("contact noc-ops@example.com", Logins([]string{"--diode-target", "grpc://ops@h"})); got != "contact noc-ops@example.com" {
		t.Errorf("MaskLogins() masked a user inside a longer one: %q", got)
	}
}

// The login is read from the authority of a URL written with a scheme,
// whatever its path, query or fragment hold and whether or not a parser
// reads it, so the relay masks the address the exporter writes.
func TestLogins_ReadsTheLoginFromTheAuthority(t *testing.T) {
	for endpoint, line := range map[string]string{
		"grpc://canary-user:canary-pass@127.0.0.1:1/x/a:b@c":               "errors resolving canary-user:canary-pass@127.0.0.1:1",
		"grpc://canary-user:canary-pass@127.0.0.1:1?redirect=grpc://a:b@c": "errors resolving canary-user:canary-pass@127.0.0.1:1",
		"grpc://canary-user:canary-pass@127.0.0.1:1#a:b@c":                 "errors resolving canary-user:canary-pass@127.0.0.1:1",
		"grpc://canary-user:canary-pass@127.0.0.1:1/%zz@x":                 "dial canary-user:canary-pass@127.0.0.1:1",
		// gRPC strips a resolver's scheme written without //.
		"dns:canary-user:canary-pass@127.0.0.1:1": "invalid target address canary-user:canary-pass@127.0.0.1:1",
	} {
		if got := MaskLogins(line, Logins([]string{"--otel-endpoint", endpoint})); strings.Contains(got, "canary") {
			t.Errorf("for %q, MaskLogins(%q) = %q, want the login masked", endpoint, line, got)
		}
	}
}

// A login is also masked as Go's %+q and Python's json.dumps write it, with
// every byte past ASCII escaped.
func TestMaskLogins_MasksALoginEscapedAsASCII(t *testing.T) {
	logins := Logins([]string{"--otel-endpoint", "grpc://us%C3%A4r:p%22q@127.0.0.1:1"})
	for _, line := range []string{
		`{"err":"errors resolving us\u00e4r:p\"q@127.0.0.1:1"}`,
		`dial "us\u00e4r:p\"q@127.0.0.1:1"`,
	} {
		if got := MaskLogins(line, logins); strings.Contains(got, "p\\\"q") {
			t.Errorf("MaskLogins(%q) = %q, want the login masked", line, got)
		}
	}
}

// A password can hold an unescaped /, ? or #, which a URL parser reads as
// the end of the authority. The Diode SDK makes its token URL from the short
// authority Python's urlparse gives it, and urllib3 refuses that URL quoting
// the user and the start of the password, with no @ after them: the first
// line below is the one the worker printed for each of the three, as the SDK
// raised it. With a /, the SDK also logs the path, which starts with the rest
// of the password.
func TestMaskLogins_MasksTheLoginAURLParserReadsShort(t *testing.T) {
	refused := "ERROR: Unable to connect to Diode Server: Failed to obtain access token: Failed to parse:" +
		" 'canary-user:canary' is not a valid host or port"
	masked := "ERROR: Unable to connect to Diode Server: Failed to obtain access token: Failed to parse:" +
		" '********' is not a valid host or port"
	for _, tc := range []struct{ target, line, want string }{
		{"grpc://canary-user:canary/pass@127.0.0.1:8080/diode", refused, masked},
		{"grpc://canary-user:canary?pass@127.0.0.1:8080/diode", refused, masked},
		{"grpc://canary-user:canary#pass@127.0.0.1:8080/diode", refused, masked},
		{
			"grpc://canary-user:canary/pass@127.0.0.1:8080/diode",
			"DEBUG: netboxlabs.diode.sdk.client: Setting up gRPC interceptor for path: /pass@127.0.0.1:8080/diode",
			"DEBUG: netboxlabs.diode.sdk.client: Setting up gRPC interceptor for path: /********@127.0.0.1:8080/diode",
		},
		{
			"grpc://canary-user:canary/pass@127.0.0.1:8080/diode",
			"target grpc://canary-user:canary/pass@127.0.0.1:8080/diode",
			"target grpc://********@127.0.0.1:8080/diode",
		},
	} {
		if got := MaskLogins(tc.line, Logins([]string{"--diode-target", tc.target})); got != tc.want {
			t.Errorf("for %q, MaskLogins(%q) = %q, want %q", tc.target, tc.line, got, tc.want)
		}
	}
}

// A password that starts with a /, ? or # leaves only the user and its : in
// the authority a URL parser reads short, and one with only a port number
// before it the user and that port. urllib3 reads the user as the host,
// with an empty port, and writes it as a host: the lines below are the ones
// the worker printed for each of the three, with --debug for the last, as the
// SDK raised them. With a /, the URL it quotes holds the password before its
// @ too.
func TestMaskLogins_MasksTheUserAURLParserReadsAsAHost(t *testing.T) {
	refused := func(host, url string) string {
		return "ERROR: Unable to connect to Diode Server: Failed to obtain access token: HTTPConnectionPool(host='" + host +
			"', port=80): Max retries exceeded with url: " + url + " (Caused by NameResolutionError(\"HTTPConnection(host='" + host +
			"', port=80): Failed to resolve '" + host + "' ([Errno -2] Name or service not known)\"))"
	}
	for _, tc := range []struct{ target, line, want string }{
		{
			"grpc://canary-user:/canary@127.0.0.1:8080/diode",
			refused("canary-user", "/canary@127.0.0.1:8080/diode/auth/token"),
			refused("********", "/********@127.0.0.1:8080/diode/auth/token"),
		},
		{"grpc://canary-user:?canary@127.0.0.1:8080/diode", refused("canary-user", "/auth/token"), refused("********", "/auth/token")},
		{"grpc://canary-user:#canary@127.0.0.1:8080/diode", refused("canary-user", "/auth/token"), refused("********", "/auth/token")},
		// urllib3 writes the host lowercased, so a user with capitals too.
		{
			"grpc://Canary-User:/canary@127.0.0.1:8080/diode",
			refused("canary-user", "/canary@127.0.0.1:8080/diode/auth/token"),
			refused("********", "/********@127.0.0.1:8080/diode/auth/token"),
		},
		// A password whose start before the separator is a port number: the
		// parser reads the user as the host and that number as its port,
		// which is not masked.
		{
			"grpc://Canary-User:80/canary@127.0.0.1:8080/diode",
			refused("canary-user", "/canary@127.0.0.1:8080/diode/auth/token"),
			refused("********", "/********@127.0.0.1:8080/diode/auth/token"),
		},
		{"grpc://canary-user:0080?canary@127.0.0.1:8080/diode", refused("canary-user", "/auth/token"), refused("********", "/auth/token")},
		{
			"grpc://canary-user:/canary@127.0.0.1:8080/diode",
			"DEBUG: urllib3.connectionpool: Starting new HTTP connection (1): canary-user:80",
			"DEBUG: urllib3.connectionpool: Starting new HTTP connection (1): ********:80",
		},
	} {
		if got := MaskLogins(tc.line, Logins([]string{"--diode-target", tc.target})); got != tc.want {
			t.Errorf("for %q, MaskLogins(%q) = %q, want %q", tc.target, tc.line, got, tc.want)
		}
	}
	logins := Logins([]string{"--diode-target", "grpc://canary-user:/canary@127.0.0.1:8080/diode"})
	if got := MaskLogins("hosts canary-user-2, canary-user.example and xcanary-user", logins); got != "hosts canary-user-2, canary-user.example and xcanary-user" {
		t.Errorf("MaskLogins() masked the user inside a longer host: %q", got)
	}
	if got := MaskLogins("user canary-user", Logins([]string{"--diode-target", "grpc://canary-user:canary@127.0.0.1:8080/diode"})); got != "user canary-user" {
		t.Errorf("MaskLogins() masked as a host a user whose password does not start with a /, ? or #: %q", got)
	}
}

func TestMaskLogins_MasksCompleteLoginsBeforeHostUsers(t *testing.T) {
	args := []string{
		"--diode-target", "grpc://bob:123456/pass@diode",
		"--otel-endpoint", "grpc://bob:" + "pw@collector:4317",
	}
	line := "dial bob:pw@collector:4317"
	want := "dial ********@collector:4317"
	if got := MaskLogins(line, Logins(args)); got != want {
		t.Errorf("MaskLogins() = %q, want %q", got, want)
	}
}

// A user and a password are masked with no @ after them too, where they
// start a word and end one, as before a port or at the end of a sentence,
// but not inside a longer word, at its start or past it; a user alone still
// needs its @.
func TestMaskLogins_MasksAUserAndAPasswordWithNoAtWhereTheyStartAWord(t *testing.T) {
	logins := Logins([]string{"--otel-endpoint", "grpc://user:pass@h:4317"})
	line := "authority user:pass, host 'user:pass', \"user:pass\", =user:pass, /user:pass and xuser:pass;" +
		" user:pass:443, user:pass. user:passage and user:pass1"
	want := "authority ********, host '********', \"********\", =********, /******** and xuser:pass;" +
		" ********:443, ********. user:passage and user:pass1"
	if got := MaskLogins(line, logins); got != want {
		t.Errorf("MaskLogins() = %q, want %q", got, want)
	}
	if got := MaskLogins("user ops, host ops", Logins([]string{"--otel-endpoint", "grpc://ops@h:4317"})); got != "user ops, host ops" {
		t.Errorf("MaskLogins() masked a user alone with no @: %q", got)
	}
}
