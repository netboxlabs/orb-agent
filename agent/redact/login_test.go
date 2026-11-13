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
