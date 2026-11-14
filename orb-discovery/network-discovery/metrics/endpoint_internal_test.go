package metrics

import (
	"strings"
	"testing"
)

// A login is masked in a text as the agent masks it in a line it relays: as
// written, trimmed; percent-decoded, as a gRPC client writes the address in
// its errors; quoted as %q quotes it; and only where it starts a word, so a
// user alone is not masked inside a longer one.
func TestMaskLoginMasksEveryFormAtTheStartOfAWord(t *testing.T) {
	for _, tc := range []struct{ text, endpoint, want string }{
		{"errors resolving canary-user:canary@pass@127.0.0.1:1", "grpc://canary-user:canary%40pass@127.0.0.1:1", "errors resolving ********@127.0.0.1:1"},
		{"device contact noc-ops@example.com, ssh ops@10.0.0.1", "grpc://ops@collector:4317", "device contact noc-ops@example.com, ssh ********@10.0.0.1"},
		{"dial canary-user:canary-pass@127.0.0.1:4317", " grpc://canary-user:canary-pass@127.0.0.1:4317 ", "dial ********@127.0.0.1:4317"},
		{`otel endpoint "canary-user:canary\"pass@h:4317"`, `canary-user:canary"pass@h:4317`, `otel endpoint "********@h:4317"`},
	} {
		if got := maskLogin(tc.text, tc.endpoint); got != tc.want {
			t.Errorf("maskLogin(%q, %q) = %q, want %q", tc.text, tc.endpoint, got, tc.want)
		}
	}
}

// Lines a gRPC client writes for a login it decodes leniently or to bytes
// that are not UTF-8, as Python's gRPC (Latin-1) and grpc-go (the raw byte,
// or U+FFFD once relayed) write them; a user and a password after a log
// format's prefix, a digit or an ANSI colour; an address read from the
// authority whatever follows it; and a resolver's scheme written without //,
// which gRPC strips.
func TestMaskLoginMasksEveryFormAGRPCClientWrites(t *testing.T) {
	for _, tc := range []struct{ text, endpoint string }{
		{"errors resolving canary-user:canaryópass@127.0.0.1:1", "grpc://canary-user:canary%F3pass@127.0.0.1:1"},
		{"invalid target address canary-user:canary\xf3pass@127.0.0.1:1", "canary-user:canary%F3pass@127.0.0.1:1"},
		{string([]rune("invalid target address canary-user:canary\xf3pass@127.0.0.1:1")), "canary-user:canary%F3pass@127.0.0.1:1"},
		{"errors resolving canary-user:canary%zz@pass@127.0.0.1:1", "grpc://canary-user:canary%zz%40pass@127.0.0.1:1"},
		{"INFO:device_discovery.client:canary-user:canary-pass@127.0.0.1:1 unreachable", "grpc://canary-user:canary-pass@127.0.0.1:1"},
		{"1canary-user:canary-pass@127.0.0.1:1", "grpc://canary-user:canary-pass@127.0.0.1:1"},
		{"\x1b[31mcanary-user:canary-pass@127.0.0.1:1\x1b[0m", "grpc://canary-user:canary-pass@127.0.0.1:1"},
		{"dial canary-user:canary-pass@127.0.0.1:1", "grpc://canary-user:canary-pass@127.0.0.1:1/%zz@x"},
		{"dial canary-user:canary-pass@127.0.0.1:1", "grpc://canary-user:canary-pass@127.0.0.1:1/x/a:b@c"},
		{"invalid target address canary-user:canary-pass@127.0.0.1:1", "dns:canary-user:canary-pass@127.0.0.1:1"},
	} {
		got := maskLogin(tc.text, tc.endpoint)
		if strings.Contains(got, "canary") || !strings.Contains(got, "********@127.0.0.1:1") {
			t.Errorf("maskLogin(%q, %q) = %q, want the login masked", tc.text, tc.endpoint, got)
		}
	}
	if got := MaskedEndpoint("grpc://u:p@h:4317/%zz@x"); got != "grpc://********@h:4317/%zz@x" {
		t.Errorf("MaskedEndpoint() = %q, want the authority's login masked", got)
	}
}
