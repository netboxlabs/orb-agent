package metrics

import "testing"

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
