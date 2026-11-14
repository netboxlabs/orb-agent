package metrics_test

import (
	"testing"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/metrics"
)

// A collector URL can carry a login, as user:password@host, with a scheme or
// without one: the line that reports the endpoint writes it masked.
func TestMaskedEndpointMasksTheLogin(t *testing.T) {
	for endpoint, want := range map[string]string{
		"grpc://canary-user:canary-pass@127.0.0.1:4317": "grpc://********@127.0.0.1:4317",
		"canary-user:canary-pass@127.0.0.1:4317":        "********@127.0.0.1:4317",
		"https://Canary-T0ken@collector:4317":           "https://********@collector:4317",
		"dns:///canary-user:canary-pass@collector:4317": "dns:///********@collector:4317",
		"grpc://127.0.0.1:4317":                         "grpc://127.0.0.1:4317",
		// As the agent reads it: written without a scheme, a login holding a
		// // or a :// is everything before the last @; with one, the login
		// ends at the authority's last @, or at the last @ when a password
		// holding a / ends the authority before it.
		"user:pa//ss@collector:4317":                      "********@collector:4317",
		"user:pa://ss@h:4317":                             "********@h:4317",
		"user:pass@collector:4317//x":                     "********@collector:4317//x",
		"grpc://u:p@h:4317?x=y@z":                         "grpc://********@h:4317?x=y@z",
		"grpc://u:pa/ss@h:4317":                           "grpc://********@h:4317",
		"grpc://canary-user:canary%40pass@127.0.0.1:4317": "grpc://********@127.0.0.1:4317",
		"127.0.0.1:4317":                                  "127.0.0.1:4317",
		"":                                                "",
	} {
		if got := metrics.MaskedEndpoint(endpoint); got != want {
			t.Errorf("MaskedEndpoint(%q) = %q, want %q", endpoint, got, want)
		}
	}
}
