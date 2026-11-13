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
		"127.0.0.1:4317":                                "127.0.0.1:4317",
		"":                                              "",
	} {
		if got := metrics.MaskedEndpoint(endpoint); got != want {
			t.Errorf("MaskedEndpoint(%q) = %q, want %q", endpoint, got, want)
		}
	}
}
