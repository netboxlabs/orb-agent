package backend

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A password holding an @ is percent-encoded in a URL, and the gRPC client
// the Python OTLP exporter dials with decodes the address before it writes
// it in its errors, which the exporter logs on every export it fails. The
// lines below are two it printed for such a URL; the agent masks the login
// in both forms in what it relays, and a user alone only where it starts a
// word, so another address's user that ends in it is kept.
func TestStartProcess_MasksALoginPercentDecodedInWhatItRelays(t *testing.T) {
	stubProcessTimers(t)
	fake := newFakeCommander(4244)
	captured := stubNewCmdOptions(t, fake)

	fake.stderrCh <- "WARNING: opentelemetry.exporter.otlp.proto.grpc.exporter: Transient error StatusCode.UNAVAILABLE" +
		" encountered while exporting metrics to canary-user:canary%40pass@127.0.0.1:1, retrying in 0.93s." +
		" Error details: errors resolving canary-user:canary@pass@127.0.0.1:1: [field:hostname lookup error:" +
		"address lookup failed for canary-user:canary@pass@127.0.0.1:1: Misformatted domain name]"
	fake.stderrCh <- "ERROR: opentelemetry.exporter.otlp.proto.grpc.exporter: Failed to export metrics to" +
		" canary-user:canary%40pass@127.0.0.1:1, error code: StatusCode.UNAVAILABLE, error details: errors resolving" +
		" canary-user:canary@pass@127.0.0.1:1: [field:hostname lookup error:address lookup failed for" +
		" canary-user:canary@pass@127.0.0.1:1: Misformatted domain name]"
	fake.stdoutCh <- "device contact noc-canarytoken@example.com, ssh canarytoken@10.0.0.1"

	var (
		logMu sync.Mutex
		lines []string
	)
	args := []string{
		"--otel-endpoint", "grpc://canary-user:canary%40pass@127.0.0.1:1",
		"--diode-target", "grpc://canarytoken@127.0.0.1:8080",
	}
	err := StartProcess(StartSpec{
		Logger:         testProcessLogger(),
		NameDisplay:    "test-backend",
		NameUnderscore: "test_backend",
		Exec:           "test-exec",
		Args:           args,
		ListenAddr:     testListenAddr(t),
		LogLine: func(line string, _ bool) {
			logMu.Lock()
			defer logMu.Unlock()
			lines = append(lines, line)
		},
		SetProc:        func(Commander, <-chan CmdStatus) {},
		ReadinessCheck: func() (string, error) { return "1.2.3", nil },
	})
	require.NoError(t, err)
	assert.Equal(t, args, captured.args, "the process is given the URLs as written")

	require.Eventually(t, func() bool {
		logMu.Lock()
		defer logMu.Unlock()
		return len(lines) == 3
	}, time.Second, 5*time.Millisecond)

	logMu.Lock()
	defer logMu.Unlock()
	for _, line := range lines {
		if strings.Contains(line, "canary-user") {
			assert.Failf(t, "a relayed line writes the login", "%s", line)
		}
		if strings.Contains(line, "127.0.0.1:1") {
			assert.Contains(t, line, "********@127.0.0.1:1")
		}
	}
	assert.Contains(t, lines, "device contact noc-canarytoken@example.com, ssh ********@10.0.0.1")
}
