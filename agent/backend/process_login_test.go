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

// A password written with a raw %, as canary%F3pass, decodes to a byte that
// is not UTF-8. grpc-go writes that byte in its error, which the agent turns
// into U+FFFD before it relays the line, and Python's gRPC writes it as
// Latin-1: the agent masks the login in both, and in a line writing it
// decoded leniently, an invalid %XX kept.
func TestStartProcess_MasksALoginWhoseDecodedBytesAreNotUTF8InWhatItRelays(t *testing.T) {
	stubProcessTimers(t)
	fake := newFakeCommander(4245)
	stubNewCmdOptions(t, fake)

	fake.stderrCh <- "rpc error: code = Unavailable desc = invalid target address canary-user:canary\xf3pass@127.0.0.1:14317," +
		" error info: address canary-user:canary\xf3pass@127.0.0.1:14317:443: too many colons in address"
	fake.stderrCh <- "WARNING: opentelemetry.exporter.otlp.proto.grpc.exporter: Transient error StatusCode.UNAVAILABLE" +
		" encountered while exporting metrics to canary-user:canary%F3pass@127.0.0.1:14317, retrying in 0.98s." +
		" Error details: errors resolving canary-user:canaryópass@127.0.0.1:14317: [field:hostname lookup error:" +
		"address lookup failed for canary-user:canaryópass@127.0.0.1:14317: Misformatted domain name]"
	fake.stderrCh <- "errors resolving canary-user:canary%zz@pass@127.0.0.1:1"

	var (
		logMu sync.Mutex
		lines []string
	)
	err := StartProcess(StartSpec{
		Logger:         testProcessLogger(),
		NameDisplay:    "test-backend",
		NameUnderscore: "test_backend",
		Exec:           "test-exec",
		Args: []string{
			"--otel-endpoint", "canary-user:canary%F3pass@127.0.0.1:14317",
			"--diode-target", "grpc://canary-user:canary%zz%40pass@127.0.0.1:1",
		},
		ListenAddr: testListenAddr(t),
		LogLine: func(line string, _ bool) {
			logMu.Lock()
			defer logMu.Unlock()
			lines = append(lines, line)
		},
		SetProc:        func(Commander, <-chan CmdStatus) {},
		ReadinessCheck: func() (string, error) { return "1.2.3", nil },
	})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		logMu.Lock()
		defer logMu.Unlock()
		return len(lines) == 3
	}, time.Second, 5*time.Millisecond)

	logMu.Lock()
	defer logMu.Unlock()
	for _, line := range lines {
		assert.NotContains(t, line, "canary", "a relayed line writes the login")
		assert.Contains(t, line, "********@127.0.0.1:")
	}
}

// A Diode target whose password holds an unescaped / stops the worker: the
// Diode SDK makes its token URL from the authority Python's urlparse reads,
// which ends at the /, and urllib3 refuses it quoting the user and the start
// of the password. The line below is the one the worker printed for such a
// target, as the SDK raised it; the agent masks the login in what it relays.
func TestStartProcess_MasksADiodeLoginWhosePasswordHoldsASlashInWhatItRelays(t *testing.T) {
	stubProcessTimers(t)
	fake := newFakeCommander(4246)
	stubNewCmdOptions(t, fake)

	fake.stderrCh <- "ERROR: Unable to connect to Diode Server: Failed to obtain access token: Failed to parse:" +
		" 'canary-user:canary' is not a valid host or port"

	var (
		logMu sync.Mutex
		lines []string
	)
	err := StartProcess(StartSpec{
		Logger:         testProcessLogger(),
		NameDisplay:    "test-backend",
		NameUnderscore: "test_backend",
		Exec:           "test-exec",
		Args:           []string{"--diode-target", "grpc://canary-user:canary/pass@127.0.0.1:8080/diode"},
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

	require.Eventually(t, func() bool {
		logMu.Lock()
		defer logMu.Unlock()
		return len(lines) == 1
	}, time.Second, 5*time.Millisecond)

	logMu.Lock()
	defer logMu.Unlock()
	assert.Equal(t, "ERROR: Unable to connect to Diode Server: Failed to obtain access token: Failed to parse:"+
		" '********' is not a valid host or port", lines[0])
}
