//go:build integration

package e2e_test

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/orb-test-lab-policy.yaml
var orbTestLabPolicyYAML []byte

const orbTestLabPolicyName = "orb-test-lab-snmp"

var defaultSNMPHosts = []string{
	"172.28.0.20", // cisco-c2960x-snmp
	"172.28.0.21", // cisco-ios-snmp
	"172.28.0.22", // juniper-junos-snmp
	"172.28.0.24", // cisco-csr1000v
	// 172.28.0.23 (juniper-ex-snmp) omitted — malformed SNMP responses in current lab image
}

func TestOrbTestLab_DryRunMultiTargetCrawl(t *testing.T) {
	hosts := snmpHostsFromEnv()
	requireLabReachable(t, hosts[0])

	bin := snmpDiscoveryBinary(t)
	dryRunDir := t.TempDir()
	port := freePort(t)

	proc := startSNMPDiscovery(t, bin, dryRunDir, port)
	waitHTTPReady(t, fmt.Sprintf("http://127.0.0.1:%d/api/v1/status", port))

	resp, err := http.Post(
		fmt.Sprintf("http://127.0.0.1:%d/api/v1/policies", port),
		"application/x-yaml",
		bytes.NewReader(orbTestLabPolicyYAML),
	)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, readBody(resp.Body))

	status := waitForPolicyCompleted(t, port, orbTestLabPolicyName, 4*time.Minute)
	runs := status.Runs
	require.NotEmpty(t, runs, "expected crawl runs for orb-test-lab policy")

	hostsWithEntities := 0
	totalEntities := 0
	for _, run := range runs {
		if run.Status != "completed" || run.EntityCount == 0 {
			continue
		}
		hostsWithEntities++
		totalEntities += run.EntityCount
	}
	require.Greater(t, hostsWithEntities, 0, "at least one lab target should produce entities")
	assert.Equal(t, len(defaultSNMPHosts), hostsWithEntities,
		"each policy target should produce entities (%d/%d)", hostsWithEntities, len(defaultSNMPHosts))

	files := dryRunFiles(t, dryRunDir)
	assert.GreaterOrEqual(t, len(files), hostsWithEntities,
		"dry-run should write one JSON file per successful ingest")

	devicesFound := 0
	for _, path := range files {
		entities, err := diode.LoadDryRunEntities(path)
		require.NoError(t, err, "load dry-run file %s", path)
		for _, ent := range entities {
			if ent.GetDevice() != nil {
				devicesFound++
			}
		}
	}
	assert.Greater(t, devicesFound, 0, "dry-run output should contain device entities")
	assert.Greater(t, totalEntities, 0, "policy runs should report ingested entity counts")

	// Exercise graceful shutdown while the process is still healthy.
	shutdownDeadline := time.Now().Add(30 * time.Second)
	require.NoError(t, proc.Process.Signal(syscall.SIGTERM))
	waitProcessExit(t, proc, shutdownDeadline)
}

type policyStatus struct {
	Name   string     `json:"name"`
	Status string     `json:"status"`
	Runs   []runStatus `json:"runs"`
}

type runStatus struct {
	Status      string `json:"status"`
	EntityCount int    `json:"entity_count"`
	Reason      string `json:"reason,omitempty"`
}

type statusResponse struct {
	Policies []policyStatus `json:"policies"`
}

func snmpHostsFromEnv() []string {
	raw := strings.TrimSpace(os.Getenv("ORB_TEST_LAB_SNMP_HOSTS"))
	if raw == "" {
		return append([]string(nil), defaultSNMPHosts...)
	}
	parts := strings.Split(raw, ",")
	hosts := make([]string, 0, len(parts))
	for _, part := range parts {
		if host := strings.TrimSpace(part); host != "" {
			hosts = append(hosts, host)
		}
	}
	if len(hosts) == 0 {
		return append([]string(nil), defaultSNMPHosts...)
	}
	return hosts
}

func requireLabReachable(t *testing.T, host string) {
	t.Helper()
	if !snmpHostReachable(host) {
		t.Skipf("orb-test-lab SNMP host %s is not reachable (start lab and run on orb-test-lab network)", host)
	}
}

func snmpHostReachable(host string) bool {
	client := gosnmp.GoSNMP{
		Target:    host,
		Port:      161,
		Community: "public",
		Version:   gosnmp.Version2c,
		Timeout:   3 * time.Second,
		Retries:   1,
	}
	if err := client.Connect(); err != nil {
		return false
	}
	defer client.Conn.Close()

	_, err := client.Get([]string{"1.3.6.1.2.1.1.1.0"})
	return err == nil
}

func snmpDiscoveryBinary(t *testing.T) string {
	t.Helper()
	if bin := strings.TrimSpace(os.Getenv("SNMP_DISCOVERY_BIN")); bin != "" {
		require.FileExists(t, bin)
		return bin
	}

	moduleRoot := moduleRoot(t)
	bin := filepath.Join(t.TempDir(), "snmp-discovery")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/main.go")
	cmd.Dir = moduleRoot
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build snmp-discovery:\n%s", out)
	return bin
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate snmp-discovery module root")
		}
		dir = parent
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func startSNMPDiscovery(t *testing.T, bin, dryRunDir string, port int) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(
		bin,
		"-dry-run",
		"-dry-run-output-dir", dryRunDir,
		"-ingest-buffer-size", "512",
		"-host", "127.0.0.1",
		"-port", strconv.Itoa(port),
		"-log-level", "WARN",
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	require.NoError(t, cmd.Start())

	t.Cleanup(func() {
		if cmd.ProcessState != nil {
			return
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		waitProcessExit(t, cmd, time.Now().Add(30*time.Second))
	})

	return cmd
}

func waitHTTPReady(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("server not ready at %s within 30s", url)
}

func waitForPolicyCompleted(t *testing.T, port int, policyName string, timeout time.Duration) policyStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last policyStatus

	for time.Now().Before(deadline) {
		status, ok := fetchPolicyStatus(t, port, policyName)
		if !ok {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		last = status
		if status.Status == "completed" {
			return status
		}
		if status.Status == "failed" {
			for _, run := range status.Runs {
				if run.Status == "failed" {
					t.Fatalf("policy %q failed: %s", policyName, run.Reason)
				}
			}
			t.Fatalf("policy %q reported failed status", policyName)
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("policy %q did not complete within %s (last status=%q runs=%d)", policyName, timeout, last.Status, len(last.Runs))
	return last
}

func fetchPolicyStatus(t *testing.T, port int, policyName string) (policyStatus, bool) {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/status", port))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body statusResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	for _, policy := range body.Policies {
		if policy.Name == policyName {
			return policy, true
		}
	}
	return policyStatus{}, false
}

func dryRunFiles(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	require.NoError(t, err)
	return matches
}

func waitProcessExit(t *testing.T, cmd *exec.Cmd, deadline time.Time) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			// SIGTERM is expected; only fail on unexpected wait errors.
			if _, ok := err.(*exec.ExitError); !ok {
				require.NoError(t, err)
			}
		}
	case <-time.After(time.Until(deadline)):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("snmp-discovery did not exit after SIGTERM")
	}
}

func readBody(r io.Reader) string {
	b, _ := io.ReadAll(r)
	return string(b)
}
