package policy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/Ullaakut/nmap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

func scannedHost(name string) nmap.Host {
	return nmap.Host{
		Hostnames: []nmap.Hostname{{Name: name, Type: "PTR"}},
		Ports:     []nmap.Port{{ID: 22, Protocol: "tcp", Service: nmap.Service{Name: "ssh"}, State: nmap.State{State: "open"}}},
	}
}

func commentsOf(t *testing.T, comments *string) config.HostMetadata {
	t.Helper()
	require.NotNil(t, comments)
	var metadata config.HostMetadata
	require.NoError(t, json.Unmarshal([]byte(*comments), &metadata))
	return metadata
}

// When the comments are the backend's to write, a replaced name is kept in
// them as nmap gave it, next to the ports, and a clean name leaves the
// hostnames list empty as it always was.
func TestIPAddressEntityKeepsAReplacedNameInTheComments(t *testing.T) {
	r := &Runner{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ip, outcome := r.ipAddressEntity(scannedHost("abc1234-vendor*model*unit.example.net"), "192.0.2.10/24", "192.0.2.10", "p")
	assert.Equal(t, hostnameReplaced, outcome)
	assert.Equal(t, "abc1234-vendor-model-unit.example.net", *ip.DnsName)
	metadata := commentsOf(t, ip.Comments)
	require.Len(t, metadata.Hostnames, 1)
	assert.Equal(t, "abc1234-vendor*model*unit.example.net", metadata.Hostnames[0].Name)
	require.Len(t, metadata.Ports, 1)
	assert.Equal(t, 22, metadata.Ports[0].Number)

	ip, outcome = r.ipAddressEntity(scannedHost("clean.example.net"), "192.0.2.11/24", "192.0.2.11", "p")
	assert.Equal(t, hostnameUnchanged, outcome)
	assert.Nil(t, commentsOf(t, ip.Comments).Hostnames)
}

// When the policy sets its own comments they go out untouched, and the
// replaced name is not recorded anywhere in the entity.
func TestIPAddressEntityLeavesThePolicysCommentsAlone(t *testing.T) {
	r := &Runner{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), config: config.PolicyConfig{Defaults: config.Defaults{Comments: "owned by the policy"}}}
	ip, outcome := r.ipAddressEntity(scannedHost("abc*unit.example.net"), "192.0.2.12/24", "192.0.2.12", "p")
	assert.Equal(t, hostnameReplaced, outcome)
	assert.Equal(t, "abc-unit.example.net", *ip.DnsName)
	require.NotNil(t, ip.Comments)
	assert.Equal(t, "owned by the policy", *ip.Comments)
}

// With emit_scan_metadata off and no policy comments, the IP carries no
// comments, so whatever NetBox holds stays; the name is still replaced.
func TestIPAddressEntitySendsNoCommentsWithScanMetadataOff(t *testing.T) {
	off := false
	r := &Runner{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), config: config.PolicyConfig{Options: config.Options{EmitScanMetadata: &off}}}
	ip, outcome := r.ipAddressEntity(scannedHost("abc*unit.example.net"), "192.0.2.13/24", "192.0.2.13", "p")
	assert.Equal(t, hostnameReplaced, outcome)
	assert.Equal(t, "abc-unit.example.net", *ip.DnsName)
	assert.Nil(t, ip.Comments)
}

// The option only drops the scan metadata: comments the policy sets still go out.
func TestIPAddressEntityKeepsThePolicysCommentsWithScanMetadataOff(t *testing.T) {
	off := false
	r := &Runner{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), config: config.PolicyConfig{
		Defaults: config.Defaults{Comments: "owned by the policy"},
		Options:  config.Options{EmitScanMetadata: &off},
	}}
	ip, _ := r.ipAddressEntity(scannedHost("clean.example.net"), "192.0.2.14/24", "192.0.2.14", "p")
	require.NotNil(t, ip.Comments)
	assert.Equal(t, "owned by the policy", *ip.Comments)
}

// With the scan metadata off by choice, a replaced name is logged at debug,
// not warned about on every run; the run's summary still counts it.
func TestIPAddressEntityLogsAReplacedNameAtDebugWithScanMetadataOff(t *testing.T) {
	off := false
	var logs bytes.Buffer
	r := &Runner{
		logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		config: config.PolicyConfig{Options: config.Options{EmitScanMetadata: &off}},
	}
	r.ipAddressEntity(scannedHost("abc*unit.example.net"), "192.0.2.15/24", "192.0.2.15", "p")
	assert.NotContains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "emit_scan_metadata is off")
	assert.NotContains(t, logs.String(), "original kept in comments")
}

// When the policy's own comments leave no room, the replaced name is warned
// about, as before.
func TestIPAddressEntityWarnsWhenThePolicysCommentsLeaveNoRoom(t *testing.T) {
	var logs bytes.Buffer
	r := &Runner{
		logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		config: config.PolicyConfig{Defaults: config.Defaults{Comments: "owned by the policy"}},
	}
	r.ipAddressEntity(scannedHost("abc*unit.example.net"), "192.0.2.16/24", "192.0.2.16", "p")
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "the policy's comments leave no room for the original")
}

// The policy's comments decide even with the scan metadata off, so the
// warning still says why the name is not kept.
func TestIPAddressEntityWarnsAboutThePolicysCommentsWithScanMetadataOff(t *testing.T) {
	off := false
	var logs bytes.Buffer
	r := &Runner{
		logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		config: config.PolicyConfig{
			Defaults: config.Defaults{Comments: "owned by the policy"},
			Options:  config.Options{EmitScanMetadata: &off},
		},
	}
	r.ipAddressEntity(scannedHost("abc*unit.example.net"), "192.0.2.17/24", "192.0.2.17", "p")
	assert.Contains(t, logs.String(), "the policy's comments leave no room for the original")
}
