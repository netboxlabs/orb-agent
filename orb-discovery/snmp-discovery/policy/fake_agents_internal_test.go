package policy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
)

// fakeAgents stands in for the SNMP agents of every address a policy reaches.
// Each answers with its own system group and one interface, and each dial is
// counted as a probe or a crawl by the timeout the runner asks for.
type fakeAgents struct {
	probeTimeout time.Duration
	mu           sync.Mutex
	probes       map[string]int
	crawls       map[string]int
}

func newFakeAgents(probeTimeout time.Duration) *fakeAgents {
	return &fakeAgents{probeTimeout: probeTimeout, probes: map[string]int{}, crawls: map[string]int{}}
}

func (f *fakeAgents) dial(host string, port uint16, _ int, timeout time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
	key := fmt.Sprintf("%s:%d", host, port)
	f.mu.Lock()
	if timeout == f.probeTimeout {
		f.probes[key]++
	} else {
		f.crawls[key]++
	}
	f.mu.Unlock()
	return &rowWalker{rows: agentRows(host)}, nil
}

func (f *fakeAgents) probeCount(host string, port uint16) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.probes[fmt.Sprintf("%s:%d", host, port)]
}

func (f *fakeAgents) crawlCount(host string, port uint16) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.crawls[fmt.Sprintf("%s:%d", host, port)]
}

// agentName is the sysName of the agent at host: sw and its last octet.
func agentName(host string) string {
	return "sw" + host[strings.LastIndex(host, ".")+1:]
}

// agentRows is what the agent at host returns: its system group and one
// interface.
func agentRows(host string) map[string]snmp.PDU {
	name := agentName(host)
	return map[string]snmp.PDU{
		".1.3.6.1.2.1.1.1.0":     {Type: gosnmp.OctetString, Value: name + " test device"},
		".1.3.6.1.2.1.1.5.0":     {Type: gosnmp.OctetString, Value: name},
		".1.3.6.1.2.1.2.2.1.2.1": {Type: gosnmp.OctetString, Value: "eth0"},
		".1.3.6.1.2.1.2.2.1.3.1": {Type: gosnmp.Integer, Value: 6},
	}
}

// rowWalker answers a walk with the rows under the walked OID, as an agent
// does.
type rowWalker struct {
	rows map[string]snmp.PDU
}

func (w *rowWalker) Connect() error { return nil }
func (w *rowWalker) Close() error   { return nil }

func (w *rowWalker) Walk(_ context.Context, oid string, identifierSize int) (map[string]snmp.PDU, error) {
	root := "." + strings.TrimPrefix(oid, ".")
	out := map[string]snmp.PDU{}
	for name, pdu := range w.rows {
		if name == root || strings.HasPrefix(name, root+".") {
			pdu.Name = name
			pdu.IdentifierSize = identifierSize
			out[name] = pdu
		}
	}
	return out, nil
}

// recordingClient keeps every batch ingested, safely across crawl jobs.
type recordingClient struct {
	mu      sync.Mutex
	batches [][]diode.Entity
}

func (c *recordingClient) Close() error { return nil }

func (c *recordingClient) Ingest(_ context.Context, entities []diode.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batches = append(c.batches, entities)
	return &diodepb.IngestResponse{}, nil
}

func (c *recordingClient) IngestProto(context.Context, []*diodepb.Entity, ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	return &diodepb.IngestResponse{}, nil
}

// devicesOf returns the top-level device of each batch ingested for the agent
// at host, told apart by the description its sysDescr gives it, so a device
// whose name was suppressed is still found.
func (c *recordingClient) devicesOf(host string) []*diode.Device {
	c.mu.Lock()
	defer c.mu.Unlock()
	var devices []*diode.Device
	for _, batch := range c.batches {
		for _, entity := range batch {
			if d, ok := entity.(*diode.Device); ok {
				if desc := d.GetDescription(); desc != nil && *desc == agentName(host)+" test device" {
					devices = append(devices, d)
				}
				break
			}
		}
	}
	return devices
}

// lockedBuffer is a log destination shared by concurrent jobs.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// slogText logs every level as text to w.
func slogText(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// newPolicyRunner builds policy p1 from YAML the way the manager does,
// defaults and validation included, with the embedded mapping, SNMP faked by
// factory and Diode by client. The runner is stopped when the test ends.
func newPolicyRunner(t *testing.T, policyYAML string, factory snmp.ClientFactory, client diode.Client, logger *slog.Logger) (*Runner, *RunStore) {
	t.Helper()
	m, err := NewManager(context.Background(), logger, client, nil)
	require.NoError(t, err)
	policies, err := m.ParsePolicies([]byte(policyYAML))
	require.NoError(t, err)
	p, ok := policies["p1"]
	require.True(t, ok)
	store := NewRunStore()
	r, err := NewRunner(context.Background(), logger, "p1", p, client, factory, &m.mappingConfig, nil, nil, store)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Stop() })
	return r, store
}
