package policy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logsservicepb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// chunkRecordingClient records every Ingest call. failOn makes that call
// (1-based) return an error; the calls in errorsOn return a response with
// an error naming the call.
type chunkRecordingClient struct {
	calls    [][]diode.Entity
	failOn   int
	errorsOn map[int]bool
}

func (c *chunkRecordingClient) Close() error { return nil }

func (c *chunkRecordingClient) Ingest(_ context.Context, entities []diode.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	c.calls = append(c.calls, entities)
	n := len(c.calls)
	if n == c.failOn {
		return nil, errors.New("connection reset")
	}
	if c.errorsOn[n] {
		return &diodepb.IngestResponse{Errors: []string{fmt.Sprintf("rejected in request %d", n)}}, nil
	}
	return &diodepb.IngestResponse{}, nil
}

func (c *chunkRecordingClient) IngestProto(context.Context, []*diodepb.Entity, ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	return &diodepb.IngestResponse{}, nil
}

func describedInterfaces(n, descriptionBytes int) []diode.Entity {
	out := make([]diode.Entity, n)
	for i := range out {
		out[i] = &diode.Interface{
			Name:        diode.String(fmt.Sprintf("Ethernet%d", i)),
			Description: diode.String(strings.Repeat("x", descriptionBytes)),
		}
	}
	return out
}

func chunkSize(entities []diode.Entity) int {
	size := 0
	for _, e := range entities {
		size += ingestEntitySize(e)
	}
	return size
}

// trunkPayload is a switch with many VLANs and trunks tagging all of them,
// the shape that outgrows a single request.
func trunkPayload(vlanCount, trunkCount int) []diode.Entity {
	site := &diode.Site{Name: diode.String("lab")}
	device := &diode.Device{Name: diode.String("core-1"), Site: site}
	group := &diode.VLANGroup{Name: diode.String("lab-vlans")}
	vlans := make([]*diode.VLAN, vlanCount)
	entities := make([]diode.Entity, 0, vlanCount+trunkCount)
	for i := range vlans {
		vlans[i] = &diode.VLAN{Vid: diode.Int64(int64(i + 2)), Name: diode.String(fmt.Sprintf("VLAN %04d", i+2)), Group: group}
		entities = append(entities, vlans[i])
	}
	for i := range trunkCount {
		entities = append(entities, &diode.Interface{
			Name: diode.String(fmt.Sprintf("Ethernet%d", i+1)), Device: device,
			Mode: diode.String("tagged"), TaggedVlans: vlans,
		})
	}
	return entities
}

func withChunkLimit(t *testing.T, limit int) {
	t.Helper()
	previous := maxIngestChunkBytes
	maxIngestChunkBytes = limit
	t.Cleanup(func() { maxIngestChunkBytes = previous })
}

func TestChunkEntitiesKeepsOrderAndStaysUnderTheLimit(t *testing.T) {
	entities := describedInterfaces(40, 1000)
	chunks := chunkEntities(entities, 10_000)

	require.Greater(t, len(chunks), 1)
	var flattened []diode.Entity
	for _, chunk := range chunks {
		assert.LessOrEqual(t, chunkSize(chunk), 10_000)
		flattened = append(flattened, chunk...)
	}
	assert.Equal(t, entities, flattened)
}

func TestChunkEntitiesFillsEachChunk(t *testing.T) {
	chunks := chunkEntities(describedInterfaces(40, 1000), 10_000)

	// Every chunk but the last is full: one more entity would not fit.
	for i := range len(chunks) - 1 {
		assert.Greater(t, chunkSize(append(chunks[i][:len(chunks[i]):len(chunks[i])], chunks[i+1][0])), 10_000)
	}
}

func TestChunkEntitiesSendsAnOversizedEntityAlone(t *testing.T) {
	entities := append(describedInterfaces(1, 100), describedInterfaces(1, 20_000)...)
	entities = append(entities, describedInterfaces(1, 100)...)

	chunks := chunkEntities(entities, 10_000)

	require.Len(t, chunks, 3)
	assert.Equal(t, []diode.Entity{entities[1]}, chunks[1])
}

func TestChunkEntitiesStartsWithAnOversizedEntity(t *testing.T) {
	entities := append(describedInterfaces(1, 20_000), describedInterfaces(1, 100)...)

	chunks := chunkEntities(entities, 10_000)

	assert.Equal(t, [][]diode.Entity{{entities[0]}, {entities[1]}}, chunks)
}

func TestChunkEntitiesSmallPayloadIsOneChunk(t *testing.T) {
	entities := describedInterfaces(3, 100)
	assert.Equal(t, [][]diode.Entity{entities}, chunkEntities(entities, maxIngestChunkBytes))
}

// A gRPC request built as the SDK builds it, with a timestamp on every
// entity, is no bigger than the estimate of its entities plus the envelope.
func TestIngestEntitySizeCoversTheGRPCRequest(t *testing.T) {
	for name, entities := range map[string][]diode.Entity{
		"small":   describedInterfaces(50, 10),
		"unicode": {&diode.Interface{Name: diode.String("Ethernet1"), Description: diode.String(strings.Repeat("Zürich 東京 ", 200))}},
		"trunks":  trunkPayload(300, 3),
	} {
		t.Run(name, func(t *testing.T) {
			request := &diodepb.IngestRequest{Id: "00000000-0000-0000-0000-000000000000", Stream: "latest", ProducerAppName: "agent01/gnmi-discovery", ProducerAppVersion: "0.0.0", SdkName: "diode-sdk-go", SdkVersion: "0.0.0"}
			for _, e := range entities {
				pe := e.ConvertToProtoEntity()
				pe.Timestamp = timestamppb.New(time.Now().UTC())
				request.Entities = append(request.Entities, pe)
			}
			assert.LessOrEqual(t, proto.Size(request), chunkSize(entities)+512)
		})
	}
}

func chunkRunner(client diode.Client) *Runner {
	return &Runner{ctx: context.Background(), logger: slog.New(slog.NewTextHandler(io.Discard, nil)), client: client}
}

func TestIngestSendsEveryChunk(t *testing.T) {
	withChunkLimit(t, 10_000)
	client := &chunkRecordingClient{}
	entities := describedInterfaces(40, 1000)

	resp, err := chunkRunner(client).ingest("192.0.2.10", entities)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Errors)
	assert.Equal(t, chunkEntities(entities, 10_000), client.calls)
}

func TestIngestStopsAtTheFirstFailedRequest(t *testing.T) {
	withChunkLimit(t, 10_000)
	client := &chunkRecordingClient{failOn: 2}
	entities := describedInterfaces(40, 1000)

	_, err := chunkRunner(client).ingest("192.0.2.10", entities)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "request 2 of")
	assert.Contains(t, err.Error(), "connection reset")
	assert.Len(t, client.calls, 2)
	// The requests before it went through, and the error says how much.
	assert.Contains(t, err.Error(), fmt.Sprintf("%d of %d entities already sent", len(client.calls[0]), len(entities)))
}

// Diode queues a request even when it reports errors for some entities, so
// the rest are still sent and every request's errors come back.
func TestIngestSendsEveryChunkAndCollectsTheirErrors(t *testing.T) {
	withChunkLimit(t, 10_000)
	client := &chunkRecordingClient{errorsOn: map[int]bool{1: true, 3: true}}
	entities := describedInterfaces(40, 1000)

	resp, err := chunkRunner(client).ingest("192.0.2.10", entities)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, []string{"rejected in request 1", "rejected in request 3"}, resp.Errors)
	assert.Len(t, client.calls, len(chunkEntities(entities, 10_000)))
}

// A request that fails outright keeps the errors earlier requests reported,
// since Diode already queued those requests.
func TestIngestFailureKeepsTheErrorsOfEarlierRequests(t *testing.T) {
	withChunkLimit(t, 10_000)
	client := &chunkRecordingClient{errorsOn: map[int]bool{1: true}, failOn: 3}

	_, err := chunkRunner(client).ingest("192.0.2.10", describedInterfaces(40, 1000))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "request 3 of")
	assert.Contains(t, err.Error(), "connection reset")
	assert.Contains(t, err.Error(), "rejected in request 1")
}

// otlpReceiver is an OTLP logs receiver with gRPC's default 4 MB limit, as
// the agent's own bridge and an OTel Collector left on its defaults have.
type otlpReceiver struct {
	logsservicepb.UnimplementedLogsServiceServer
	mu          sync.Mutex
	records     int
	exports     int
	recordSizes []int
}

func (o *otlpReceiver) Export(_ context.Context, in *logsservicepb.ExportLogsServiceRequest) (*logsservicepb.ExportLogsServiceResponse, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.exports++
	for _, rl := range in.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			for _, lr := range sl.GetLogRecords() {
				o.records++
				// The record's share of the request, with its field tag and length.
				o.recordSizes = append(o.recordSizes, 1+protowire.SizeBytes(proto.Size(lr)))
			}
		}
	}
	return &logsservicepb.ExportLogsServiceResponse{}, nil
}

func startOTLPReceiver(t *testing.T) (*otlpReceiver, diode.Client) {
	t.Helper()
	receiver := &otlpReceiver{}
	server := grpc.NewServer()
	logsservicepb.RegisterLogsServiceServer(server, receiver)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	client, err := diode.NewOTLPClient("grpc://"+listener.Addr().String(), "agent01/gnmi-discovery", "0.0.0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return receiver, client
}

// The estimate covers each log record the OTLP client builds, which for a
// small entity is mostly the record around it rather than its JSON.
func TestIngestEntitySizeCoversTheOTLPLogRecord(t *testing.T) {
	receiver, client := startOTLPReceiver(t)
	entities := append(describedInterfaces(3, 0), &diode.IPAddress{Address: diode.String("192.0.2.1/24")}, &diode.VLAN{Vid: diode.Int64(10)})

	_, err := chunkRunner(client).ingest("192.0.2.10", entities)

	require.NoError(t, err)
	require.Len(t, receiver.recordSizes, len(entities))
	for i, e := range entities {
		assert.LessOrEqual(t, receiver.recordSizes[i], ingestEntitySize(e), "entity %d", i)
	}
}

// Over OTLP the SDK sends each entity as JSON, larger than its protobuf, and
// every request still fits under the receiver's limit.
func TestIngestStaysUnderTheOTLPReceiverLimit(t *testing.T) {
	receiver, client := startOTLPReceiver(t)
	entities := trunkPayload(2000, 40)

	resp, err := chunkRunner(client).ingest("192.0.2.10", entities, diode.WithIngestMetadata(diode.Metadata{"policy_name": "p"}))

	require.NoError(t, err)
	assert.Empty(t, resp.Errors)
	assert.Greater(t, receiver.exports, 1)
	assert.Equal(t, len(entities), receiver.records)
}

// startLargeFlush runs an on_change policy whose first flush is over the
// chunk limit, ingesting into client.
func startLargeFlush(t *testing.T, client diode.Client) *Runner {
	t.Helper()
	withChunkLimit(t, 1_000)
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	updates := []gnmi.Update{{Path: "/system/state/hostname", Value: "r1"}}
	for i := 1; i <= 20; i++ {
		updates = append(updates,
			gnmi.Update{Path: fmt.Sprintf("/interfaces/interface[name=Ethernet%d]/state/admin-status", i), Value: "UP"},
			gnmi.Update{Path: fmt.Sprintf("/interfaces/interface[name=Ethernet%d]/state/description", i), Value: strings.Repeat("d", 60)},
		)
	}
	fake := &gnmi.FakeSession{
		Caps: &gnmi.CapabilitiesResult{Vendor: "Arista"}, OnChangeSupport: true,
		OnChangeStream: []gnmi.Notification{{Updates: updates}, {SyncDone: true}},
	}
	pol := config.Policy{
		Config: config.PolicyConfig{Mode: config.ModeOnChange, DebounceMs: 20, Defaults: config.Defaults{Site: "lab", Role: "router"}},
		Scope:  config.Scope{Targets: []config.Target{{Host: "h:1"}}},
	}
	r, err := NewRunner(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), "chunks", pol, client, &gnmi.FakeDialer{Session: fake}, store)
	require.NoError(t, err)
	r.Start()
	t.Cleanup(func() { require.NoError(t, r.Stop()) })
	return r
}

// A flush whose payload is over the limit goes out in several requests and
// the run completes with every entity counted.
func TestRunnerFlushesALargeTargetInChunks(t *testing.T) {
	client := &recordingClient{}
	r := startLargeFlush(t, client)

	require.Eventually(t, func() bool {
		runs := r.Runs()
		return len(runs) >= 1 && runs[0].Status == RunStatusCompleted
	}, 5*time.Second, 20*time.Millisecond)
	require.Greater(t, client.count(), 1)
	sent := 0
	client.mu.Lock()
	for _, call := range client.ingested {
		sent += len(call)
	}
	client.mu.Unlock()
	assert.Equal(t, sent, r.Runs()[0].EntityCount)
}

// A flush fails when its requests report errors, after sending every one.
func TestRunnerFailsAFlushWhoseRequestsReportErrors(t *testing.T) {
	client := &recordingClient{respErrors: []string{"rejected"}}
	r := startLargeFlush(t, client)

	require.Eventually(t, func() bool {
		runs := r.Runs()
		return len(runs) >= 1 && runs[0].Status == RunStatusFailed
	}, 5*time.Second, 20*time.Millisecond)
	sent := 0
	client.mu.Lock()
	calls := len(client.ingested)
	for _, call := range client.ingested {
		sent += len(call)
	}
	client.mu.Unlock()
	require.Greater(t, calls, 1)
	assert.Equal(t, sent, r.Runs()[0].EntityCount)
	assert.Contains(t, r.Runs()[0].Reason, "rejected")
}
