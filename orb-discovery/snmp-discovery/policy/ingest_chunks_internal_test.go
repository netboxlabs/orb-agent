package policy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
)

// chunkRecordingClient records every Ingest call. failOn makes that call
// (1-based) return an error; errorsOn makes it return a response with errors.
type chunkRecordingClient struct {
	calls    [][]diode.Entity
	failOn   int
	errorsOn int
}

func (c *chunkRecordingClient) Close() error { return nil }

func (c *chunkRecordingClient) Ingest(_ context.Context, entities []diode.Entity, _ ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	c.calls = append(c.calls, entities)
	switch len(c.calls) {
	case c.failOn:
		return nil, errors.New("connection reset")
	case c.errorsOn:
		return &diodepb.IngestResponse{Errors: []string{"rejected"}}, nil
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
			Name:        diode.String(fmt.Sprintf("Gi0/%d", i)),
			Description: diode.String(strings.Repeat("x", descriptionBytes)),
		}
	}
	return out
}

func chunkSize(entities []diode.Entity) int {
	size := 0
	for _, e := range entities {
		size += proto.Size(e.ConvertToProtoEntity()) + ingestEntityOverheadBytes
	}
	return size
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
	entities := describedInterfaces(40, 1000)
	chunks := chunkEntities(entities, 10_000)

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

// Each entity counts its share of the request beyond its own encoding, so
// small entities do not overfill a chunk.
func TestChunkEntitiesCountsEachEntitysRequestOverhead(t *testing.T) {
	entities := make([]diode.Entity, 30)
	for i := range entities {
		entities[i] = &diode.Interface{Name: diode.String(fmt.Sprintf("Gi0/%02d", i))}
	}
	perEntity := proto.Size(entities[0].ConvertToProtoEntity()) + ingestEntityOverheadBytes

	chunks := chunkEntities(entities, 10*perEntity)

	assert.Len(t, chunks[0], 10)
}

func TestChunkEntitiesSmallPayloadIsOneChunk(t *testing.T) {
	entities := describedInterfaces(3, 100)
	assert.Equal(t, [][]diode.Entity{entities}, chunkEntities(entities, maxIngestChunkBytes))
}

func chunkRunner(client diode.Client) *Runner {
	return &Runner{
		ctx:    context.Background(),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		client: client,
	}
}

func withChunkLimit(t *testing.T, limit int) {
	t.Helper()
	previous := maxIngestChunkBytes
	maxIngestChunkBytes = limit
	t.Cleanup(func() { maxIngestChunkBytes = previous })
}

func TestIngestSendsEveryChunk(t *testing.T) {
	withChunkLimit(t, 10_000)
	client := &chunkRecordingClient{}
	entities := describedInterfaces(40, 1000)

	resp, err := chunkRunner(client).ingest(entities)

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Errors)
	assert.Equal(t, chunkEntities(entities, 10_000), client.calls)
}

func TestIngestStopsAtTheFirstFailedChunk(t *testing.T) {
	withChunkLimit(t, 10_000)
	client := &chunkRecordingClient{failOn: 2}

	_, err := chunkRunner(client).ingest(describedInterfaces(40, 1000))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "chunk 2 of")
	assert.Contains(t, err.Error(), "connection reset")
	assert.Len(t, client.calls, 2)
}

func TestIngestStopsAtTheFirstChunkWithErrors(t *testing.T) {
	withChunkLimit(t, 10_000)
	client := &chunkRecordingClient{errorsOn: 1}

	resp, err := chunkRunner(client).ingest(describedInterfaces(40, 1000))

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, []string{"rejected"}, resp.Errors)
	assert.Len(t, client.calls, 1)
}

// A run whose payload is over the limit goes out in several requests and
// still completes with every entity counted.
func TestRunIngestsALargeTargetInChunks(t *testing.T) {
	withChunkLimit(t, 2_000)
	pdus := map[string]snmp.PDU{}
	for i := 1; i <= 30; i++ {
		pdus[fmt.Sprintf("1.3.6.1.2.1.2.2.1.2.%d", i)] = snmp.PDU{Value: fmt.Sprintf("Gi0/%d", i), Type: gosnmp.OctetString, IdentifierSize: 1}
	}
	walker := &staticWalker{pdus: map[string]map[string]snmp.PDU{"1.3.6.1.2.1.2.2.1.2": pdus}}
	factory := func(_ string, _ uint16, _ int, _ time.Duration, _ *config.Authentication, _ *slog.Logger) (snmp.Walker, error) {
		return walker, nil
	}
	entries := []config.MappingEntry{{
		OID: "1.3.6.1.2.1.2.2.1", Entity: "interface", Field: "_id", IdentifierSize: 1,
		MappingEntries: []config.MappingEntry{{OID: "1.3.6.1.2.1.2.2.1.2", Entity: "interface", Field: "name"}},
	}}
	client := &chunkRecordingClient{}
	runner := queryTargetRunner(factory, entries)
	runner.client = client
	runner.runStore = NewRunStore()
	runner.timeout = 5 * time.Second

	runner.runWithMetadata(config.Target{Host: "192.0.2.10", Port: 161}, "")

	require.Greater(t, len(client.calls), 1)
	sent := 0
	for _, call := range client.calls {
		sent += len(call)
	}
	runs := runner.runStore.GetRunsForTarget("test-policy", "192.0.2.10", 161)
	require.Len(t, runs, 1)
	assert.Equal(t, RunStatusCompleted, runs[0].Status)
	assert.Equal(t, sent, runs[0].EntityCount)
}
