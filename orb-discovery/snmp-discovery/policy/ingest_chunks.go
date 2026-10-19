package policy

import (
	"fmt"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"google.golang.org/protobuf/proto"
)

// maxIngestChunkBytes keeps each ingest request well under the 4 MB Diode
// accepts, the same threshold device-discovery uses. A variable so tests can
// lower it.
var maxIngestChunkBytes = 3 * 1024 * 1024

// ingestEntityOverheadBytes covers what each entity adds to a request beyond
// its own encoding: the timestamp the SDK sets and the repeated-field framing.
const ingestEntityOverheadBytes = 32

// chunkEntities splits entities, in order, into groups whose encoded size
// stays under maxBytes. An entity larger than maxBytes on its own goes out
// alone, and Diode decides whether to accept it.
func chunkEntities(entities []diode.Entity, maxBytes int) [][]diode.Entity {
	var chunks [][]diode.Entity
	var current []diode.Entity
	size := 0
	for _, entity := range entities {
		n := proto.Size(entity.ConvertToProtoEntity()) + ingestEntityOverheadBytes
		if len(current) > 0 && size+n > maxBytes {
			chunks = append(chunks, current)
			current, size = nil, 0
		}
		current = append(current, entity)
		size += n
	}
	return append(chunks, current)
}

// ingest sends entities in requests under maxIngestChunkBytes. It stops at
// the first request that fails, or whose response reports errors, and
// returns that result; requests before it have already been accepted.
func (r *Runner) ingest(entities []diode.Entity, opts ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	chunks := chunkEntities(entities, maxIngestChunkBytes)
	if len(chunks) > 1 {
		r.logger.Info("splitting the ingest into several requests to stay under Diode's message size limit",
			"entity_count", len(entities), "requests", len(chunks))
	}
	var resp *diodepb.IngestResponse
	for i, chunk := range chunks {
		var err error
		resp, err = r.client.Ingest(r.ctx, chunk, opts...)
		if err != nil {
			if len(chunks) > 1 {
				return nil, fmt.Errorf("chunk %d of %d: %w", i+1, len(chunks), err)
			}
			return nil, err
		}
		if resp != nil && len(resp.Errors) > 0 {
			return resp, nil
		}
	}
	return resp, nil
}
