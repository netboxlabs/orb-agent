package policy

import (
	"fmt"
	"strings"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// maxIngestChunkBytes keeps each ingest request well under the 4 MB that
// Diode, and the OTLP receivers it is reached through, accept. The same
// threshold device-discovery uses. A variable so tests can lower it.
var maxIngestChunkBytes = 3 * 1024 * 1024

// ingestEntityOverheadBytes covers what each entity adds to a request beyond
// its own encoding: the timestamp the SDK sets, and the OTLP log record or
// the protobuf framing around it.
const ingestEntityOverheadBytes = 160

// ingestEntitySize is an entity's share of an ingest request. It is measured
// as JSON, which the OTLP client sends and which in practice is larger than
// the protobuf the gRPC client sends, so one budget holds over both transports.
func ingestEntitySize(entity diode.Entity) int {
	pe := entity.ConvertToProtoEntity()
	body, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(pe)
	if err != nil {
		return 2*proto.Size(pe) + ingestEntityOverheadBytes
	}
	return len(body) + ingestEntityOverheadBytes
}

// chunkEntities splits entities, in order, into groups whose size stays under
// maxBytes. An entity larger than maxBytes on its own goes out alone, and
// Diode decides whether to accept it.
func chunkEntities(entities []diode.Entity, maxBytes int) [][]diode.Entity {
	var chunks [][]diode.Entity
	var current []diode.Entity
	size := 0
	for _, entity := range entities {
		n := ingestEntitySize(entity)
		if len(current) > 0 && size+n > maxBytes {
			chunks = append(chunks, current)
			current, size = nil, 0
		}
		current = append(current, entity)
		size += n
	}
	return append(chunks, current)
}

// ingest sends a target's entities in requests under maxIngestChunkBytes.
// Diode queues a request even when it reports errors for some of its
// entities, so every request is sent and the errors of all of them are
// returned together. A request that fails outright stops the rest; its error
// says how many entities were already sent and keeps the errors that earlier
// requests reported, and the retried flush sends them all again.
func (r *Runner) ingest(host string, entities []diode.Entity, opts ...diode.IngestOption) (*diodepb.IngestResponse, error) {
	chunks := chunkEntities(entities, maxIngestChunkBytes)
	if len(chunks) > 1 {
		r.logger.Debug("sending the target in several requests to stay under Diode's message size limit",
			"policy", r.name, "host", host, "entity_count", len(entities), "requests", len(chunks))
	}
	var errs []string
	sent := 0
	for i, chunk := range chunks {
		resp, err := r.client.Ingest(r.ctx, chunk, opts...)
		if err != nil {
			if len(chunks) > 1 {
				err = fmt.Errorf("request %d of %d failed, %d of %d entities already sent: %w",
					i+1, len(chunks), sent, len(entities), err)
			}
			if len(errs) > 0 {
				err = fmt.Errorf("%w (earlier requests reported: %s)", err, strings.Join(errs, "; "))
			}
			return nil, err
		}
		if resp != nil {
			errs = append(errs, resp.Errors...)
		}
		sent += len(chunk)
	}
	return &diodepb.IngestResponse{Errors: errs}, nil
}
