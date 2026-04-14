package otlpbridge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ---------------------------------------------------------------------------
// recordingPublisher — thread-safe publisher that records every message
// ---------------------------------------------------------------------------

type publishedMsg struct {
	topic   string
	payload []byte
}

type recordingPublisher struct {
	mu       sync.Mutex
	messages []publishedMsg
}

func (r *recordingPublisher) Publish(_ context.Context, topic string, payload []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages = append(r.messages, publishedMsg{topic: topic, payload: append([]byte(nil), payload...)})
	return nil
}

func (r *recordingPublisher) snapshot() []publishedMsg {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]publishedMsg, len(r.messages))
	copy(out, r.messages)
	return out
}

// parseSeq extracts the integer suffix from payloads like "rot-0042" or "pre-0007".
func parseSeq(payload []byte) (int, error) {
	s := string(payload)
	idx := strings.LastIndex(s, "-")
	if idx < 0 {
		return 0, fmt.Errorf("no dash in %q", s)
	}
	return strconv.Atoi(s[idx+1:])
}

// collectAll merges snapshots from multiple publishers into one slice.
func collectAll(pubs ...*recordingPublisher) []publishedMsg {
	var all []publishedMsg
	for _, p := range pubs {
		all = append(all, p.snapshot()...)
	}
	return all
}

// ---------------------------------------------------------------------------
// Test 1: Enqueue-level zero-data-loss through rotation cycles
// ---------------------------------------------------------------------------

func TestBridge_ZeroDataLoss_CredentialRotation(t *testing.T) {
	t.Parallel()

	const (
		preReadyCount   = 50
		steadyCount     = 200
		rotationCount   = 1000
		rotationsTotal  = 3
		msgsPerRotation = rotationCount / rotationsTotal // ~333
		rotationPoint   = msgsPerRotation / 3            // simulate rotation after ~1/3 of each batch
		ingestTopic     = "ingest/test"
		telTopic        = "telemetry/test"
	)

	ctx := context.Background()
	bridge, err := NewBridgeServer(BridgeConfig{Encoding: "protobuf"}, nil, slog.Default())
	require.NoError(t, err)
	bridge.initialBackoff = 5 * time.Millisecond
	require.NoError(t, bridge.Start(ctx))
	defer func() { _ = bridge.Stop(context.Background()) }()

	// ---- Phase 1: pre-ready queuing (startup) ----
	pub1 := &recordingPublisher{}

	for i := 0; i < preReadyCount; i++ {
		require.NoError(t, bridge.Enqueue(ctx, false, []byte(fmt.Sprintf("pre-%04d", i))))
	}
	assert.Empty(t, pub1.snapshot(), "nothing should be published before ready")

	bridge.SetPublisher(pub1)
	bridge.SetIngestTopic(ingestTopic)
	bridge.SetTelemetryTopic(telTopic)

	// Wait for the writer goroutine to drain all pre-ready messages.
	require.Eventually(t, func() bool {
		return len(pub1.snapshot()) >= preReadyCount
	}, 5*time.Second, time.Millisecond, "all pre-ready messages should drain")

	msgs := pub1.snapshot()[:preReadyCount]
	for i, m := range msgs {
		assert.Equal(t, fmt.Sprintf("pre-%04d", i), string(m.payload), "pre-ready ordering")
		assert.Equal(t, telTopic, m.topic)
	}

	// ---- Phase 2: steady-state publishing ----
	for i := 0; i < steadyCount; i++ {
		isIngest := i%3 == 0
		require.NoError(t, bridge.Enqueue(ctx, isIngest, []byte(fmt.Sprintf("steady-%04d", i))))
	}

	require.Eventually(t, func() bool {
		return len(pub1.snapshot()) >= preReadyCount+steadyCount
	}, 5*time.Second, time.Millisecond, "all steady-state messages should publish")

	steadyMsgs := pub1.snapshot()[preReadyCount : preReadyCount+steadyCount]
	for i, m := range steadyMsgs {
		expectedTopic := telTopic
		if i%3 == 0 {
			expectedTopic = ingestTopic
		}
		assert.Equal(t, expectedTopic, m.topic, "topic routing for steady-%04d", i)
	}

	// ---- Phase 3: rotation under concurrent load ----
	// We accumulate publishers across rotations to verify total count at the end.
	var allPubs []*recordingPublisher
	allPubs = append(allPubs, pub1) // pub1 will also receive some rotation messages

	globalSeq := 0 // tracks sequence across all rotation cycles
	for rot := 0; rot < rotationsTotal; rot++ {
		triggerRotation := make(chan struct{})
		rotationDone := make(chan struct{})
		batchSize := msgsPerRotation
		if rot == rotationsTotal-1 {
			// Last batch gets any remainder
			batchSize = rotationCount - (msgsPerRotation * (rotationsTotal - 1))
		}

		startSeq := globalSeq
		enqueueErrs := make(chan error, batchSize)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < batchSize; i++ {
				seq := startSeq + i
				if err := bridge.Enqueue(ctx, false, []byte(fmt.Sprintf("rot-%04d", seq))); err != nil {
					enqueueErrs <- fmt.Errorf("rot-%04d: %w", seq, err)
				}
				if i == rotationPoint {
					close(triggerRotation)
					<-rotationDone
				}
			}
			close(enqueueErrs)
		}()

		// Wait for sender to reach rotation point
		<-triggerRotation

		// Simulate rotation: clear publisher so the bridge buffers
		bridge.ClearPublisher()

		// Let some messages queue while publisher is nil
		// Then restore with a new publisher
		newPub := &recordingPublisher{}
		allPubs = append(allPubs, newPub)
		bridge.SetPublisher(newPub)
		bridge.SetIngestTopic(ingestTopic)
		bridge.SetTelemetryTopic(telTopic)
		close(rotationDone)

		wg.Wait()
		for err := range enqueueErrs {
			t.Errorf("enqueue failed during rotation %d: %v", rot, err)
		}
		globalSeq += batchSize
	}

	// Wait for the writer goroutine to publish all rotation messages.
	require.Eventually(t, func() bool {
		allMsgs := collectAll(allPubs...)
		var count int
		for _, m := range allMsgs {
			if strings.HasPrefix(string(m.payload), "rot-") {
				count++
			}
		}
		return count == rotationCount
	}, 10*time.Second, 10*time.Millisecond,
		"expected all %d rotation messages to be published", rotationCount)

	// ---- Verification ----
	allMsgs := collectAll(allPubs...)
	// Filter to only rotation messages (skip pre- and steady- prefixed)
	var rotMsgs []publishedMsg
	for _, m := range allMsgs {
		if strings.HasPrefix(string(m.payload), "rot-") {
			rotMsgs = append(rotMsgs, m)
		}
	}

	require.Equal(t, rotationCount, len(rotMsgs),
		"expected exactly %d rotation messages, got %d (zero data loss)", rotationCount, len(rotMsgs))

	// Check no duplicates, no gaps
	seen := make(map[int]bool)
	for _, m := range rotMsgs {
		seq, err := parseSeq(m.payload)
		require.NoError(t, err)
		assert.False(t, seen[seq], "duplicate sequence number: %d", seq)
		seen[seq] = true
	}
	for i := 0; i < rotationCount; i++ {
		assert.True(t, seen[i], "missing sequence number: %d", i)
	}

	// Check ordering within each publisher: sequences should be monotonically increasing
	for idx, pub := range allPubs {
		msgs := pub.snapshot()
		var seqs []int
		for _, m := range msgs {
			if !strings.HasPrefix(string(m.payload), "rot-") {
				continue
			}
			seq, err := parseSeq(m.payload)
			require.NoError(t, err)
			seqs = append(seqs, seq)
		}
		assert.True(t, sort.IntsAreSorted(seqs),
			"publisher %d: rotation messages not in order: %v", idx, seqs)
	}
}

// ---------------------------------------------------------------------------
// Test 2: Full gRPC path — handler → marshal → Enqueue → publish
// ---------------------------------------------------------------------------

func TestBridge_ZeroDataLoss_GRPCPath(t *testing.T) {
	t.Parallel()

	const (
		preReadyCount = 20
		steadyCount   = 40
		rotationCount = 40
		ingestTopic   = "ingest/grpc-test"
		telTopic      = "telemetry/grpc-test"
	)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	bridge, err := NewBridgeServer(BridgeConfig{ListenAddr: ":0", Encoding: "json"}, nil, logger)
	require.NoError(t, err)
	bridge.initialBackoff = 5 * time.Millisecond
	require.NoError(t, bridge.Start(context.Background()))
	defer func() { _ = bridge.Stop(context.Background()) }()

	// Connect a gRPC metrics client to the bridge.
	// Extract the port and dial localhost explicitly — listener.Addr() on ":0"
	// may return a wildcard like "[::]:<port>" which isn't reliably dialable.
	_, port, err := net.SplitHostPort(bridge.listener.Addr().String())
	require.NoError(t, err)
	conn, err := grpc.NewClient("localhost:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	client := collectormetrics.NewMetricsServiceClient(conn)

	// Helper: send one empty ExportMetricsServiceRequest
	sendOne := func() {
		_, err := client.Export(context.Background(), &collectormetrics.ExportMetricsServiceRequest{})
		require.NoError(t, err)
	}

	// ---- Phase 1: pre-ready — bridge queues ----
	for i := 0; i < preReadyCount; i++ {
		sendOne()
	}

	pub1 := &recordingPublisher{}
	bridge.SetPublisher(pub1)
	bridge.SetIngestTopic(ingestTopic)
	bridge.SetTelemetryTopic(telTopic)

	require.Eventually(t, func() bool {
		return len(pub1.snapshot()) >= preReadyCount
	}, 5*time.Second, time.Millisecond,
		"all pre-ready gRPC requests should drain")

	// ---- Phase 2: steady-state ----
	for i := 0; i < steadyCount; i++ {
		sendOne()
	}
	require.Eventually(t, func() bool {
		return len(pub1.snapshot()) >= preReadyCount+steadyCount
	}, 5*time.Second, time.Millisecond)

	// ---- Phase 3: rotation ----
	bridge.ClearPublisher()

	for i := 0; i < rotationCount; i++ {
		sendOne()
	}

	pub2 := &recordingPublisher{}
	bridge.SetPublisher(pub2)
	bridge.SetIngestTopic(ingestTopic)
	bridge.SetTelemetryTopic(telTopic)

	// ---- Verification ----
	require.Eventually(t, func() bool {
		return len(pub1.snapshot())+len(pub2.snapshot()) >= preReadyCount+steadyCount+rotationCount
	}, 5*time.Second, time.Millisecond,
		"zero data loss through gRPC path: expected %d",
		preReadyCount+steadyCount+rotationCount)
}
