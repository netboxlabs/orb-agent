package fleet

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestHeartbeater_MultipleStopStartCycles_OBS2315 exercises repeated disconnect/reconnect style
// handoffs; each cycle must allow periodic publishes again (OBS-2315).
func TestHeartbeater_MultipleStopStartCycles_OBS2315(t *testing.T) {
	hb := createTestHeartbeater()
	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	testTopic := "test/heartbeat"
	var publishCount atomic.Int32
	mockPublish.On("Publish", mock.Anything, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Run(func(_ mock.Arguments) {
		publishCount.Add(1)
	}).Maybe()

	for range 4 {
		hb.StartHeartbeats(ctx, testTopic, "test-agent-id", mockPublish.Publish, nil)
		time.Sleep(80 * time.Millisecond)
		hb.stop(testTopic, mockPublish.Publish)
	}
	require.GreaterOrEqual(t, int(publishCount.Load()), 8)
	mockPublish.AssertExpectations(t)
}

// TestHeartbeater_AtMostOnePublishAtATime verifies the heartbeat loop never publishes concurrently
// (session handoff should cancel the previous loop before the next ticks).
func TestHeartbeater_AtMostOnePublishAtATime(t *testing.T) {
	hb := createTestHeartbeater()
	var mu sync.Mutex
	concurrent := 0
	maxConcurrent := 0
	mockPublish := &mockPublishFunc{}
	ctx := context.Background()
	testTopic := "test/heartbeat"

	publish := func(c context.Context, topic string, payload []byte) error {
		mu.Lock()
		concurrent++
		if concurrent > maxConcurrent {
			maxConcurrent = concurrent
		}
		mu.Unlock()
		time.Sleep(2 * time.Millisecond)
		err := mockPublish.Publish(c, topic, payload)
		mu.Lock()
		concurrent--
		mu.Unlock()
		return err
	}
	mockPublish.On("Publish", mock.Anything, testTopic, mock.AnythingOfType("[]uint8")).Return(nil).Maybe()

	hb.StartHeartbeats(ctx, testTopic, "test-agent-id", publish, nil)
	time.Sleep(10 * time.Millisecond)
	hb.StartHeartbeats(ctx, testTopic, "test-agent-id", publish, nil)
	time.Sleep(120 * time.Millisecond)
	hb.stop(testTopic, publish)

	assert.LessOrEqual(t, maxConcurrent, 1, "heartbeats should not publish concurrently")
	mockPublish.AssertExpectations(t)
}
