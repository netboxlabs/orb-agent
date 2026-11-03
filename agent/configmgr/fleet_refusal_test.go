package configmgr

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet"
)

// The messages these tests count.
const (
	refusalMsg       = "Fleet refused the agent's credentials"
	attemptFailedMsg = "refresh and reconnect attempt failed"
	exhaustedMsg     = "all refresh and reconnect attempts exhausted"
	reconnectedMsg   = "successfully refreshed JWT and reconnected"
)

type recordedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

// recordingHandler keeps every record logged through it.
type recordingHandler struct {
	mu      sync.Mutex
	records []recordedRecord
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]any{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, recordedRecord{level: r.Level, msg: r.Message, attrs: attrs})
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

// matching returns the records logged at level whose message starts with prefix.
func (h *recordingHandler) matching(level slog.Level, prefix string) []recordedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []recordedRecord
	for _, r := range h.records {
		if r.level == level && strings.HasPrefix(r.msg, prefix) {
			out = append(out, r)
		}
	}
	return out
}

// recordLogs makes mgr log through a recordingHandler and returns it.
func recordLogs(mgr *FleetConfigManager) *recordingHandler {
	h := &recordingHandler{}
	mgr.logger = slog.New(h)
	return h
}

// newRefusingTokenServer is a token endpoint that answers status to the
// refuseForCount requests after the priming one, and a valid token after.
func newRefusingTokenServer(t *testing.T, refuseForCount, status int) (*httptest.Server, *controlledTokenServer) {
	t.Helper()
	server, handler := newControlledTokenServer(t, refuseForCount)
	handler.mu.Lock()
	handler.failStatus = status
	handler.mu.Unlock()
	return server, handler
}

// startReconnectWorker runs mgr's reconnect worker with millisecond backoffs
// and returns a func that stops it and waits for it to return.
func startReconnectWorker(t *testing.T, mgr *FleetConfigManager, maxRetries int, retryDelay, refusedRetryDelay time.Duration) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		mgr.runReconnectWorker(ctx, 10*time.Second, maxRetries, 10*time.Millisecond, 50*time.Millisecond, retryDelay, refusedRetryDelay)
	}()
	stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("the reconnect worker did not return after its context was cancelled")
		}
	}
	t.Cleanup(stop)
	return stop
}

// A token endpoint that refuses the credentials gets one request per refusal
// delay, not the fast attempts a server error gets; each refusal logs one
// ERROR naming it, and a signal sent during the wait, as the token monitor or
// a failing publish sends, does not bring the retry forward.
func TestFleetConfigManager_ReconnectWorker_RetriesARefusalAtTheRefusalPace(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, handler := newRefusingTokenServer(t, 100, status)
			defer server.Close()
			mockConn := &fleet.MockMQTTConnection{}
			mgr := newReconnectWorkerManager(t, mockConn, server.URL)
			logs := recordLogs(mgr)

			const refusedRetryDelay = 300 * time.Millisecond
			startReconnectWorker(t, mgr, 5, 50*time.Millisecond, refusedRetryDelay)
			mgr.reconnectChan <- struct{}{}

			require.Eventually(t, func() bool { return len(logs.matching(slog.LevelError, refusalMsg)) == 1 },
				2*time.Second, 5*time.Millisecond, "the first refusal is logged")
			mgr.reconnectChan <- struct{}{}
			require.Eventually(t, func() bool { return len(logs.matching(slog.LevelError, refusalMsg)) == 2 },
				2*time.Second, 5*time.Millisecond, "the refused refresh is retried")

			times := handler.RequestTimes()
			require.Len(t, times, 3, "the priming request, then one per refusal")
			assert.GreaterOrEqual(t, times[2].Sub(times[1]), refusedRetryDelay, "a refused refresh is retried only after the refusal delay")
			assert.Empty(t, logs.matching(slog.LevelError, attemptFailedMsg), "a refusal is not logged as a failed attempt")
			assert.Empty(t, logs.matching(slog.LevelError, exhaustedMsg))
			assert.Equal(t, int64(status), logs.matching(slog.LevelError, refusalMsg)[0].attrs["status_code"])
			assert.Equal(t, 1, mockConn.DisconnectCount(), "a refused agent disconnects once, so Fleet shows it offline")
		})
	}
}

// Credentials restored in Fleet reconnect the agent at the next retry, with
// no extra refresh for a signal sent during the wait, and the token monitor
// signals the worker again afterwards.
func TestFleetConfigManager_ReconnectWorker_RestoredCredentialsEndTheRefusal(t *testing.T) {
	server, handler := newRefusingTokenServer(t, 1, http.StatusUnauthorized)
	defer server.Close()
	mgr := newReconnectWorkerManager(t, &fleet.MockMQTTConnection{}, server.URL)
	logs := recordLogs(mgr)

	stop := startReconnectWorker(t, mgr, 5, 50*time.Millisecond, 100*time.Millisecond)
	mgr.reconnectChan <- struct{}{}
	require.Eventually(t, func() bool { return len(logs.matching(slog.LevelError, refusalMsg)) == 1 },
		2*time.Second, 5*time.Millisecond, "the first refusal is logged")
	mgr.reconnectChan <- struct{}{}

	require.Eventually(t, func() bool { return len(logs.matching(slog.LevelInfo, reconnectedMsg)) == 1 },
		2*time.Second, 5*time.Millisecond, "the retry after the refusal delay reconnects")
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 3, handler.RequestCount(), "the priming request, the refused one and the accepted one")

	stop()
	mgr.checkTokenExpiry(2 * time.Hour)
	select {
	case <-mgr.reconnectChan:
	default:
		t.Fatal("once Fleet accepts the credentials again, the token monitor signals the worker")
	}
}

// While Fleet refuses the credentials, the token monitor neither warns that
// the token expires nor signals the worker, which retries at its own pace.
func TestFleetConfigManager_TokenMonitor_QuietWhileFleetRefusesTheCredentials(t *testing.T) {
	server, handler := newRefusingTokenServer(t, 100, http.StatusUnauthorized)
	defer server.Close()
	mgr := newReconnectWorkerManager(t, &fleet.MockMQTTConnection{}, server.URL)
	logs := recordLogs(mgr)

	startReconnectWorker(t, mgr, 5, 50*time.Millisecond, time.Minute)
	mgr.reconnectChan <- struct{}{}
	require.Eventually(t, func() bool { return len(logs.matching(slog.LevelError, refusalMsg)) == 1 },
		2*time.Second, 5*time.Millisecond, "the refusal is logged")

	// Within a two-hour buffer the cached token is expiring soon.
	mgr.checkTokenExpiry(2 * time.Hour)
	assert.Empty(t, logs.matching(slog.LevelWarn, "JWT token"), "no expiry WARN while the refusal is reported")
	select {
	case <-mgr.reconnectChan:
		t.Fatal("the token monitor signalled the worker while Fleet refuses the credentials")
	default:
	}
	assert.Equal(t, 2, handler.RequestCount(), "the priming request and the refused one")
}

// A server error keeps today's fast retries and messages, and leaves the token
// monitor signalling the worker.
func TestFleetConfigManager_ReconnectWorker_ServerErrorKeepsTheFastRetries(t *testing.T) {
	server, handler := newControlledTokenServer(t, 100)
	defer server.Close()
	mgr := newReconnectWorkerManager(t, &fleet.MockMQTTConnection{}, server.URL)
	logs := recordLogs(mgr)

	// A refusal delay shorter than any backoff: a server error handled as a
	// refusal would show as an extra request.
	stop := startReconnectWorker(t, mgr, 3, 5*time.Second, time.Millisecond)
	mgr.reconnectChan <- struct{}{}
	require.Eventually(t, func() bool { return len(logs.matching(slog.LevelError, exhaustedMsg)) == 1 },
		2*time.Second, 5*time.Millisecond, "the attempts are exhausted")
	stop()

	assert.Len(t, logs.matching(slog.LevelError, attemptFailedMsg), 3, "one ERROR per failed attempt")
	assert.Empty(t, logs.matching(slog.LevelError, refusalMsg), "a server error is not a refusal")
	assert.Equal(t, 4, handler.RequestCount(), "the priming request and three attempts")

	mgr.checkTokenExpiry(2 * time.Hour)
	assert.Len(t, logs.matching(slog.LevelWarn, "JWT token expiring soon"), 1)
	select {
	case <-mgr.reconnectChan:
	default:
		t.Fatal("after a server error the token monitor still signals the worker")
	}
}

// Stopping the agent during the refusal wait returns the worker at once.
func TestFleetConfigManager_ReconnectWorker_StopsDuringTheRefusalWait(t *testing.T) {
	server, _ := newRefusingTokenServer(t, 100, http.StatusUnauthorized)
	defer server.Close()
	mgr := newReconnectWorkerManager(t, &fleet.MockMQTTConnection{}, server.URL)
	logs := recordLogs(mgr)

	stop := startReconnectWorker(t, mgr, 5, 50*time.Millisecond, time.Minute)
	mgr.reconnectChan <- struct{}{}
	require.Eventually(t, func() bool { return len(logs.matching(slog.LevelError, refusalMsg)) == 1 },
		2*time.Second, 5*time.Millisecond, "the refusal is logged")

	started := time.Now()
	stop()
	assert.Less(t, time.Since(started), time.Second, "the worker returns without waiting out the refusal delay")
}
