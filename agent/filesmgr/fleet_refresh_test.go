package filesmgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

type refreshClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *refreshClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *refreshClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newRefreshFleet builds a fleet manager with a fake clock and registers a
// publish function (as the connect-time catch-up does). The registration
// publish itself is drained, so the returned channel only carries re-requests.
func newRefreshFleet(t *testing.T, eng Manager, clk *refreshClock) (*FleetFilesManager, chan []byte) {
	t.Helper()
	f := newTestFleet(eng)
	t.Cleanup(f.stopCancel)
	f.now = clk.now
	pub := make(chan []byte, 8)
	f.SendBundleListRequest(context.Background(), func(_ context.Context, payload []byte) error {
		pub <- payload
		return nil
	})
	<-pub
	return f, pub
}

func expectRequest(t *testing.T, pub chan []byte) {
	t.Helper()
	select {
	case payload := <-pub:
		var raw map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(payload, &raw))
		var fn string
		require.NoError(t, json.Unmarshal(raw["func"], &fn))
		assert.Equal(t, messages.BundleListReqRPCFunc, fn)
	case <-time.After(2 * time.Second):
		t.Fatal("expected a bundle list re-request, got none")
	}
}

func expectNoRequest(t *testing.T, pub chan []byte) {
	t.Helper()
	select {
	case <-pub:
		t.Fatal("unexpected bundle list re-request")
	case <-time.After(150 * time.Millisecond):
	}
}

func bundleWithExpiry(expiresAt int64) messages.PackagesCredentialsRPCPayload {
	return messages.PackagesCredentialsRPCPayload{Bundles: []messages.BundleSpec{
		{Name: "nbl_custom_worker", Version: "0.2.0", URL: "https://example.com/b.tar.gz", SHA256: "aaa111", ExpiresAt: expiresAt},
	}}
}

func failingEngine() *mockEngine {
	eng := &mockEngine{}
	eng.On("Ensure", mock.Anything, mock.Anything).Return("", assert.AnError)
	return eng
}

func TestFleetHandlePackages_ExpiredURLFailureRequestsFreshList(t *testing.T) {
	clk := &refreshClock{t: time.Unix(1_800_000_000, 0)}
	f, pub := newRefreshFleet(t, failingEngine(), clk)

	f.HandlePackages(context.Background(), bundleWithExpiry(clk.now().Unix()-60))
	expectRequest(t, pub)
}

func TestFleetHandlePackages_UnexpiredFailureDoesNotRequest(t *testing.T) {
	clk := &refreshClock{t: time.Unix(1_800_000_000, 0)}
	f, pub := newRefreshFleet(t, failingEngine(), clk)

	f.HandlePackages(context.Background(), bundleWithExpiry(clk.now().Unix()+600))
	expectNoRequest(t, pub)
}

func TestFleetHandlePackages_UnknownExpiryIsIgnored(t *testing.T) {
	clk := &refreshClock{t: time.Unix(1_800_000_000, 0)}
	f, pub := newRefreshFleet(t, failingEngine(), clk)

	f.HandlePackages(context.Background(), bundleWithExpiry(0))
	expectNoRequest(t, pub)
}

func TestFleetHandlePackages_SuccessWithPastExpiryDoesNotRequest(t *testing.T) {
	clk := &refreshClock{t: time.Unix(1_800_000_000, 0)}
	eng := &mockEngine{}
	eng.On("Ensure", mock.Anything, mock.Anything).Return("/opt/orb/files/nbl_custom_worker/0.2.0", nil)
	f, pub := newRefreshFleet(t, eng, clk)

	f.HandlePackages(context.Background(), bundleWithExpiry(clk.now().Unix()-60))
	expectNoRequest(t, pub)
}

func TestFleetHandlePackages_NoRegisteredPublishFuncIsSafe(t *testing.T) {
	clk := &refreshClock{t: time.Unix(1_800_000_000, 0)}
	f := newTestFleet(failingEngine())
	t.Cleanup(f.stopCancel)
	f.now = clk.now

	// No SendBundleListRequest yet, so there is nothing to publish with.
	assert.NotPanics(t, func() {
		f.HandlePackages(context.Background(), bundleWithExpiry(clk.now().Unix()-60))
	})
	f.requestFreshBundleList()
}

func TestFleetHandlePackages_RefreshIsRateLimited(t *testing.T) {
	clk := &refreshClock{t: time.Unix(1_800_000_000, 0)}
	f, pub := newRefreshFleet(t, failingEngine(), clk)
	expired := bundleWithExpiry(clk.now().Unix() - 60)

	f.HandlePackages(context.Background(), expired)
	expectRequest(t, pub)

	f.HandlePackages(context.Background(), expired) // within the cooldown
	expectNoRequest(t, pub)

	clk.advance(bundleRefreshCooldown + time.Second)
	f.HandlePackages(context.Background(), expired)
	expectRequest(t, pub)
}

// A refresh that captured publisher A must not replace publisher B, which a
// reconnect registered while the refresh was still publishing.
func TestFleetRefresh_DoesNotReplaceCurrentPublisher(t *testing.T) {
	clk := &refreshClock{t: time.Unix(1_800_000_000, 0)}
	f := newTestFleet(failingEngine())
	t.Cleanup(f.stopCancel)
	f.now = clk.now

	oldPub := make(chan []byte, 4)
	newPub := make(chan []byte, 4)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var oldCalls atomic.Int32

	oldFn := func(_ context.Context, payload []byte) error {
		if oldCalls.Add(1) == 1 {
			return nil // the registration publish
		}
		once.Do(func() { close(entered) })
		<-release
		oldPub <- payload
		return nil
	}
	newFn := func(_ context.Context, payload []byte) error {
		newPub <- payload
		return nil
	}

	f.SendBundleListRequest(context.Background(), oldFn)

	// Start a refresh; it captures oldFn and blocks inside it.
	done := make(chan struct{})
	go func() {
		f.requestFreshBundleList()
		close(done)
	}()
	<-entered

	// A reconnect registers the new publisher while the refresh is in flight.
	f.SendBundleListRequest(context.Background(), newFn)
	<-newPub // drain the registration publish

	close(release)
	<-done
	expectRequest(t, oldPub) // the in-flight refresh still completes via oldFn

	// The next refresh must go through the new publisher.
	clk.advance(bundleRefreshCooldown + time.Second)
	f.requestFreshBundleList()
	expectRequest(t, newPub)
	expectNoRequest(t, oldPub)
}

func engineFailingWith(err error) *mockEngine {
	eng := &mockEngine{}
	eng.On("Ensure", mock.Anything, mock.Anything).Return("", err)
	return eng
}

func statusErr(code int) error {
	return &httpStatusError{StatusCode: code, err: fmt.Errorf("bad response code: %d", code)}
}

// A 401/403 from the server means the delivered URL is no good even when its
// expiry has not passed (or is unknown), so it triggers a refresh on its own.
func TestFleetHandlePackages_RejectedURLRequestsFreshList(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			clk := &refreshClock{t: time.Unix(1_800_000_000, 0)}
			// Wrapped the way the engine returns it; unexpired so the trigger is
			// the status, not the clock.
			f, pub := newRefreshFleet(t, engineFailingWith(fmt.Errorf("fetch x: %w", statusErr(code))), clk)

			f.HandlePackages(context.Background(), bundleWithExpiry(clk.now().Unix()+600))
			expectRequest(t, pub)
		})
	}
}

func TestFleetHandlePackages_RejectedURLWithUnknownExpiryRequests(t *testing.T) {
	clk := &refreshClock{t: time.Unix(1_800_000_000, 0)}
	f, pub := newRefreshFleet(t, engineFailingWith(statusErr(http.StatusForbidden)), clk)

	f.HandlePackages(context.Background(), bundleWithExpiry(0))
	expectRequest(t, pub)
}

func TestFleetHandlePackages_OtherStatusesDoNotRequest(t *testing.T) {
	for _, code := range []int{
		http.StatusBadRequest,
		http.StatusNotFound,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			clk := &refreshClock{t: time.Unix(1_800_000_000, 0)}
			f, pub := newRefreshFleet(t, engineFailingWith(statusErr(code)), clk)

			f.HandlePackages(context.Background(), bundleWithExpiry(clk.now().Unix()+600))
			expectNoRequest(t, pub)
		})
	}
}

func TestURLRejected(t *testing.T) {
	assert.False(t, urlRejected(nil))
	assert.False(t, urlRejected(errors.New("boom")))
	assert.False(t, urlRejected(statusErr(http.StatusNotFound)))
	assert.True(t, urlRejected(statusErr(http.StatusUnauthorized)))
	assert.True(t, urlRejected(statusErr(http.StatusForbidden)))
	assert.True(t, urlRejected(fmt.Errorf("outer: %w", statusErr(http.StatusForbidden))))
}
