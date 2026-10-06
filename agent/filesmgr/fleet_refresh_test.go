package filesmgr

import (
	"context"
	"encoding/json"
	"sync"
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
