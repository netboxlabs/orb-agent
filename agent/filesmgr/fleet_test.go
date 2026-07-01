package filesmgr

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

func boolPtr(b bool) *bool { return &b }

// mockEngine is a mock disk engine (filesmgr.Manager) injected into
// FleetFilesManager so HandlePackages can be tested without real downloads.
type mockEngine struct {
	mock.Mock
}

func (m *mockEngine) Start(ctx context.Context) error { args := m.Called(ctx); return args.Error(0) }
func (m *mockEngine) Stop(ctx context.Context) error  { args := m.Called(ctx); return args.Error(0) }

func (m *mockEngine) Ensure(ctx context.Context, spec FileSpec) (string, error) {
	args := m.Called(ctx, spec)
	return args.String(0), args.Error(1)
}

func (m *mockEngine) Get(name string) (FileEntry, bool) {
	args := m.Called(name)
	return args.Get(0).(FileEntry), args.Bool(1)
}

func (m *mockEngine) List() []FileEntry { return nil }

func (m *mockEngine) Remove(ctx context.Context, name string) error {
	args := m.Called(ctx, name)
	return args.Error(0)
}

func (m *mockEngine) Rollback(ctx context.Context, name string) error {
	args := m.Called(ctx, name)
	return args.Error(0)
}

func (m *mockEngine) Subscribe(fn func(FileEvent)) func() {
	args := m.Called(fn)
	return args.Get(0).(func())
}

func newTestFleet(eng Manager) *FleetFilesManager {
	stopCtx, stopCancel := context.WithCancel(context.Background())
	return &FleetFilesManager{
		Manager:    eng,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		stopCtx:    stopCtx,
		stopCancel: stopCancel,
	}
}

func TestFleetHandlePackages_ExtractDefaultsTrueWhenAbsent(t *testing.T) {
	eng := &mockEngine{}
	eng.On("Ensure", mock.Anything, FileSpec{
		Name:    "nbl_custom_worker",
		Version: "0.2.0",
		URL:     "https://example.com/bundle.tar.gz",
		SHA256:  "abc123",
		Extract: true, // BundleSpec omitted extract -> defaults to true
	}).Return("/opt/orb/files/nbl_custom_worker/0.2.0", nil)

	f := newTestFleet(eng)
	f.HandlePackages(context.Background(), messages.PackagesCredentialsRPCPayload{
		Bundles: []messages.BundleSpec{
			{Name: "nbl_custom_worker", Version: "0.2.0", URL: "https://example.com/bundle.tar.gz", SHA256: "abc123"},
		},
	})
	eng.AssertExpectations(t)
}

func TestFleetHandlePackages_ExtractHonorsExplicitFalse(t *testing.T) {
	eng := &mockEngine{}
	eng.On("Ensure", mock.Anything, FileSpec{
		Name:    "single_binary",
		Version: "1.0.0",
		URL:     "https://example.com/bin",
		SHA256:  "def456",
		Extract: false,
	}).Return("/opt/orb/files/single_binary/1.0.0", nil)

	f := newTestFleet(eng)
	f.HandlePackages(context.Background(), messages.PackagesCredentialsRPCPayload{
		Bundles: []messages.BundleSpec{
			{Name: "single_binary", Version: "1.0.0", URL: "https://example.com/bin", SHA256: "def456", Extract: boolPtr(false)},
		},
	})
	eng.AssertExpectations(t)
}

func TestFleetHandlePackages_PartialFailureIsNonFatal(t *testing.T) {
	eng := &mockEngine{}
	eng.On("Ensure", mock.Anything, FileSpec{
		Name:    "nbl_custom_worker",
		Version: "0.2.0",
		URL:     "https://example.com/worker.tar.gz",
		SHA256:  "aaa111",
		Extract: true,
	}).Return("", assert.AnError)
	eng.On("Ensure", mock.Anything, FileSpec{
		Name:    "nbl_custom_collector",
		Version: "0.1.0",
		URL:     "https://example.com/collector.tar.gz",
		SHA256:  "bbb222",
		Extract: true,
	}).Return("/opt/orb/files/nbl_custom_collector/0.1.0", nil)

	f := newTestFleet(eng)
	// First bundle fails; the second must still be attempted (non-fatal).
	f.HandlePackages(context.Background(), messages.PackagesCredentialsRPCPayload{
		Bundles: []messages.BundleSpec{
			{Name: "nbl_custom_worker", Version: "0.2.0", URL: "https://example.com/worker.tar.gz", SHA256: "aaa111"},
			{Name: "nbl_custom_collector", Version: "0.1.0", URL: "https://example.com/collector.tar.gz", SHA256: "bbb222"},
		},
	})
	eng.AssertExpectations(t)
}

func TestFleetHandlePackages_EmptyBundles(t *testing.T) {
	eng := &mockEngine{}
	f := newTestFleet(eng)
	f.HandlePackages(context.Background(), messages.PackagesCredentialsRPCPayload{})
	eng.AssertNotCalled(t, "Ensure")
}

func TestFleetSendBundleListRequest(t *testing.T) {
	f := newTestFleet(&mockEngine{})

	var captured []byte
	f.SendBundleListRequest(context.Background(), func(_ context.Context, payload []byte) error {
		captured = payload
		return nil
	})

	require.NotNil(t, captured)
	// Assert the full envelope, incl. an empty-object payload (RPC.Payload is `any`,
	// so a nil/wrong payload would otherwise slip through).
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(captured, &raw))
	var fn, schema string
	require.NoError(t, json.Unmarshal(raw["func"], &fn))
	require.NoError(t, json.Unmarshal(raw["schema_version"], &schema))
	assert.Equal(t, messages.BundleListReqRPCFunc, fn)
	assert.Equal(t, messages.CurrentRPCSchemaVersion, schema)
	assert.JSONEq(t, "{}", string(raw["payload"]))
}
