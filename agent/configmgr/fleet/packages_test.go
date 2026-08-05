package fleet

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
)

// mockFilesManager implements filesmgr.Manager but NOT bundleInstaller — it
// stands in for a non-fleet (dummy) files manager, where packages delivery is a
// no-op.
type mockFilesManager struct {
	mock.Mock
}

func (m *mockFilesManager) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockFilesManager) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockFilesManager) Ensure(ctx context.Context, spec filesmgr.FileSpec) (string, error) {
	args := m.Called(ctx, spec)
	return args.String(0), args.Error(1)
}

func (m *mockFilesManager) Get(name string) (filesmgr.FileEntry, bool) {
	args := m.Called(name)
	return args.Get(0).(filesmgr.FileEntry), args.Bool(1)
}

func (m *mockFilesManager) List() []filesmgr.FileEntry        { return nil }
func (m *mockFilesManager) ListPending() []filesmgr.FileEntry { return nil }

func (m *mockFilesManager) Remove(ctx context.Context, name string) error {
	args := m.Called(ctx, name)
	return args.Error(0)
}

func (m *mockFilesManager) Rollback(ctx context.Context, name string) error {
	args := m.Called(ctx, name)
	return args.Error(0)
}

func (m *mockFilesManager) Subscribe(fn func(filesmgr.FileEvent)) func() {
	args := m.Called(fn)
	return args.Get(0).(func())
}

// mockBundleInstaller additionally implements bundleInstaller — it stands in for
// the fleet files-manager type.
type mockBundleInstaller struct {
	mockFilesManager
}

func (m *mockBundleInstaller) HandlePackages(ctx context.Context, payload messages.PackagesCredentialsRPCPayload) {
	m.Called(ctx, payload)
}

func newTestMessagingWithFiles(fm filesmgr.Manager) *Messaging {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	return NewMessaging(logger, nil, resetChan, &groupManager, fm)
}

func marshalPackagesRPC(t *testing.T, bundles ...messages.BundleSpec) []byte {
	t.Helper()
	body, err := json.Marshal(messages.PackagesCredentialsRPC{
		SchemaVersion: "2",
		Func:          messages.PackagesCredentialsRPCFunc,
		Payload:       messages.PackagesCredentialsRPCPayload{Bundles: bundles},
	})
	assert.NoError(t, err)
	return body
}

var noopTopicActions = TopicActions{
	Subscribe:   func(string) error { return nil },
	Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
	Unsubscribe: func(string) error { return nil },
}

// When the files manager is the fleet type (implements bundleInstaller),
// packages_credentials is routed to HandlePackages.
func TestDispatchToHandlers_PackagesCredentials_RoutesToInstaller(t *testing.T) {
	fm := &mockBundleInstaller{}
	fm.On("HandlePackages", mock.Anything, mock.AnythingOfType("messages.PackagesCredentialsRPCPayload")).Return()

	messaging := newTestMessagingWithFiles(fm)
	payload := marshalPackagesRPC(t,
		messages.BundleSpec{Name: "nbl_custom_worker", Version: "0.2.0", URL: "https://example.com/bundle.tar.gz", SHA256: "abc123"},
	)

	err := messaging.DispatchToHandlers(context.Background(), payload, "org1", "agent1", noopTopicActions)
	assert.NoError(t, err)
	fm.AssertCalled(t, "HandlePackages", mock.Anything, mock.AnythingOfType("messages.PackagesCredentialsRPCPayload"))
}

// When the files manager is not the fleet type (no bundleInstaller), packages
// delivery is skipped quietly — no install attempt, no error.
func TestDispatchToHandlers_PackagesCredentials_NonFleetSkips(t *testing.T) {
	fm := &mockFilesManager{}
	messaging := newTestMessagingWithFiles(fm)
	payload := marshalPackagesRPC(t,
		messages.BundleSpec{Name: "nbl_custom_worker", Version: "0.2.0", URL: "https://example.com/bundle.tar.gz", SHA256: "abc123"},
	)

	err := messaging.DispatchToHandlers(context.Background(), payload, "org1", "agent1", noopTopicActions)
	assert.NoError(t, err)
	fm.AssertNotCalled(t, "Ensure")
}
