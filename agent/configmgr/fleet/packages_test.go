package fleet

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
	"github.com/netboxlabs/orb-agent/agent/filesmgr"
)

// mockFilesManager implements filesmgr.Manager for testing
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

func newTestMessagingWithFiles(fm filesmgr.Manager) *Messaging {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	return NewMessaging(logger, nil, resetChan, &groupManager, fm)
}

func TestHandlePackages_HappyPath(t *testing.T) {
	fm := &mockFilesManager{}
	fm.On("Ensure", mock.Anything, filesmgr.FileSpec{
		Name:    "nbl_cisco_meraki",
		Version: "0.2.0",
		URL:     "https://example.com/bundle.tar.gz",
		SHA256:  "abc123",
		Extract: true,
	}).Return("/opt/orb/files/nbl_cisco_meraki/0.2.0", nil)

	messaging := newTestMessagingWithFiles(fm)
	payload := messages.PackagesCredentialsRPCPayload{
		Bundles: []messages.BundleSpec{
			{
				Name:      "nbl_cisco_meraki",
				Version:   "0.2.0",
				URL:       "https://example.com/bundle.tar.gz",
				SHA256:    "abc123",
				ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
			},
		},
	}
	messaging.handlePackages(context.Background(), payload)
	fm.AssertExpectations(t)
}

func TestHandlePackages_EmptyBundles(t *testing.T) {
	fm := &mockFilesManager{}
	// Ensure should never be called for empty payload
	messaging := newTestMessagingWithFiles(fm)
	messaging.handlePackages(context.Background(), messages.PackagesCredentialsRPCPayload{})
	fm.AssertNotCalled(t, "Ensure")
}

func TestHandlePackages_PartialFailure(t *testing.T) {
	fm := &mockFilesManager{}
	fm.On("Ensure", mock.Anything, filesmgr.FileSpec{
		Name:    "nbl_cisco_meraki",
		Version: "0.2.0",
		URL:     "https://example.com/meraki.tar.gz",
		SHA256:  "aaa111",
		Extract: true,
	}).Return("", assert.AnError)
	fm.On("Ensure", mock.Anything, filesmgr.FileSpec{
		Name:    "nbl_cisco_catalyst_center",
		Version: "0.1.0",
		URL:     "https://example.com/catalyst.tar.gz",
		SHA256:  "bbb222",
		Extract: true,
	}).Return("/opt/orb/files/nbl_cisco_catalyst_center/0.1.0", nil)

	messaging := newTestMessagingWithFiles(fm)
	payload := messages.PackagesCredentialsRPCPayload{
		Bundles: []messages.BundleSpec{
			{Name: "nbl_cisco_meraki", Version: "0.2.0", URL: "https://example.com/meraki.tar.gz", SHA256: "aaa111"},
			{Name: "nbl_cisco_catalyst_center", Version: "0.1.0", URL: "https://example.com/catalyst.tar.gz", SHA256: "bbb222"},
		},
	}
	// Should not panic — failure is non-fatal
	messaging.handlePackages(context.Background(), payload)
	fm.AssertExpectations(t)
}

func TestDispatchToHandlers_PackagesCredentials(t *testing.T) {
	fm := &mockFilesManager{}
	fm.On("Ensure", mock.Anything, mock.AnythingOfType("filesmgr.FileSpec")).
		Return("/opt/orb/files/nbl_cisco_meraki/0.2.0", nil)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	resetChan := make(chan struct{}, 1)
	groupManager := newGroupManager()
	handlers := NewMessaging(logger, nil, resetChan, &groupManager, fm)

	rpc := messages.PackagesCredentialsRPC{
		SchemaVersion: "2",
		Func:          messages.PackagesCredentialsRPCFunc,
		Payload: messages.PackagesCredentialsRPCPayload{
			Bundles: []messages.BundleSpec{
				{Name: "nbl_cisco_meraki", Version: "0.2.0", URL: "https://example.com/bundle.tar.gz", SHA256: "abc123"},
			},
		},
	}
	payload, err := json.Marshal(rpc)
	assert.NoError(t, err)

	err = handlers.DispatchToHandlers(context.Background(), payload, "org1", "agent1", TopicActions{
		Subscribe:   func(string) error { return nil },
		Publish:     func(_ context.Context, _ string, _ []byte) error { return nil },
		Unsubscribe: func(string) error { return nil },
	})
	assert.NoError(t, err)
	fm.AssertExpectations(t)
}

func TestHandlePackages_NilFilesManager(_ *testing.T) {
	messaging := newTestMessagingWithFiles(nil)
	payload := messages.PackagesCredentialsRPCPayload{
		Bundles: []messages.BundleSpec{
			{Name: "nbl_cisco_meraki", Version: "0.2.0", URL: "https://example.com/bundle.tar.gz", SHA256: "abc123"},
		},
	}
	// Should not panic when filesManager is nil
	messaging.handlePackages(context.Background(), payload)
}
