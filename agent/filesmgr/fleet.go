package filesmgr

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/configmgr/fleet/messages"
)

var _ Manager = (*FleetFilesManager)(nil)

// bundleInstallTimeout bounds a single bundle's fetch + install.
const bundleInstallTimeout = 10 * time.Minute

// FleetFilesManager is the fleet-triggered files-manager type. Bundles are
// delivered to it over MQTT by the fleet config manager (HandlePackages), and
// on every (re)connect it asks the control plane to re-deliver its current set
// (SendBundleListRequest). All file mechanics (fetch/verify/track/events) come
// from the embedded disk engine; this type only adds the fleet trigger.
type FleetFilesManager struct {
	Manager // embedded disk engine

	logger     *slog.Logger
	stopCtx    context.Context
	stopCancel context.CancelFunc
}

// newFleetFilesManager builds a fleet files manager over a disk engine rooted at
// cfg.Root (defaulting to defaultRoot when empty).
func newFleetFilesManager(logger *slog.Logger, cfg config.FilesManagerConfig) *FleetFilesManager {
	if logger == nil {
		logger = slog.Default()
	}
	root := cfg.Root
	if root == "" {
		root = defaultRoot
	}
	stopCtx, stopCancel := context.WithCancel(context.Background())
	return &FleetFilesManager{
		Manager:    NewManager(logger, root),
		logger:     logger.With("subsystem", "filesmgr-fleet"),
		stopCtx:    stopCtx,
		stopCancel: stopCancel,
	}
}

// Stop cancels any in-flight bundle installation, then stops the engine.
func (f *FleetFilesManager) Stop(ctx context.Context) error {
	f.stopCancel()
	return f.Manager.Stop(ctx)
}

// HandlePackages installs each bundle from a packages_credentials delivery.
// Failures are non-fatal: a failed bundle is logged and skipped so the rest of
// the delivery still installs. A bundle with no explicit "extract" defaults to
// true (bundles are tarballs); an explicit false is honored.
func (f *FleetFilesManager) HandlePackages(_ context.Context, payload messages.PackagesCredentialsRPCPayload) {
	if len(payload.Bundles) == 0 {
		f.logger.Debug("packages_credentials received with empty bundle list, nothing to do")
		return
	}
	f.logger.Info("installing bundles", "count", len(payload.Bundles))
	for _, bundle := range payload.Bundles {
		// TODO: check bundle.ExpiresAt before Ensure to avoid downloading with
		// an already-expired presigned URL.
		installCtx, cancel := context.WithTimeout(f.stopCtx, bundleInstallTimeout)
		extract := true
		if bundle.Extract != nil {
			extract = *bundle.Extract
		}
		spec := FileSpec{
			Name:       bundle.Name,
			Version:    bundle.Version,
			URL:        bundle.URL,
			SHA256:     bundle.SHA256,
			Extract:    extract,
			TargetPath: bundle.TargetPath,
			Mode:       bundle.Mode,
		}
		path, err := f.Ensure(installCtx, spec)
		cancel()
		if err != nil {
			f.logger.Error("failed to install bundle",
				"name", bundle.Name, "version", bundle.Version, "error", err)
			continue
		}
		f.logger.Info("bundle installed",
			"name", bundle.Name, "version", bundle.Version, "path", path)
	}
}

// SendBundleListRequest publishes a bundle_list_req (via publishFunc, which
// targets the agent outbox) asking the control plane to re-deliver the agent's
// current bundle set. This is the connect/reconnect catch-up.
func (f *FleetFilesManager) SendBundleListRequest(ctx context.Context, publishFunc func(ctx context.Context, payload []byte) error) {
	body, err := json.Marshal(messages.RPC{
		SchemaVersion: messages.CurrentRPCSchemaVersion,
		Func:          messages.BundleListReqRPCFunc,
		Payload:       messages.BundleListReqRPCPayload{},
	})
	if err != nil {
		f.logger.Error("failed to marshal bundle_list_req, skipping", "error", err)
		return
	}
	if err := publishFunc(ctx, body); err != nil {
		f.logger.Error("error sending bundle_list_req", "error", err)
		return
	}
	f.logger.Debug("bundle_list_req sent")
}
