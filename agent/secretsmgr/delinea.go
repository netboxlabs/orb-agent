package secretsmgr

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"

	"github.com/DelineaXPM/tss-sdk-go/v3/server"

	"github.com/netboxlabs/orb-agent/agent/config"
)

var _ Manager = (*delineaManager)(nil)

// delineaManager resolves ${delinea://…} placeholders against Delinea Secret Server.
type delineaManager struct {
	logger   *slog.Logger
	config   config.DelineaManager
	ctx      context.Context
	client   *server.Server
	usedVars map[string]cachedSecret
	callback func(map[string]bool)
}

// Start validates the configuration and constructs the SDK client. It does
// NOT eagerly authenticate — the SDK lazy-auths on first secret fetch.
func (d *delineaManager) Start(ctx context.Context) error {
	d.ctx = ctx
	d.usedVars = make(map[string]cachedSecret)

	if (d.config.ServerURL == "" && d.config.Tenant == "") ||
		(d.config.ServerURL != "" && d.config.Tenant != "") {
		return fmt.Errorf("either server_url or tenant must be set (not both and not neither)")
	}
	if d.config.Username == "" {
		return fmt.Errorf("username is required")
	}
	if d.config.Password == "" {
		return fmt.Errorf("password is required")
	}

	sdkCfg := server.Configuration{
		Credentials: server.UserCredential{
			Username: d.config.Username,
			Password: d.config.Password,
		},
		ServerURL: d.config.ServerURL,
		Tenant:    d.config.Tenant,
	}
	// NOTE: server.New mutates http.DefaultTransport.TLSClientConfig globally
	// when this field is non-nil. Only set it when the operator explicitly
	// opted into skip_tls.
	if d.config.SkipTLS {
		sdkCfg.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // operator opted in via config
	}

	c, err := server.New(sdkCfg)
	if err != nil {
		return fmt.Errorf("failed to create delinea client: %w", err)
	}
	d.client = c

	return nil
}

// RegisterUpdatePoliciesCallback registers the policy-reapply callback.
func (d *delineaManager) RegisterUpdatePoliciesCallback(callback func(map[string]bool)) {
	d.callback = callback
}

// SolvePolicySecrets is a stub for Task 5.
func (d *delineaManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	return payload, nil
}

// SolveConfigSecrets is a stub for Task 6.
func (d *delineaManager) SolveConfigSecrets(backends map[string]any, cm config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	return backends, cm, nil
}
