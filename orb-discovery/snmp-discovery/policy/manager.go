package policy

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/snmp"
	"gopkg.in/yaml.v3"
)

//go:embed mapping.yaml
var embeddedMapping embed.FS

const (
	// SNMPDefaultPort is the default SNMP port
	SNMPDefaultPort = 161
)

// Manager represents the policy manager
type Manager struct {
	policies      map[string]*Runner
	client        diode.Client
	logger        *slog.Logger
	ctx           context.Context
	mappingConfig config.Mapping
}

// NewManager returns a new policy manager
func NewManager(ctx context.Context, logger *slog.Logger, client diode.Client) *Manager {
	mappingConfig, err := loadMappingConfig()
	if err != nil {
		logger.Error("Failed to load mapping config", "error", err)
	}
	return &Manager{
		ctx:           ctx,
		client:        client,
		logger:        logger,
		mappingConfig: mappingConfig,
		policies:      make(map[string]*Runner),
	}
}

// ParsePolicies parses the policies from the request
func (m *Manager) ParsePolicies(data []byte) (map[string]config.Policy, error) {
	var payload config.Policies
	if err := yaml.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	if len(payload.Policies) == 0 {
		return nil, errors.New("no policies found in the request")
	}

	for name, policy := range payload.Policies {
		if err := m.validatePolicy(policy); err != nil {
			return nil, fmt.Errorf("%s : invalid policy : %w", name, err)
		}
	}

	for name := range payload.Policies {

		// Create a new policy with updated mappings
		updatedPolicy := payload.Policies[name]
		m.applyDefaults(&updatedPolicy)
		payload.Policies[name] = updatedPolicy
	}

	return payload.Policies, nil
}

// loadMappingConfig loads the mapping config from the embedded file
func loadMappingConfig() (config.Mapping, error) {
	mappingConfigFileContents, err := embeddedMapping.ReadFile("mapping.yaml")
	if err != nil {
		return config.Mapping{}, fmt.Errorf("failed to read embedded mapping config file: %w", err)
	}

	var mappingConfig config.Mapping
	if err := yaml.Unmarshal(mappingConfigFileContents, &mappingConfig); err != nil {
		return config.Mapping{}, fmt.Errorf("failed to unmarshal embedded mapping config: %w", err)
	}

	return mappingConfig, nil
}

// applyDefaults applies the default values to the policy
// Note: this is different to the default mapping values (comments, tags etc)
func (m *Manager) applyDefaults(policy *config.Policy) {
	for i, target := range policy.Scope.Targets {
		if target.Port == 0 {
			policy.Scope.Targets[i].Port = SNMPDefaultPort
		}
	}
}

// validatePolicy validates the policy
func (m *Manager) validatePolicy(policy config.Policy) error {
	if policy.Scope.Authentication.ProtocolVersion == "" {
		return fmt.Errorf("missing protocol version")
	}

	if policy.Scope.Authentication.ProtocolVersion != "SNMPv1" && policy.Scope.Authentication.ProtocolVersion != "SNMPv2c" && policy.Scope.Authentication.ProtocolVersion != "SNMPv3" {
		return fmt.Errorf("unsupported protocol version")
	}

	if policy.Scope.Authentication.ProtocolVersion == "SNMPv2c" || policy.Scope.Authentication.ProtocolVersion == "SNMPv1" {
		if policy.Scope.Authentication.Community == "" {
			return fmt.Errorf("missing community")
		}
	}

	if policy.Scope.Authentication.ProtocolVersion == "SNMPv3" {
		if policy.Scope.Authentication.SecurityLevel != "noAuthNoPriv" &&
			policy.Scope.Authentication.SecurityLevel != "authNoPriv" &&
			policy.Scope.Authentication.SecurityLevel != "authPriv" {
			return fmt.Errorf("invalid security level %s", policy.Scope.Authentication.SecurityLevel)
		}
		if policy.Scope.Authentication.SecurityLevel == "authNoPriv" || policy.Scope.Authentication.SecurityLevel == "authPriv" {
			if policy.Scope.Authentication.Username == "" {
				return fmt.Errorf("missing username")
			}

			if policy.Scope.Authentication.AuthPassphrase == "" {
				return fmt.Errorf("missing auth passphrase")
			}

			if policy.Scope.Authentication.AuthProtocol == "" {
				return fmt.Errorf("missing auth protocol")
			}
		}
		if policy.Scope.Authentication.SecurityLevel == "authPriv" {
			if policy.Scope.Authentication.PrivPassphrase == "" {
				return fmt.Errorf("missing priv passphrase")
			}

			if policy.Scope.Authentication.PrivProtocol == "" {
				return fmt.Errorf("missing priv protocol")
			}
		}
	}

	return nil
}

// HasPolicy checks if the policy exists
func (m *Manager) HasPolicy(name string) bool {
	_, ok := m.policies[name]
	return ok
}

// StartPolicy starts the policy
func (m *Manager) StartPolicy(name string, policy config.Policy) error {
	m.logger.Debug("Starting policy", "policy", policy)
	if len(policy.Scope.Targets) == 0 {
		return fmt.Errorf("%s : no targets found in the policy", name)
	}

	if !m.HasPolicy(name) {
		r, err := NewRunner(m.ctx, m.logger, name, policy, m.client, snmp.NewClient, m.mappingConfig)
		if err != nil {
			return err
		}

		r.Start()
		m.policies[name] = r
	}
	return nil
}

// StopPolicy stops the policy
func (m *Manager) StopPolicy(name string) error {
	if m.HasPolicy(name) {
		if err := m.policies[name].Stop(); err != nil {
			return err
		}
		delete(m.policies, name)
	}
	return nil
}

// Stop stops the policy manager
func (m *Manager) Stop() error {
	for name := range m.policies {
		if err := m.StopPolicy(name); err != nil {
			return err
		}
	}
	return nil
}

// GetCapabilities returns the capabilities of snm-discovery
func (m *Manager) GetCapabilities() []string {
	return []string{"targets"}
}
