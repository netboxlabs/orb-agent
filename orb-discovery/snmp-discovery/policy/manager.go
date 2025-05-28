package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/snmp"
	"gopkg.in/yaml.v3"
)

// Manager represents the policy manager
type Manager struct {
	policies map[string]*Runner
	client   diode.Client
	logger   *slog.Logger
	ctx      context.Context
}

// NewManager returns a new policy manager
func NewManager(ctx context.Context, logger *slog.Logger, client diode.Client) *Manager {
	return &Manager{
		ctx:      ctx,
		client:   client,
		logger:   logger,
		policies: make(map[string]*Runner),
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

	// Load the mapping config
	for name, policy := range payload.Policies {
		mappingConfig, err := m.loadMappingConfig(policy)
		if err != nil {
			return nil, fmt.Errorf("%s : invalid policy : %w", name, err)
		}

		// Create a new policy with updated mappings
		updatedPolicy := payload.Policies[name]
		updatedPolicy.Scope.Mappings = mappingConfig.Entries
		payload.Policies[name] = updatedPolicy
	}

	// Load the mapping config
	for name, policy := range payload.Policies {
		mappingConfig, err := m.loadMappingConfig(policy)
		if err != nil {
			return nil, fmt.Errorf("%s : invalid policy : %w", name, err)
		}

		// Create a new policy with updated mappings
		updatedPolicy := payload.Policies[name]
		updatedPolicy.Scope.Mappings = mappingConfig.Entries
		payload.Policies[name] = updatedPolicy
	}

	return payload.Policies, nil
}

func (m *Manager) loadMappingConfig(policy config.Policy) (config.Mapping, error) {
	m.logger.Debug("Loading mapping config", "mappingConfig", policy.Scope.MappingConfig)
	mappingConfigFileContents, err := os.ReadFile(policy.Scope.MappingConfig)
	if err != nil {
		return config.Mapping{}, fmt.Errorf("failed to read mapping config file: %w", err)
	}

	var mappingConfig config.Mapping
	if err := yaml.Unmarshal(mappingConfigFileContents, &mappingConfig); err != nil {
		return config.Mapping{}, err
	}

	return mappingConfig, nil
}

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

	// m.logger.Info("validating policy", "policy", policy.Scope.Authentication)

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

	// Validate MappingConfig
	if policy.Scope.MappingConfig == "" {
		return fmt.Errorf("missing mapping configuration file")
	}

	if _, err := os.Stat(policy.Scope.MappingConfig); os.IsNotExist(err) {
		return fmt.Errorf("mapping configuration file does not exist")
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

	if len(policy.Scope.Mappings) == 0 {
		return fmt.Errorf("%s : no mappings found in the policy", name)
	}

	if len(policy.Scope.Mappings) == 0 {
		return fmt.Errorf("%s : no mappings found in the policy", name)
	}

	if !m.HasPolicy(name) {
		r, err := NewRunner(m.ctx, m.logger, name, policy, m.client, snmp.NewClient)
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
