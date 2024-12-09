package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-discovery/network-discovery/config"
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
	var payload config.Config
	if err := yaml.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	if payload.Network.Policies == nil {
		return nil, errors.New("no policies found in the request")
	}

	return payload.Network.Policies, nil
}

// HasPolicy checks if the policy exists
func (m *Manager) HasPolicy(name string) bool {
	_, ok := m.policies[name]
	return ok
}

// StartPolicy starts the policy
func (m *Manager) StartPolicy(name string, policy config.Policy) error {
	if len(policy.Scope.Targets) == 0 {
		return fmt.Errorf("%s : no targets found in the policy", name)
	}

	if !m.HasPolicy(name) {
		r, err := NewRunner(m.ctx, m.logger, name, policy, m.client)
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

// GetCapabilities returns the capabilities of network-discovery
func (m *Manager) GetCapabilities() []string {
	return []string{"targets, ports"}
}
