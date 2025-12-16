package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/network-discovery/config"
	"gopkg.in/yaml.v3"
)

// Manager represents the policy manager
type Manager struct {
	policies map[string]*Runner
	client   diode.Client
	logger   *slog.Logger
	ctx      context.Context
	jobStore *JobStore
}

// NewManager returns a new policy manager
func NewManager(ctx context.Context, logger *slog.Logger, client diode.Client) *Manager {
	return &Manager{
		ctx:      ctx,
		client:   client,
		logger:   logger,
		policies: make(map[string]*Runner),
		jobStore: NewJobStore(),
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

	return payload.Policies, nil
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
		r, err := NewRunner(m.ctx, m.logger, name, policy, m.client, m.jobStore)
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
	return []string{"targets, ports, exclude_ports, timing, fast_mode, ping_scan, top_ports, scan_types, max_retries"}
}

// Status represents the status of a policy with its jobs
type Status struct {
	Name   string `json:"name"`
	Status string `json:"status"` // derived from latest job
	Jobs   []*Job `json:"jobs"`
}

// GetPolicyStatuses returns all policies with their status and jobs
func (m *Manager) GetPolicyStatuses() []Status {
	allJobs := m.jobStore.GetAllPoliciesWithJobs()

	statuses := make([]Status, 0)

	// Get statuses for all policies that have runners
	for name := range m.policies {
		jobs := m.jobStore.GetJobsForPolicy(name)
		status := "unknown"
		if len(jobs) > 0 {
			latestJob := jobs[len(jobs)-1]
			status = string(latestJob.Status)
		}
		statuses = append(statuses, Status{
			Name:   name,
			Status: status,
			Jobs:   jobs,
		})
	}

	// Also include policies that have jobs but no active runner
	for name, jobs := range allJobs {
		if !m.HasPolicy(name) {
			status := "unknown"
			if len(jobs) > 0 {
				latestJob := jobs[len(jobs)-1]
				status = string(latestJob.Status)
			}

			statuses = append(statuses, Status{
				Name:   name,
				Status: status,
				Jobs:   jobs,
			})
		}
	}

	return statuses
}
