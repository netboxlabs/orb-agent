package policy

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"go.yaml.in/yaml/v3"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/data"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/env"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/targets"
)

//go:embed mapping.yaml
var embeddedMapping embed.FS

const (
	// SNMPDefaultPort is the default SNMP port
	SNMPDefaultPort = 161
	// defaultSite is the site a policy that names none is given.
	defaultSite = "undefined"
)

// Manager represents the policy manager
type Manager struct {
	policies      map[string]*Runner
	client        diode.Client
	logger        *slog.Logger
	ctx           context.Context
	mappingConfig config.Mapping
	manufacturers data.ManufacturerRetriever
	runStore      *RunStore
}

// NewManager returns a new policy manager
func NewManager(ctx context.Context, logger *slog.Logger, client diode.Client, manufacturers data.ManufacturerRetriever) (*Manager, error) {
	mappingConfig, err := loadMappingConfig()
	if err != nil {
		logger.Error("failed to load mapping config", "error", err)
		return nil, err
	}

	return &Manager{
		ctx:           ctx,
		client:        client,
		logger:        logger,
		mappingConfig: mappingConfig,
		policies:      make(map[string]*Runner),
		manufacturers: manufacturers,
		runStore:      NewRunStore(),
	}, nil
}

// ParsePolicies parses the policies from the request
func (m *Manager) ParsePolicies(data []byte) (map[string]config.Policy, error) {
	var payload config.Policies
	if err := yaml.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	config.WarnUnknownPolicyKeys(data, m.logger)

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
		if err := m.resolveAuthenticationEnvVars(&updatedPolicy); err != nil {
			return nil, fmt.Errorf("%s : failed to resolve environment variables : %w", name, err)
		}
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

	if policy.Config.Defaults.Interface.Type == "" {
		policy.Config.Defaults.Interface.Type = "other"
	}

	if policy.Config.Defaults.Role == "" {
		policy.Config.Defaults.Role = "undefined"
	}

	if policy.Config.Defaults.Site == "" {
		policy.Config.Defaults.Site = defaultSite
	}

	if policy.Config.Options.CreateUnknownVlans == nil {
		trueVal := true
		policy.Config.Options.CreateUnknownVlans = &trueVal
	}

	if src := policy.Config.Options.InterfaceNameSource; src != nil {
		switch *src {
		case config.InterfaceNameSourceAuto, config.InterfaceNameSourceIfName, config.InterfaceNameSourceIfDescr:
			// recognized
		default:
			m.logger.Warn("unknown interface_name_source; using auto", "value", *src)
			policy.Config.Options.InterfaceNameSource = nil // normalize → auto
		}
	}
}

// validateAuthentication validates a single authentication configuration
func (m *Manager) validateAuthentication(auth *config.Authentication, context string) error {
	if auth == nil {
		return fmt.Errorf("%s: authentication is nil", context)
	}

	if auth.ProtocolVersion == "" {
		return fmt.Errorf("%s: missing protocol version", context)
	}

	if auth.ProtocolVersion != "SNMPv1" && auth.ProtocolVersion != "SNMPv2c" && auth.ProtocolVersion != "SNMPv3" {
		return fmt.Errorf("%s: unsupported protocol version", context)
	}

	if auth.ContextName != "" && auth.ProtocolVersion != snmp.ProtocolVersion3 {
		return fmt.Errorf("%s: context_name is only valid for SNMPv3 (got %q)",
			context, auth.ProtocolVersion)
	}

	if auth.ProtocolVersion == "SNMPv2c" || auth.ProtocolVersion == "SNMPv1" {
		if auth.Community == "" {
			return fmt.Errorf("%s: missing community", context)
		}
	}

	if auth.ProtocolVersion == "SNMPv3" {
		if auth.SecurityLevel != "noAuthNoPriv" &&
			auth.SecurityLevel != "authNoPriv" &&
			auth.SecurityLevel != "authPriv" {
			return fmt.Errorf("%s: invalid security level %s", context, auth.SecurityLevel)
		}
		if auth.SecurityLevel == "authNoPriv" || auth.SecurityLevel == "authPriv" {
			if auth.Username == "" {
				return fmt.Errorf("%s: missing username", context)
			}

			if auth.AuthPassphrase == "" {
				return fmt.Errorf("%s: missing auth passphrase", context)
			}

			if auth.AuthProtocol == "" {
				return fmt.Errorf("%s: missing auth protocol", context)
			}
		}
		if auth.SecurityLevel == "authPriv" {
			if auth.PrivPassphrase == "" {
				return fmt.Errorf("%s: missing priv passphrase", context)
			}

			if auth.PrivProtocol == "" {
				return fmt.Errorf("%s: missing priv protocol", context)
			}
		}
	}

	return nil
}

// validatePolicy validates the policy
func (m *Manager) validatePolicy(policy config.Policy) error {
	hasPolicyAuth := policy.Scope.Authentication.ProtocolVersion != ""

	// Validate policy-level auth if present
	if hasPolicyAuth {
		if err := m.validateAuthentication(&policy.Scope.Authentication, "policy-level"); err != nil {
			return err
		}
	} else if policy.Scope.Authentication.ContextName != "" {
		// A scope.authentication block with a context_name but no
		// protocol_version skips the check above entirely (hasPolicyAuth is
		// false), yet it is still env-resolved and then silently discarded
		// for any target with its own authentication block. Catch it here
		// rather than letting it disappear the same way the missing-context
		// bug this ticket exists to fix did.
		return fmt.Errorf("policy-level: context_name is only valid for SNMPv3 (got %q)",
			policy.Scope.Authentication.ProtocolVersion)
	}

	// Validate each target's authentication
	for _, target := range policy.Scope.Targets {
		if target.Authentication != nil {
			// Target has its own auth - validate it
			context := fmt.Sprintf("target %s", target.Host)
			if err := m.validateAuthentication(target.Authentication, context); err != nil {
				return err
			}
		} else if !hasPolicyAuth {
			// Target has no auth and there's no policy-level fallback
			return fmt.Errorf("target %s: no authentication configured and no policy-level fallback available", target.Host)
		}
	}

	// Reject unknown enum values at parse time so operators get an
	// immediate error rather than silently degrading at scan time.
	if policy.Config.Options.DiscoverModules != nil {
		switch *policy.Config.Options.DiscoverModules {
		case config.DiscoverModulesOff, config.DiscoverModulesLinecards, config.DiscoverModulesFull:
		default:
			return fmt.Errorf(
				"invalid options.discover_modules %q (allowed: %s, %s, %s)",
				*policy.Config.Options.DiscoverModules,
				config.DiscoverModulesOff, config.DiscoverModulesLinecards, config.DiscoverModulesFull,
			)
		}
	}

	return validateRackPlacement(policy)
}

// rackUnit is a U and face of a rack, named within a site. The location is
// kept apart, since a target without one may land in any location.
type rackUnit struct {
	site, rack string
	position   float64
	face       string
}

// devicePlacement is what a target sends its device: a rack and, when it
// places the device, a U and face (zero otherwise). location is empty when the
// target has none; oidLocation marks one read from an OID at scan time.
type devicePlacement struct {
	unit        rackUnit
	location    string
	oidLocation bool
}

// pinnedPlacement is what the first target naming a netbox_id sends it.
type pinnedPlacement struct {
	placement devicePlacement
	host      string
}

// validateRackPlacement rejects a position or face NetBox would refuse, or
// that one target cannot describe. Only an upper bound and multi-U overlaps
// are left to NetBox, since they depend on rack and device heights.
func validateRackPlacement(policy config.Policy) error {
	defaults := &policy.Config.Defaults
	if defaults.Position != nil || defaults.RackFace() != "" {
		return errors.New("defaults: position and face are set per target, in override_defaults")
	}
	// Each U maps its locations ("" for none) to the target placed there.
	placedAt := map[rackUnit]map[string]string{}
	pinnedAt := map[int]pinnedPlacement{}
	for _, target := range policy.Scope.Targets {
		override := target.OverrideDefaults
		placed := override != nil && (override.Position != nil || override.RackFace() != "")
		if placed {
			if err := checkTargetPlacement(target, defaults); err != nil {
				return err
			}
		}
		p := placementOf(defaults, override, placed)
		if p.unit.rack == "" {
			continue
		}
		if target.NetboxID != nil && keepsNetboxID(target.Host) {
			seen, err := pinDevice(pinnedAt, target, p)
			if err != nil {
				return err
			}
			if seen {
				continue
			}
		}
		if placed {
			if err := claimUnit(placedAt, target, p); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkTargetPlacement refuses a target's position and face unless set
// together, valid, in a rack, for a single host.
func checkTargetPlacement(target config.Target, defaults *config.Defaults) error {
	override := target.OverrideDefaults
	face := override.RackFace()
	switch {
	case face == "":
		return fmt.Errorf("target %s: override_defaults position needs a face (front or rear)", target.Host)
	case override.Position == nil:
		return fmt.Errorf("target %s: override_defaults face needs a position", target.Host)
	case face != config.RackFaceFront && face != config.RackFaceRear:
		return fmt.Errorf("target %s: override_defaults face %q must be front or rear", target.Host, override.Face)
	// math.Mod is NaN for an infinite or NaN position, so those fail too.
	case *override.Position < 1 || math.Mod(*override.Position, 0.5) != 0:
		return fmt.Errorf("target %s: override_defaults position %v must be 1 or more, in steps of 0.5",
			target.Host, *override.Position)
	case override.RackName() == "" && defaults.RackName() == "":
		return fmt.Errorf("target %s: override_defaults position and face need a rack, in defaults or override_defaults",
			target.Host)
	}
	if coversSeveralAddresses(target.Host) {
		return fmt.Errorf("target %s: position and face need a single host; a range or subnet would place every device at the same U",
			target.Host)
	}
	return nil
}

// placementOf returns what a target sends its device once the policy
// defaults are merged in.
func placementOf(defaults, override *config.Defaults, placed bool) devicePlacement {
	merged := config.MergeDefaults(defaults, override)
	site := merged.Site
	if site == "" {
		site = defaultSite // as applyDefaults fills it in
	}
	p := devicePlacement{
		unit:        rackUnit{site: site, rack: merged.RackName()},
		location:    strings.TrimSpace(merged.Location),
		oidLocation: data.IsOIDReference(merged.Location),
	}
	if placed {
		p.unit.position = *merged.Position
		p.unit.face = merged.RackFace()
	}
	return p
}

// pinDevice records what a netbox_id target sends, refusing something
// different for the same id: the targets update one device, so they must send
// it the same rack, position and face (a rack without a position counts too).
// It reports whether an earlier target already sent this placement.
func pinDevice(pinnedAt map[int]pinnedPlacement, target config.Target, p devicePlacement) (bool, error) {
	prior, ok := pinnedAt[*target.NetboxID]
	if !ok {
		pinnedAt[*target.NetboxID] = pinnedPlacement{placement: p, host: target.Host}
		return false, nil
	}
	// A location read from an OID is only known at scan time, so it cannot
	// be shown to match.
	if prior.placement.oidLocation || p.oidLocation {
		return false, fmt.Errorf("targets %s and %s place netbox_id %d in a location read from an OID; set a literal location",
			prior.host, target.Host, *target.NetboxID)
	}
	if prior.placement != p {
		return false, fmt.Errorf("targets %s and %s place netbox_id %d at different slots",
			prior.host, target.Host, *target.NetboxID)
	}
	return true, nil
}

// claimUnit records the U a target places its device at, refusing one
// another target took. Diode matches a device by rack, position and face once
// name and site miss, so a new device sent to a taken U would update the
// device there.
func claimUnit(placedAt map[rackUnit]map[string]string, target config.Target, p devicePlacement) error {
	// A location read from an OID is only known at scan time, so such a
	// target is left out of the check rather than compared by its OID.
	if p.oidLocation {
		return nil
	}
	taken := placedAt[p.unit]
	if taken == nil {
		taken = map[string]string{}
		placedAt[p.unit] = taken
	}
	// A rack sent without a location binds any rack of that name in the
	// site, so no location clashes with any.
	other, clash := taken[p.location]
	if p.location == "" {
		for _, host := range taken {
			other, clash = host, true
			break
		}
	} else if !clash {
		other, clash = taken[""]
	}
	if clash {
		return fmt.Errorf("targets %s and %s are both placed at %s U%v %s",
			other, target.Host, p.unit.rack, p.unit.position, p.unit.face)
	}
	taken[p.location] = target.Host
	return nil
}

// coversSeveralAddresses reports whether host is a subnet or range of more
// than one address. A CIDR is judged by its prefix length, so a large subnet
// is never listed just to be counted.
func coversSeveralAddresses(host string) bool {
	if p, err := netip.ParsePrefix(host); err == nil {
		return p.Bits() < p.Addr().BitLen()
	}
	hosts, err := targets.Expand(host)
	return err == nil && len(hosts) > 1
}

// keepsNetboxID reports whether the runner applies a target's netbox_id: only
// when the host is written as the single address or name it expands to, so a
// /32 or a one-address range drops it.
func keepsNetboxID(host string) bool {
	if _, err := netip.ParsePrefix(host); err == nil {
		return false
	}
	hosts, err := targets.Expand(host)
	return err == nil && len(hosts) == 1 && hosts[0] == host
}

// HasPolicy checks if the policy exists
func (m *Manager) HasPolicy(name string) bool {
	_, ok := m.policies[name]
	return ok
}

// StartPolicy starts the policy
func (m *Manager) StartPolicy(name string, policy config.Policy) error {
	m.logger.Debug("starting policy", "policy", policy)
	if len(policy.Scope.Targets) == 0 {
		return fmt.Errorf("%s : no targets found in the policy", name)
	}

	if !m.HasPolicy(name) {
		// Load device lookup extensions
		deviceLookup, err := data.LoadDeviceLookupExtensions(policy.Config.LookupExtensionsDir)
		if err != nil {
			m.logger.Warn("failed to load device lookup extensions", "error", err, "directory", policy.Config.LookupExtensionsDir)
		} else {
			m.logReportedExtensionFiles(deviceLookup, policy.Config.LookupExtensionsDir)
		}

		// Build the per-policy manufacturer resolver: the built-in IANA
		// catalog held by the Manager + any manufacturers: blocks in
		// built-in extension files + optional user overrides from
		// policy.Config.LookupExtensionsDir. Per-file YAML parse errors
		// inside the user directory are logged and skipped, so partial
		// overrides still apply. Only a hard construction failure (e.g.
		// the built-in catalog itself being unreadable) falls back to
		// the built-in-only catalog so the policy can still run.
		manufacturerRetriever := m.manufacturers
		if resolver, err := data.NewManufacturerResolver(m.manufacturers, policy.Config.LookupExtensionsDir, m.logger); err != nil {
			m.logger.Warn("failed to load manufacturer overrides", "error", err, "directory", policy.Config.LookupExtensionsDir)
		} else {
			manufacturerRetriever = resolver
		}

		// Create logger-aware ClientFactory wrapper
		clientFactory := func(host string, port uint16, retries int, timeout time.Duration, authentication *config.Authentication, logger *slog.Logger) (snmp.Walker, error) {
			return snmp.NewClient(host, port, retries, timeout, authentication, logger)
		}

		r, err := NewRunner(m.ctx, m.logger, name, policy, m.client, clientFactory, &m.mappingConfig, manufacturerRetriever, deviceLookup, m.runStore)
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

// resolveAuthenticationEnvVarsForAuth resolves environment variables for a single Authentication
func (m *Manager) resolveAuthenticationEnvVarsForAuth(auth *config.Authentication, context string) error {
	if auth == nil {
		return nil
	}

	fields := []struct {
		field *string
		label string
	}{
		{&auth.Community, "community"},
		{&auth.Username, "username"},
		{&auth.AuthPassphrase, "auth_passphrase"},
		{&auth.PrivPassphrase, "priv_passphrase"},
		{&auth.ContextName, "context_name"},
	}

	// Iterate over the fields and resolve environment variables
	for _, f := range fields {
		resolved, err := env.ResolveEnv(*f.field)
		if err != nil {
			return fmt.Errorf("%s: failed to resolve %s environment variable: %w", context, f.label, err)
		}
		*f.field = resolved
	}

	return nil
}

// resolveAuthenticationEnvVars resolves environment variables in authentication configuration
func (m *Manager) resolveAuthenticationEnvVars(policy *config.Policy) error {
	// Resolve policy-level authentication
	if err := m.resolveAuthenticationEnvVarsForAuth(&policy.Scope.Authentication, "policy-level"); err != nil {
		return err
	}

	// Resolve target-level authentication
	for i := range policy.Scope.Targets {
		if policy.Scope.Targets[i].Authentication != nil {
			context := fmt.Sprintf("target %s", policy.Scope.Targets[i].Host)
			if err := m.resolveAuthenticationEnvVarsForAuth(policy.Scope.Targets[i].Authentication, context); err != nil {
				return err
			}
		}
	}

	return nil
}

// Status represents the status of a policy with its runs
type Status struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "unknown" if there are no runs, "running" if any run is in-flight, otherwise the latest run's status
	Runs   []*Run `json:"runs"`
}

// deriveStatus returns "unknown" when runs is empty, "running" if any run is still running,
// and otherwise the latest run's status. Expects runs sorted newest-first, as returned by RunStore.GetRunsForPolicy.
func deriveStatus(runs []*Run) string {
	if len(runs) == 0 {
		return "unknown"
	}
	for _, r := range runs {
		if r.Status == RunStatusRunning {
			return string(RunStatusRunning)
		}
	}
	return string(runs[0].Status)
}

// GetPolicyStatuses returns all policies with their status and runs
func (m *Manager) GetPolicyStatuses() []Status {
	allRuns := m.runStore.GetAllPoliciesWithRuns()

	var statuses []Status

	// Get statuses for all policies that have runners
	for name := range m.policies {
		runs := m.runStore.GetRunsForPolicy(name)
		statuses = append(statuses, Status{
			Name:   name,
			Status: deriveStatus(runs),
			Runs:   runs,
		})
	}

	// Also include policies that have runs but no active runner
	for name, runs := range allRuns {
		if !m.HasPolicy(name) {
			statuses = append(statuses, Status{
				Name:   name,
				Status: deriveStatus(runs),
				Runs:   runs,
			})
		}
	}

	return statuses
}

// logReportedExtensionFiles logs what lookup_extensions_dir actually
// contributed.
//
// The bare "loaded device lookup extensions" message this replaces only proved
// the directory was readable. A file with a wrong top-level key or bad
// indentation parses to zero entries without error, so an operator whose custom
// OID was ignored saw nothing but a success line followed by the model falling
// back to the raw OID (issue #486). Reporting per-file entry counts, and
// warning on the two cases that contribute nothing, makes that self-diagnosing.
func (m *Manager) logReportedExtensionFiles(lookup *data.DeviceLookup, dir string) {
	// Sanitize before any branch uses it, so no path can log the raw value.
	safeDir := sanitizeLogValue(dir)

	files := lookup.UserExtensionFiles()
	if dir == "" {
		m.logger.Info("loaded device lookup extensions", "directory", safeDir)
		return
	}
	if len(files) == 0 {
		// The operator configured a directory and nothing in it was read, so
		// none of their overrides are in effect. Reporting success here is the
		// misleading case this reporting exists to remove.
		m.logger.Warn("lookup_extensions_dir has no .yaml or .yml files; no custom entries were loaded",
			"directory", safeDir, "files_ignored", lookup.UserExtensionSkippedFiles())
		return
	}

	total, mfrTotal, moduleTotal := 0, 0, 0
	for _, f := range files {
		mfrTotal += f.ManufacturerEntries
		moduleTotal += f.ModuleEntries
		if f.ModulesErr != nil {
			m.logger.Warn("lookup extension file has an unparseable modules section; its module entries were skipped",
				"directory", safeDir,
				"file", sanitizeLogValue(f.Name),
				"error", sanitizeLogValue(f.ModulesErr.Error()))
		}
		switch {
		case f.Err != nil:
			// The devices section, or the whole file, could not be read. The
			// counts show what the other sections still contributed.
			m.logger.Warn("lookup extension file has an unparseable devices section; its device entries were skipped",
				"directory", safeDir,
				"file", sanitizeLogValue(f.Name),
				"manufacturer_entries", f.ManufacturerEntries,
				"module_entries", f.ModuleEntries,
				"error", sanitizeLogValue(f.Err.Error()))
		case f.Entries == 0 && f.ManufacturerEntries == 0 && f.ModuleEntries == 0 && f.ModulesErr == nil:
			// Only when no recognised section contributed. A file carrying just
			// a manufacturers: or modules: block declares no devices by design,
			// so warning about it would nag a healthy config.
			m.logger.Warn("lookup extension file contributed no device, manufacturer or module entries; check that it starts with a 'devices:', 'manufacturers:' or 'modules:' key and is indented with spaces",
				"directory", safeDir, "file", sanitizeLogValue(f.Name))
		default:
			total += f.Entries
		}
	}
	m.logger.Info("loaded device lookup extensions",
		"directory", safeDir, "files", len(files),
		"entries", total, "manufacturer_entries", mfrTotal, "module_entries", moduleTotal)
}

// sanitizeLogValue flattens CR and LF so a value cannot forge additional log
// records.
//
// A filename or YAML parse error is operator-supplied and can echo file
// content, and both reach the log. slog's own handlers escape newlines, so this
// is belt and braces there, but it keeps the guarantee in this code rather than
// resting on which handler happens to be installed, and it restores a
// protection the previous logging here applied deliberately.
// Every path runs the replacements. An early return for values that contain no
// newline would be a shortcut from input to output that bypasses them, which
// leaves the value tainted as far as static analysis is concerned and is the
// kind of subtlety worth not being clever about in a sanitizer.
func sanitizeLogValue(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}
