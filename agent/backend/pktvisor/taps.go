package pktvisor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
)

// managedTapPrefix starts the name of every tap the agent creates and manages.
const managedTapPrefix = "fleet_"

// managedInputTypes lists the input types the agent creates taps for.
var managedInputTypes = []string{"flow", "netprobe"}

// policyNameRE is the name format pktvisor accepts for modules and policies.
var policyNameRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)

// managedTapName returns the name of the managed tap for an input type.
func managedTapName(inputType string) string {
	return managedTapPrefix + inputType
}

// checkPolicyName refuses a policy name pktvisor would not accept.
func checkPolicyName(name string) error {
	if !policyNameRE.MatchString(name) {
		return fmt.Errorf("pktvisor policy name %q must match [a-zA-Z_][a-zA-Z0-9_-]*", name)
	}
	return nil
}

// managedTapType returns the input type whose managed tap the body needs, or
// "" when the body names its own tap.
func managedTapType(body any) (string, error) {
	doc, _ := body.(map[string]any)
	input, ok := doc["input"].(map[string]any)
	if !ok {
		return "", errors.New("pktvisor policy has no input section")
	}

	if tap, present := input["tap"]; present && tap != nil && tap != "" {
		name, isString := tap.(string)
		if !isString {
			return "", errors.New("pktvisor policy input.tap must be a tap name")
		}
		if strings.HasPrefix(name, managedTapPrefix) {
			return "", fmt.Errorf("tap %q: names starting with %q are reserved for taps the agent manages; leave input.tap out to use one", name, managedTapPrefix)
		}
		return "", nil
	}
	if sel, present := input["tap_selector"]; present && sel != nil {
		return "", nil
	}

	inputType, _ := input["input_type"].(string)
	if inputType == "" {
		return "", errors.New("pktvisor policy names no tap, so it must set input.input_type")
	}
	if !slices.Contains(managedInputTypes, inputType) {
		msg := fmt.Sprintf("pktvisor policy with input_type %q must name a tap in input.tap or input.tap_selector; the agent creates taps only for netprobe and flow", inputType)
		if inputType == "sflow" {
			msg += " (for sFlow, use input_type flow)"
		}
		return "", errors.New(msg)
	}
	return inputType, nil
}

// tapInfo is one entry of pktvisor's tap list. pktvisor reports null for the
// config and tags of a tap created without them.
type tapInfo struct {
	InputType string         `json:"input_type"`
	Config    map[string]any `json:"config"`
	Tags      map[string]any `json:"tags"`
}

// ownManagedTap reports whether a tap is one the agent creates: a managed
// name, the matching input type and nothing else set. A tap that merely
// carries a managed name, such as one from the config file, is not the
// agent's to delete.
func ownManagedTap(name string, info tapInfo) bool {
	for _, t := range managedInputTypes {
		if name == managedTapName(t) {
			return info.InputType == t && len(info.Config) == 0 && len(info.Tags) == 0
		}
	}
	return false
}

// keepTap marks a managed tap that cleanup must not delete.
func (p *pktvisorBackend) keepTap(tap string) {
	p.keptMu.Lock()
	defer p.keptMu.Unlock()
	if p.keptTaps == nil {
		p.keptTaps = map[string]bool{}
	}
	p.keptTaps[tap] = true
}

// isKept reports whether keepTap marked the tap.
func (p *pktvisorBackend) isKept(tap string) bool {
	p.keptMu.Lock()
	defer p.keptMu.Unlock()
	return p.keptTaps[tap]
}

// clearKeptTaps drops every mark.
func (p *pktvisorBackend) clearKeptTaps() {
	p.keptMu.Lock()
	defer p.keptMu.Unlock()
	p.keptTaps = nil
}

// apiURL returns the admin API address for a path.
func (p *pktvisorBackend) apiURL(path string) string {
	return fmt.Sprintf("%s://%s%s", p.adminAPIProtocol, net.JoinHostPort(p.adminAPIHost, p.adminAPIPort.Get()), path)
}

// withTap returns a copy of the policy body that names the tap. It copies only
// what it changes, the body and its input section, and drops a null
// tap_selector: pktvisor counts a null key as present and refuses the policy.
func withTap(body map[string]any, tap string) map[string]any {
	out := maps.Clone(body)
	input, _ := body["input"].(map[string]any)
	newInput := maps.Clone(input)
	newInput["tap"] = tap
	if sel, present := newInput["tap_selector"]; present && sel == nil {
		delete(newInput, "tap_selector")
	}
	out["input"] = newInput
	return out
}

// ensureTap creates the managed tap for an input type, or accepts the one
// already there when it is the agent's own.
func (p *pktvisorBackend) ensureTap(inputType string) error {
	name := managedTapName(inputType)
	doc, err := yaml.Marshal(map[string]any{
		"version": "1.0",
		"visor": map[string]any{
			"taps": map[string]any{
				name: map[string]any{"input_type": inputType},
			},
		},
	})
	if err != nil {
		return err
	}

	var created any
	err = backend.CommonRequest("pktvisor", p.proc, p.logger, p.apiURL("/api/v1/taps"), &created,
		http.MethodPost, bytes.NewBuffer(doc), "application/x-yaml", tapsTimeout, "error")
	if err == nil {
		return nil
	}
	var httpErr *backend.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusConflict {
		return fmt.Errorf("creating tap %q: %w", name, err)
	}

	// The name is taken. Fetch raw and decode strictly: CommonRequest's YAML
	// fallback can report success for a body that does not fit the target.
	var raw json.RawMessage
	if err := backend.CommonRequest("pktvisor", p.proc, p.logger, p.apiURL("/api/v1/taps/"+name), &raw,
		http.MethodGet, http.NoBody, "application/json", tapsTimeout, "error"); err != nil {
		return fmt.Errorf("reading tap %q: %w", name, err)
	}
	var taps map[string]tapInfo
	if err := json.Unmarshal(raw, &taps); err != nil {
		return fmt.Errorf("reading tap %q: reply did not decode: %w", name, err)
	}
	info, ok := taps[name]
	if !ok {
		return fmt.Errorf("reading tap %q: reply does not hold it", name)
	}
	if !ownManagedTap(name, info) {
		return fmt.Errorf("tap %q exists but is not one the agent manages (input_type %q, config set: %t)",
			name, info.InputType, len(info.Config) > 0)
	}
	return nil
}

// removeUnusedTaps deletes the managed taps no policy uses. pktvisor's tap
// DELETE detaches the tap from every policy, so it runs only for a tap the
// policy list does not mention. Failures are logged and leave the taps for
// the next removal.
func (p *pktvisorBackend) removeUnusedTaps() {
	// Fetch raw and decode here: CommonRequest's YAML fallback can report
	// success for a body that does not fit the target, which for the policy
	// list would read as "no policy uses any tap".
	var rawTaps json.RawMessage
	if err := backend.CommonRequest("pktvisor", p.proc, p.logger, p.apiURL("/api/v1/taps"), &rawTaps,
		http.MethodGet, http.NoBody, "application/json", tapsTimeout, "error"); err != nil {
		p.logger.Warn("pktvisor tap cleanup: listing taps failed", "error", err)
		return
	}
	// pktvisor answers null when it has no taps, which CommonRequest leaves
	// as an empty raw message. An empty tap list has no candidates, so there
	// is nothing to clean up and nothing to fail closed about.
	if len(rawTaps) == 0 {
		return
	}
	var taps map[string]tapInfo
	if err := json.Unmarshal(rawTaps, &taps); err != nil {
		p.logger.Warn("pktvisor tap cleanup: tap list did not decode", "error", err)
		return
	}
	var candidates []string
	for name, info := range taps {
		if ownManagedTap(name, info) && !p.isKept(name) {
			candidates = append(candidates, name)
		}
	}
	if len(candidates) == 0 {
		return
	}
	slices.Sort(candidates)

	var rawPols json.RawMessage
	if err := backend.CommonRequest("pktvisor", p.proc, p.logger, p.apiURL("/api/v1/policies"), &rawPols,
		http.MethodGet, http.NoBody, "application/json", tapsTimeout, "error"); err != nil {
		p.logger.Warn("pktvisor tap cleanup: listing policies failed", "error", err)
		return
	}
	// pktvisor always answers an object here, {} when it has no policies, so
	// null or a body that does not decode must not read as "no policy uses a
	// tap": the DELETE detaches the tap from every policy.
	var pols map[string]struct {
		Taps map[string]any `json:"taps"`
	}
	if err := json.Unmarshal(rawPols, &pols); err != nil || pols == nil {
		p.logger.Warn("pktvisor tap cleanup: policy list did not decode", "error", err)
		return
	}
	used := map[string]bool{}
	for _, pol := range pols {
		for tap := range pol.Taps {
			used[tap] = true
		}
	}

	for _, name := range candidates {
		if used[name] {
			continue
		}
		var resp any
		err := backend.CommonRequest("pktvisor", p.proc, p.logger, p.apiURL("/api/v1/taps/"+name), &resp,
			http.MethodDelete, http.NoBody, "application/json", tapsTimeout, "error")
		var httpErr *backend.HTTPError
		if err != nil && (!errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound) {
			p.logger.Warn("pktvisor tap cleanup: deleting tap failed", "tap", name, "error", err)
		}
	}
}
