package pktvisor

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"

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

// removeUnusedTaps deletes the managed taps no policy uses. pktvisor's tap
// DELETE detaches the tap from every policy, so it runs only for a tap the
// policy list does not mention. Failures are logged and leave the taps for
// the next removal.
func (p *pktvisorBackend) removeUnusedTaps() {
	var taps map[string]tapInfo
	if err := backend.CommonRequest("pktvisor", p.proc, p.logger, p.apiURL("/api/v1/taps"), &taps,
		http.MethodGet, http.NoBody, "application/json", tapsTimeout, "error"); err != nil {
		p.logger.Warn("pktvisor tap cleanup: listing taps failed", "error", err)
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

	var pols map[string]struct {
		Taps map[string]any `json:"taps"`
	}
	if err := backend.CommonRequest("pktvisor", p.proc, p.logger, p.apiURL("/api/v1/policies"), &pols,
		http.MethodGet, http.NoBody, "application/json", tapsTimeout, "error"); err != nil {
		p.logger.Warn("pktvisor tap cleanup: listing policies failed", "error", err)
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
