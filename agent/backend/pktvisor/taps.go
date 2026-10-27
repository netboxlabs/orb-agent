package pktvisor

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
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
