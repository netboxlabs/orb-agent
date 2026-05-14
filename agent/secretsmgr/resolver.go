package secretsmgr

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

// cachedSecret is a value cached during placeholder resolution, plus the set of
// policy IDs that referenced it. Used by providers that poll for change
// detection (vault, delinea).
type cachedSecret struct {
	Value     string
	policyIDs map[string]bool
}

// resolverFunc returns the resolved value for a single placeholder body
// (the substring between "<scheme>://" and the closing "}"). policyID is the
// policy that triggered the lookup; the resolver is expected to record it for
// later change-tracking.
type resolverFunc func(body, policyID string) (string, error)

// processValue walks v and, for any string leaf that contains a
// ${<scheme>://<body>} placeholder, returns the value produced by
// resolve(body, policyID) in place of that string. The placeholder must be
// the whole string value — surrounding text and additional placeholders are
// not substituted (only the first match is resolved and replaces the entire
// string). Map/slice leaves are walked recursively; other values pass
// through unchanged.
func processValue(v any, scheme, policyID string, resolve resolverFunc) (any, error) {
	switch val := v.(type) {
	case string:
		return processString(val, scheme, policyID, resolve)
	case map[string]any:
		return processMap(val, scheme, policyID, resolve)
	case []any:
		return processSlice(val, scheme, policyID, resolve)
	default:
		return val, nil
	}
}

func processString(s, scheme, policyID string, resolve resolverFunc) (string, error) {
	re := regexp.MustCompile(`\${` + regexp.QuoteMeta(scheme) + `://([^}]+)}`)
	if !re.MatchString(s) {
		return s, nil
	}

	match := re.FindStringSubmatchIndex(s)
	if len(match) < 4 {
		return "", fmt.Errorf("failed to find %s reference in string: %s", scheme, s)
	}

	body := s[match[2]:match[3]]
	return resolve(body, policyID)
}

func processMap(m map[string]any, scheme, policyID string, resolve resolverFunc) (map[string]any, error) {
	result := make(map[string]any)
	for key, val := range m {
		processed, err := processValue(val, scheme, policyID, resolve)
		if err != nil {
			return nil, fmt.Errorf("failed to process value for key %s: %w", key, err)
		}
		result[key] = processed
	}
	return result, nil
}

func processSlice(s []any, scheme, policyID string, resolve resolverFunc) ([]any, error) {
	result := make([]any, len(s))
	for i, val := range s {
		processed, err := processValue(val, scheme, policyID, resolve)
		if err != nil {
			return nil, fmt.Errorf("failed to process value at index %d: %w", i, err)
		}
		result[i] = processed
	}
	return result, nil
}

// structToMap converts any struct to a map[string]any via YAML round-trip.
func structToMap(input any) (map[string]any, error) {
	data, err := yaml.Marshal(input)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// mapToStruct converts a map[string]any back into a struct of type T via YAML.
func mapToStruct[T any](input any) (T, error) {
	data, err := yaml.Marshal(input)
	if err != nil {
		return *new(T), err
	}
	var result T
	if err := yaml.Unmarshal(data, &result); err != nil {
		return *new(T), err
	}
	return result, nil
}
