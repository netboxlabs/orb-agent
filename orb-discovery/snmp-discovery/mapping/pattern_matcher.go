package mapping

import (
	"fmt"
	"log/slog"
	"regexp"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
)

// CompiledPattern wraps a pattern with its pre-compiled regex
type CompiledPattern struct {
	Pattern *regexp.Regexp
	Type    string
}

// PatternMatcher handles interface name pattern matching with caching
type PatternMatcher struct {
	compiledPatterns []CompiledPattern
	logger           *slog.Logger
}

// NewPatternMatcher creates a PatternMatcher with pre-compiled patterns
func NewPatternMatcher(patterns []config.InterfacePattern, logger *slog.Logger) (*PatternMatcher, error) {
	compiled := make([]CompiledPattern, 0, len(patterns))

	for i, pattern := range patterns {
		regex, err := regexp.Compile(pattern.Match)
		if err != nil {
			return nil, fmt.Errorf("failed to compile pattern %d ('%s'): %w", i, pattern.Match, err)
		}
		compiled = append(compiled, CompiledPattern{
			Pattern: regex,
			Type:    pattern.Type,
		})
	}

	return &PatternMatcher{
		compiledPatterns: compiled,
		logger:           logger,
	}, nil
}

// MatchInterfaceType matches interface name against patterns with priority-aware logic
// Returns matched type or empty string if no match
func (pm *PatternMatcher) MatchInterfaceType(interfaceName string, userPatternCount int) string {
	if len(pm.compiledPatterns) == 0 {
		return ""
	}

	// Separate user patterns from built-in patterns
	userPatterns := pm.compiledPatterns[:userPatternCount]
	builtinPatterns := pm.compiledPatterns[userPatternCount:]

	// Priority 1: Check user patterns first
	if len(userPatterns) > 0 {
		if matchedType := pm.findBestMatch(interfaceName, userPatterns); matchedType != "" {
			pm.logger.Debug("Matched interface with user pattern",
				"interface", interfaceName,
				"type", matchedType)
			return matchedType
		}
	}

	// Priority 2: Check built-in patterns only if no user pattern matched
	if matchedType := pm.findBestMatch(interfaceName, builtinPatterns); matchedType != "" {
		pm.logger.Debug("Matched interface with built-in pattern",
			"interface", interfaceName,
			"type", matchedType)
		return matchedType
	}

	return ""
}

// findBestMatch finds the most specific (longest) match in a pattern list
func (pm *PatternMatcher) findBestMatch(interfaceName string, patterns []CompiledPattern) string {
	bestMatchLength := 0
	bestMatchType := ""

	for _, compiled := range patterns {
		match := compiled.Pattern.FindString(interfaceName)
		if match != "" {
			matchLength := len(match)
			if matchLength > bestMatchLength {
				bestMatchLength = matchLength
				bestMatchType = compiled.Type
			}
		}
	}

	return bestMatchType
}

// MergePatterns merges user patterns with built-in defaults
// User patterns always come first (highest priority)
func MergePatterns(userPatterns []config.InterfacePattern, includeDefaults bool) []config.InterfacePattern {
	if !includeDefaults {
		return userPatterns
	}

	merged := make([]config.InterfacePattern, 0, len(userPatterns)+len(DefaultInterfacePatterns))

	// User patterns first (highest priority)
	if len(userPatterns) > 0 {
		merged = append(merged, userPatterns...)
	}

	// Built-in patterns as fallback
	merged = append(merged, DefaultInterfacePatterns...)

	return merged
}
