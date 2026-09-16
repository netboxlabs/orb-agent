package config_test

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

func TestRenderStackMemberName(t *testing.T) {
	assert.Equal(t, "core-sw-2", config.RenderStackMemberName("{name}-{id}", "core-sw", 2))
	assert.Equal(t, "core-sw-css2", config.RenderStackMemberName("{name}-css{id}", "core-sw", 2))
	assert.Equal(t, "2.core-sw", config.RenderStackMemberName("{id}.{name}", "core-sw", 2),
		"placeholders may appear in any order")
	assert.Equal(t, "core-sw-2-core-sw", config.RenderStackMemberName("{name}-{id}-{name}", "core-sw", 2),
		"and more than once")

	// An empty template resolves here rather than emitting a nameless
	// Device, which NetBox could not match on at all.
	assert.Equal(t, "core-sw-2", config.RenderStackMemberName("", "core-sw", 2))

	// Substitution is single-pass: a name that itself looks like a
	// placeholder is data, not a template. This is the one input where this
	// backend and device-discovery differ, deliberately — see the renderer's
	// comment. device-discovery chains replaces and renders "2-2" here.
	assert.Equal(t, "{id}-2", config.RenderStackMemberName("{name}-{id}", "{id}", 2),
		"a substituted value is never itself expanded")
}

// TestStackMemberTemplateProblem mirrors device-discovery's rules exactly.
// An operator may paste the same template into both backends, and one that
// is accepted by one and refused by the other would name the same stack two
// different ways.
func TestStackMemberTemplateProblem(t *testing.T) {
	for _, tmpl := range []string{
		"{name}-{id}",
		"{name}-css{id}",
		"{id}.{name}",
		"sw-{name}-{id}-eu",
	} {
		assert.Empty(t, config.StackMemberTemplateProblem(tmpl), "template %q must be accepted", tmpl)
	}

	for tmpl, want := range map[string]string{
		"":                 "template is empty",
		"   ":              "template is empty",
		"{name}-{ident}":   "unknown placeholder {ident}",
		"{name}-{id.real}": "disallowed placeholder {id.real}",
		"{name}-{id[0]}":   "disallowed placeholder {id[0]}",
		"{name}-{id:>4}":   "disallowed placeholder {id:>4}",
		"{id}-only":        "template must include the {name} placeholder",
		"{name}-{id}}":     "template has stray or unbalanced braces",
		"{{name}-{id}":     "template has stray or unbalanced braces",
		"{name}-fixed":     "template does not vary by member {id}",
	} {
		assert.Equal(t, want, config.StackMemberTemplateProblem(tmpl), "template %q", tmpl)
	}
}

// TestNormalizeStackMemberTemplate pins that a naming preference never
// costs discovery: an unusable template falls back to the shipped naming
// rather than rejecting the policy.
func TestNormalizeStackMemberTemplate(t *testing.T) {
	logger := slog.Default()
	assert.Equal(t, "{name}-css{id}", config.NormalizeStackMemberTemplate("{name}-css{id}", logger))
	assert.Equal(t, config.DefaultStackMemberTemplate, config.NormalizeStackMemberTemplate("", logger))
	assert.Equal(t, config.DefaultStackMemberTemplate, config.NormalizeStackMemberTemplate("{name}-{bogus}", logger),
		"an unusable template falls back rather than failing the policy")
	assert.NotPanics(t, func() {
		config.NormalizeStackMemberTemplate("{name}-{bogus}", nil)
	}, "a nil logger must not panic; some callers have none")
}
