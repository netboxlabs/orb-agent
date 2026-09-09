package config

import (
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// DefaultStackMemberTemplate reproduces the naming snmp-discovery emitted
// before the template existed, so an operator who sets nothing sees no
// change. It is also device-discovery's default, which is what keeps one
// physical stack discovered by both backends on the same NetBox rows.
const DefaultStackMemberTemplate = "{name}-{id}"

// stackTemplatePlaceholders are the only tokens the renderer substitutes.
// {name} is the stack name, {id} the device-reported member id.
var stackTemplatePlaceholders = []string{"name", "id"}

var stackTemplateToken = regexp.MustCompile(`\{([^{}]*)\}`)

// RenderStackMemberName renders a member name by bounded token replacement.
//
// Deliberately not a format string: an operator template is data, and the
// only substitutions it can ask for are the two placeholders below. This
// mirrors device-discovery's renderer, which avoids str.format for the same
// reason, so a template that behaves one way there behaves the same here.
// An empty template means the caller expressed no preference, and is
// resolved here rather than at each call site: this is the one point every
// member name passes through, and a caller that forgot would otherwise emit
// a Device with an empty name, which NetBox cannot match on at all.
func RenderStackMemberName(template, name string, memberID int) string {
	if template == "" {
		template = DefaultStackMemberTemplate
	}
	r := strings.NewReplacer("{name}", name, "{id}", strconv.Itoa(memberID))
	return r.Replace(template)
}

// StackMemberTemplateProblem returns why a template is unusable, or "" when
// it is fine. The rules match device-discovery's exactly, because an
// operator may reasonably paste the same template into both backends and a
// template accepted by one and refused by the other would name the same
// stack two different ways.
func StackMemberTemplateProblem(template string) string {
	if strings.TrimSpace(template) == "" {
		return "template is empty"
	}
	tokens := stackTemplateToken.FindAllStringSubmatch(template, -1)
	sawName := false
	for _, m := range tokens {
		tok := m[1]
		if strings.ContainsAny(tok, ".[:") {
			return "disallowed placeholder {" + tok + "}"
		}
		if !slices.Contains(stackTemplatePlaceholders, tok) {
			return "unknown placeholder {" + tok + "}"
		}
		if tok == "name" {
			sawName = true
		}
	}
	if !sawName {
		// Without it, two stacks in one site produce identical member
		// names and collapse onto each other's NetBox rows.
		return "template must include the {name} placeholder"
	}
	// The token regexp only matches balanced pairs, so "{name}-{id}}" and
	// "{{name}-{id}" pass the checks above yet leave a literal brace in the
	// rendered name. Substituting the allowed placeholders and looking for
	// a residual brace catches both.
	residual := strings.NewReplacer("{name}", "", "{id}", "").Replace(template)
	if strings.ContainsAny(residual, "{}") {
		return "template has stray or unbalanced braces"
	}
	if RenderStackMemberName(template, "vc", 1) == RenderStackMemberName(template, "vc", 2) {
		return "template does not vary by member {id}"
	}
	return ""
}

// NormalizeStackMemberTemplate returns the template to use, falling back to
// the default with a warning rather than rejecting the policy. A naming
// preference is not worth refusing to discover a device over, and the
// fallback is the naming that shipped before the option existed.
func NormalizeStackMemberTemplate(template string, logger *slog.Logger) string {
	if template == "" {
		return DefaultStackMemberTemplate
	}
	if problem := StackMemberTemplateProblem(template); problem != "" {
		if logger != nil {
			logger.Warn("ignoring stack_member_name_template; using the default",
				"template", template, "problem", problem, "default", DefaultStackMemberTemplate)
		}
		return DefaultStackMemberTemplate
	}
	return template
}
