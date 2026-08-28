package config

import (
	"bytes"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureWarnings(t *testing.T, yamlText string) string {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	WarnUnknownPolicyKeys([]byte(yamlText), logger)
	return buf.String()
}

// A key written at config level instead of config.options is reported with the
// path it belongs at. This is the shape that made a real report unreproducible:
// the key is dropped, the option stays off, and the emitted entity count is
// identical with and without it.
func TestMisplacedOptionNamesTheCorrectPath(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      capture_config: true
      defaults:
        site: s
    scope:
      targets:
        - host: 10.0.0.1
`)
	require.Contains(t, out, "capture_config")
	require.Contains(t, out, "options.capture_config", "the warning must name the path the key belongs at")
}

func TestUnknownKeyReportedWithoutSuggestion(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      totally_made_up_key: 42
    scope:
      targets:
        - host: 10.0.0.1
`)
	require.Contains(t, out, "totally_made_up_key")
	assert.NotContains(t, out, "did_you_mean", "a key matching nothing must not get an invented suggestion")
}

func TestUnknownKeyInsideOptionsIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      options:
        capture_config: true
        nope_option: 1
    scope:
      targets:
        - host: 10.0.0.1
`)
	require.Contains(t, out, "nope_option")
}

// `capture config: true` is a valid YAML mapping key, and yaml.v3 reports it
// with the space intact. Requiring a single non-whitespace token skipped the
// entry, hiding the very mistake this warning exists to surface.
func TestKeyContainingWhitespaceIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      bogus key: 1
    scope:
      targets:
        - host: 10.0.0.1
`)
	require.Contains(t, out, "bogus key")
}

// Blocks that are not a closed, documented set stay silent. Policy names and the
// surrounding agent config are operator-chosen, so warning on them would fire on
// correct files and train operators to ignore the warning.
func TestBlocksWithOperatorChosenKeysStaySilent(t *testing.T) {
	out := captureWarnings(t, `
policies:
  a_policy_name_nobody_can_predict:
    scope:
      targets:
        - host: 10.0.0.1
`)
	assert.Empty(t, out, "expected silence outside the narrowed blocks")
}

// A key written at the wrong indent level lands in a neighbouring block, where
// the permissive decode drops it and the feature it configures never turns on.
// This is the mistake a copied sample propagates.
func TestAKeyInTheWrongBlockIsReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      defaults:
        site: New York NY
        rescan_interval_ms: 3600000
    scope:
      targets:
        - host: 10.0.0.1
`)
	assert.Contains(t, out, "rescan_interval_ms")
}

// A typo inside a defaults block silently ships the built-in value instead of
// the operator's.
func TestMisspelledDefaultsKeysAreReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      defaults:
        rol: Router
        device:
          manufacurer: Acme
        interface:
          if_typ: other
    scope:
      targets:
        - host: 10.0.0.1
`)
	assert.Contains(t, out, "rol")
	assert.Contains(t, out, "manufacurer")
	assert.Contains(t, out, "if_typ")
}

// A misspelled scope credential is the expensive one: the permissive decode
// drops it, and every target in the range then authenticates with no username at
// all — a whole subnet failing for a reason nothing else reports.
func TestMisspelledScopeAndTargetKeysAreReported(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    scope:
      usernme: admin
      targets:
        - host: 10.0.0.1
          passwrd: hunter2
          tls:
            skip_verfy: true
`)
	assert.Contains(t, out, "usernme")
	assert.Contains(t, out, "passwrd")
	assert.Contains(t, out, "skip_verfy")
}

func TestValidPolicyIsSilent(t *testing.T) {
	out := captureWarnings(t, `
policies:
  p1:
    config:
      mode: subscribe
      options:
        capture_config: true
      defaults:
        site: s
    scope:
      targets:
        - host: 10.0.0.1
`)
	assert.Empty(t, out, "a valid policy must not warn")
}

func TestMalformedYamlIsLeftToThePermissiveDecode(t *testing.T) {
	out := captureWarnings(t, "policies: [this is not a map")
	assert.Empty(t, out, "syntax errors are reported by the real decode")
}

func TestNilLoggerIsSafe(t *testing.T) {
	assert.NotPanics(t, func() {
		WarnUnknownPolicyKeys([]byte("policies:\n  p1:\n    config:\n      bogus: 1\n"), nil)
	})
}

// A bare `tls:` reads as "no TLS settings here" and means the opposite: a null
// node unmarshals to the nil that signals inheritance, so the target silently
// picks up the scope's block — skip_verify, CA path and all.
func TestBareTLSKeyIsReported(t *testing.T) {
	out := captureNullKeyWarnings(t, `
policies:
  p1:
    scope:
      tls:
        skip_verify: true
      targets:
        - host: 10.0.0.1
          tls:
        - host: 10.0.0.2
`)
	assert.Contains(t, out, "10.0.0.1")
	assert.NotContains(t, out, "10.0.0.2", "an absent tls key is the normal way to inherit")
}

func TestFilledTLSBlocksAreSilent(t *testing.T) {
	out := captureNullKeyWarnings(t, `
policies:
  p1:
    scope:
      targets:
        - host: 10.0.0.1
          tls:
            insecure: true
`)
	assert.Empty(t, out)
}

func captureNullKeyWarnings(t *testing.T, doc string) string {
	t.Helper()
	var buf bytes.Buffer
	WarnAmbiguousNullKeys([]byte(doc), slog.New(slog.NewTextHandler(&buf, nil)))
	return buf.String()
}

// yaml.v3 gives `username:` and `username: null` the same nil pointer an omitted
// key produces, so a bare credential key reads as "no username" and silently
// does the opposite: it inherits the scope's. Only an empty string is present.
func TestBareCredentialKeysAreReported(t *testing.T) {
	out := captureNullKeyWarnings(t, `
policies:
  p1:
    scope:
      username: admin
      password: campus-secret
      targets:
        - host: 10.0.0.1
          username:
        - host: 10.0.0.2
          password: null
        - host: 10.0.0.3
          username: ""
        - host: 10.0.0.4
`)
	assert.Contains(t, out, "10.0.0.1")
	assert.Contains(t, out, "empty username key")
	assert.Contains(t, out, "10.0.0.2")
	assert.Contains(t, out, "empty password key")
	assert.NotContains(t, out, "10.0.0.3", `username: "" is present, and does what it says`)
	assert.NotContains(t, out, "10.0.0.4", "an absent key is the normal way to inherit")
}

// Anchors and merge keys are ordinary YAML, and the decoder honours them. A
// walker that matched only literal keys went blind on any policy using them: a
// target inheriting `username: null` through a merge decodes to the same nil as
// one that wrote it directly, so it silently took the scope's credential while
// the direct one was warned about.
func TestNullCredentialsInheritedThroughAMergeAreReported(t *testing.T) {
	out := captureNullKeyWarnings(t, `
policies:
  p1:
    scope:
      username: admin
      password: campus-secret
      targets:
        - &anon
          host: 10.0.0.1
          username: null
        - <<: *anon
          host: 10.0.0.2
        - host: 10.0.0.3
`)
	assert.Contains(t, out, "10.0.0.1", "the direct null")
	assert.Contains(t, out, "10.0.0.2", "the same null reached through a merge")
	assert.NotContains(t, out, "10.0.0.3", "a target that inherits normally is silent")
}

// An explicit key beats a merged one, which is YAML's own precedence rule.
func TestAnExplicitKeyOverridesAMergedNull(t *testing.T) {
	out := captureNullKeyWarnings(t, `
policies:
  p1:
    scope:
      username: admin
      targets:
        - &base
          host: 10.0.0.1
          username: null
        - <<: *base
          host: 10.0.0.2
          username: legacy
`)
	assert.Contains(t, out, "10.0.0.1")
	assert.NotContains(t, out, "10.0.0.2", "the explicit username wins over the merged null")
}

// A whole target supplied as an alias is still walked.
func TestATargetSuppliedAsAnAliasIsWalked(t *testing.T) {
	out := captureNullKeyWarnings(t, `
policies:
  p1:
    scope:
      username: admin
      targets:
        - &whole
          host: 10.0.0.1
          tls:
        - *whole
`)
	assert.Contains(t, out, "10.0.0.1")
	assert.Contains(t, out, "tls block")
}

// A policies map may itself import entries with `<<`. The decoder brings them in
// normally, so a merged policy's targets are live — and reading policies.Content
// directly visited the merge key instead of the policies it imported, so those
// targets were never walked at all.
func TestPoliciesImportedThroughAMergeAreWalked(t *testing.T) {
	out := captureNullKeyWarnings(t, `
shared: &shared
  p1:
    scope:
      username: admin
      password: campus-secret
      targets:
        - host: 10.0.0.1
          username: null
policies:
  <<: *shared
  p2:
    scope:
      username: admin
      targets:
        - host: 10.0.0.2
          username: null
`)
	assert.Contains(t, out, "10.0.0.1", "the merged policy's target")
	assert.Contains(t, out, "10.0.0.2", "the literal policy's target")
}

// An explicit policy name beats a merged one of the same name, which is YAML's
// own rule and therefore what the decoder will use.
func TestAnExplicitPolicyOverridesAMergedOneOfTheSameName(t *testing.T) {
	out := captureNullKeyWarnings(t, `
shared: &shared
  p1:
    scope:
      username: admin
      targets:
        - host: 10.0.0.1
          username: null
policies:
  <<: *shared
  p1:
    scope:
      targets:
        - host: 10.9.9.9
`)
	assert.NotContains(t, out, "10.0.0.1", "the merged p1 is shadowed and never applied")
	assert.NotContains(t, out, "10.9.9.9", "the winning p1 has nothing to warn about")
}

// A self-referential merge must not take the walker down with it. yaml.v3
// rejects most of these before this code runs, but the walker reads
// operator-supplied input and should not be what overflows the stack.
func TestASelfReferentialMergeTerminates(t *testing.T) {
	done := make(chan string, 1)
	go func() {
		done <- captureNullKeyWarnings(t, `
policies: &loop
  <<: *loop
  p1:
    scope:
      targets:
        - host: 10.0.0.1
`)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WarnAmbiguousNullKeys did not terminate on a self-referential merge")
	}
}

// origin is the fourth inheritable pointer field and was the one left out of this
// check. A target meant to use origin-less paths writes `origin: ""`; a bare
// `origin:` decodes to the same nil an omitted key produces, so it takes the
// scope's vendor origin instead and the device then rejects its Subscribe or Get
// paths, with nothing connecting that back to the policy.
func TestABareOriginKeyIsReported(t *testing.T) {
	out := captureNullKeyWarnings(t, `
policies:
  p1:
    scope:
      origin: srl_nokia
      targets:
        - host: 10.0.0.1
          origin:
        - host: 10.0.0.2
          origin: null
        - host: 10.0.0.3
          origin: ""
        - host: 10.0.0.4
`)
	assert.Contains(t, out, "10.0.0.1")
	assert.Contains(t, out, "10.0.0.2")
	assert.Contains(t, out, "empty origin key")
	// slog escapes the quotes in its own output, so match the stable half.
	assert.Contains(t, out, "for origin-less paths")
	assert.NotContains(t, out, "10.0.0.3", `origin: "" is present and means what it says`)
	assert.NotContains(t, out, "10.0.0.4", "an absent key is the normal way to inherit")
}

// Each field's guidance says what "" means for that field, since it is not the
// same thing for a credential and for a path origin.
func TestNullKeyGuidanceIsPerField(t *testing.T) {
	out := captureNullKeyWarnings(t, `
policies:
  p1:
    scope:
      username: admin
      origin: srl_nokia
      targets:
        - host: 10.0.0.1
          username:
          origin:
`)
	assert.Contains(t, out, "to connect without one")
	assert.Contains(t, out, "for origin-less paths")
}
