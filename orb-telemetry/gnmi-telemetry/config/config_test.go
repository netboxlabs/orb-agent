package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func strp(s string) *string { return &s }

func TestEffectiveTargetInheritsScopeAndKeepsOverrides(t *testing.T) {
	scope := Scope{Username: "scope-user", Password: "scope-pass", Port: 57400, Origin: strp(""), TLS: &TLSConfig{SkipVerify: true}}
	plain := EffectiveTarget(scope, Target{Host: "10.0.0.1"})
	assert.Equal(t, "scope-user", plain.ResolvedUsername())
	assert.Equal(t, "scope-pass", plain.ResolvedPassword())
	assert.Equal(t, uint16(57400), plain.Port)
	assert.Equal(t, "", plain.ResolvedOrigin(), "an explicit empty scope origin means the native schema")
	assert.True(t, plain.ResolvedTLS().SkipVerify)

	own := EffectiveTarget(scope, Target{Host: "10.0.0.2", Username: strp("u2"), Password: strp(""), Port: 6030, Origin: strp("openconfig"), TLS: &TLSConfig{CAFile: "/ca.pem"}})
	assert.Equal(t, "u2", own.ResolvedUsername())
	assert.Equal(t, "", own.ResolvedPassword(), "an explicit empty target password is kept, not inherited")
	assert.Equal(t, uint16(6030), own.Port)
	assert.Equal(t, "openconfig", own.ResolvedOrigin())
	assert.Equal(t, TLSConfig{CAFile: "/ca.pem"}, own.ResolvedTLS(), "a target tls block replaces the scope's entirely")
}

func TestEffectiveTargetIsIdempotentAndDefaults(t *testing.T) {
	scope := Scope{Username: "u", TLS: &TLSConfig{SkipVerify: true}}
	once := EffectiveTarget(scope, Target{Host: "h"})
	twice := EffectiveTarget(scope, once)
	assert.Equal(t, once, twice)
	got := EffectiveTarget(Scope{}, Target{Host: "h"})
	assert.Equal(t, uint16(DefaultGNMIPort), got.Port)
	assert.Equal(t, "openconfig", got.ResolvedOrigin())
	assert.Equal(t, TLSConfig{}, got.ResolvedTLS())
}

func TestPolicyConfigResolvers(t *testing.T) {
	var c PolicyConfig
	assert.Equal(t, time.Duration(DefaultProbeTimeoutMs)*time.Millisecond, c.ResolvedProbeTimeout())
	assert.Equal(t, time.Duration(0), c.ResolvedRescanInterval(), "unset disables rescans")
	c.ProbeTimeoutMs, c.RescanIntervalMs = 500, 120000
	assert.Equal(t, 500*time.Millisecond, c.ResolvedProbeTimeout())
	assert.Equal(t, 2*time.Minute, c.ResolvedRescanInterval())
}

func TestPolicyYAMLRoundTrip(t *testing.T) {
	src := `
policies:
  core:
    config:
      metrics_interval: 30
      mode: auto
    scope:
      username: admin
      password: ${GNMI_PASSWORD}
      origin: openconfig
      tls:
        skip_verify: true
      targets:
        - host: 10.0.0.0/24
        - host: 10.0.0.11
          id: "42"
          mode: sample
          profile: nokia_srlinux
`
	var p Policies
	require.NoError(t, yaml.Unmarshal([]byte(src), &p))
	core := p.Policies["core"]
	require.NotNil(t, core.Config.MetricsInterval)
	assert.Equal(t, 30, *core.Config.MetricsInterval)
	assert.Equal(t, "auto", core.Config.Mode)
	assert.Len(t, core.Scope.Targets, 2)
	assert.Equal(t, "42", core.Scope.Targets[1].ID)
	assert.Equal(t, "sample", core.Scope.Targets[1].Mode)
	assert.Equal(t, "nokia_srlinux", core.Scope.Targets[1].Profile)
	assert.True(t, core.Scope.TLS.SkipVerify)
}
