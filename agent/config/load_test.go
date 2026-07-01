package config

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const sampleYAML = `
orb:
  config_manager:
    active: local
    sources:
      local:
        config: /etc/orb/agent.yaml
  secrets_manager:
    active: doppler
    sources:
      doppler:
        timeout: 30
  backends:
    network_discovery:
`

func emptyEnviron() []string { return nil }

// envFromMap builds an environ func from a map so Load tests run against a
// fully controlled environment (no leakage from the dev/CI shell).
func envFromMap(m map[string]string) func() []string {
	return func() []string {
		out := make([]string, 0, len(m))
		for k, v := range m {
			out = append(out, k+"="+v)
		}
		return out
	}
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// decodeLegacy mimics today's cmd/main loadConfig loop for the golden comparison.
func decodeLegacy(t *testing.T, files ...string) Config {
	t.Helper()
	var want Config
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := yaml.NewDecoder(f).Decode(&want); err != nil {
			_ = f.Close()
			t.Fatalf("legacy decode %s: %v", p, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close %s: %v", p, err)
		}
	}
	return want
}

// GOLDEN: file-only Load of the REAL shipped default_config.yaml must equal the
// legacy yaml decode (exercises files_manager empty-struct, otlp_bridge port int,
// multi-backend nil maps, and ${FLEET_*} literals).
func TestLoad_FileOnly_MatchesLegacy_DefaultConfig(t *testing.T) {
	t.Parallel()
	const p = "../docker/default_config.yaml"

	got, err := loadWithEnv(nil, []string{p}, emptyEnviron)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := decodeLegacy(t, p)
	want.OrbAgent.ConfigFile = p

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Load != legacy decode of default_config.yaml\n got: %#v\nwant: %#v", got, want)
	}
}

// GOLDEN: a local-config-manager example round-trips identically too.
func TestLoad_FileOnly_MatchesLegacy_LocalConfig(t *testing.T) {
	t.Parallel()
	const body = `
orb:
  config_manager:
    active: local
    sources:
      local:
        config: /etc/orb/agent.yaml
  backends:
    network_discovery:
      foo: bar
`
	p := writeTempConfig(t, body)
	got, err := loadWithEnv(nil, []string{p}, emptyEnviron)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := decodeLegacy(t, p)
	want.OrbAgent.ConfigFile = p
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Load != legacy decode (local)\n got: %#v\nwant: %#v", got, want)
	}
}

// The corruption guard: string fields whose YAML looks octal/hex/bool must NOT
// be coerced, and YAML 1.1 bool words must still parse (all preserved because
// files never pass through koanf).
func TestLoad_FileOnly_StringFieldsNotCoerced(t *testing.T) {
	t.Parallel()
	const body = `
orb:
  config_manager:
    active: fleet
    sources:
      fleet:
        client_id: true
        client_secret: 0700
        skip_tls: yes
`
	p := writeTempConfig(t, body)
	got, err := loadWithEnv(nil, []string{p}, emptyEnviron)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	fleet := got.OrbAgent.ConfigManager.Sources.Fleet
	if fleet.ClientID != "true" {
		t.Errorf("client_id = %q; want \"true\" (not bool-coerced)", fleet.ClientID)
	}
	if fleet.ClientSecret != "0700" {
		t.Errorf("client_secret = %q; want \"0700\" (not octal-coerced)", fleet.ClientSecret)
	}
	if !fleet.SkipTLS {
		t.Errorf("skip_tls = %v; want true (YAML 1.1 bool leniency preserved)", fleet.SkipTLS)
	}
}

// Multi-file uses replace (last-wins), NOT deep-merge, of nested map values.
func TestLoad_MultiFile_ReplaceSemantics(t *testing.T) {
	t.Parallel()
	a := writeTempConfig(t, "orb:\n  backends:\n    network_discovery:\n      a: 1\n")
	b := writeTempConfig(t, "orb:\n  backends:\n    network_discovery:\n      b: 2\n")

	got, err := loadWithEnv(nil, []string{a, b}, emptyEnviron)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	nd, _ := got.OrbAgent.Backends["network_discovery"].(map[string]any)
	if _, hasA := nd["a"]; hasA {
		t.Errorf("expected replace semantics; key 'a' from file A survived: %#v", nd)
	}
	if _, hasB := nd["b"]; !hasB {
		t.Errorf("expected 'b' from file B present: %#v", nd)
	}
	want := decodeLegacy(t, a, b)
	want.OrbAgent.ConfigFile = a
	if !reflect.DeepEqual(got, want) {
		t.Errorf("multi-file Load != legacy loop\n got: %#v\nwant: %#v", got, want)
	}
}

// The overlay merges onto the decoded struct without zeroing file-set siblings.
func TestLoad_Overlay_PreservesFileSiblings(t *testing.T) {
	t.Parallel()
	p := writeTempConfig(t, sampleYAML)
	environ := envFromMap(map[string]string{
		"ORB_SECRETS_MANAGER__ACTIVE":                           "vault",
		"ORB_SECRETS_MANAGER__SOURCES__VAULT__ADDRESS":          "http://127.0.0.1:8200",
		"ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH":             "token",
		"ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH_ARGS__TOKEN": "root",
	})

	got, err := loadWithEnv(nil, []string{p}, environ)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.OrbAgent.SecretsManager.Active != "vault" {
		t.Errorf("active = %q; want vault", got.OrbAgent.SecretsManager.Active)
	}
	// Config manager (file-set) must survive the overlay.
	if got.OrbAgent.ConfigManager.Active != "local" {
		t.Errorf("config manager clobbered: %q", got.OrbAgent.ConfigManager.Active)
	}
	// Sibling secrets source (file-set) must survive.
	if dt := got.OrbAgent.SecretsManager.Sources.Doppler.Timeout; dt == nil || *dt != 30 {
		t.Errorf("file's secrets doppler.timeout not preserved: %v", dt)
	}
	v := got.OrbAgent.SecretsManager.Sources.Vault
	if v.Address != "http://127.0.0.1:8200" || v.Auth != "token" || v.AuthArgs["token"] != "root" {
		t.Errorf("vault source not populated: %#v", v)
	}
}

// Generic overlay coerces string->*int.
func TestLoad_GenericOverlay_Coercion(t *testing.T) {
	t.Parallel()
	p := writeTempConfig(t, sampleYAML)
	environ := envFromMap(map[string]string{
		"ORB_SECRETS_MANAGER__ACTIVE":                  "vault",
		"ORB_SECRETS_MANAGER__SOURCES__VAULT__TIMEOUT": "45", // string -> *int
	})

	got, err := loadWithEnv(nil, []string{p}, environ)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.OrbAgent.SecretsManager.Active != "vault" {
		t.Errorf("active = %q; want vault", got.OrbAgent.SecretsManager.Active)
	}
	to := got.OrbAgent.SecretsManager.Sources.Vault.Timeout
	if to == nil || *to != 45 {
		t.Errorf("vault.timeout not coerced to 45: %v", to)
	}
}

// Unknown/mistyped ORB_* keys are ignored and surfaced at debug.
func TestLoad_UnknownGenericKey_IgnoredAndLogged(t *testing.T) {
	t.Parallel()
	p := writeTempConfig(t, sampleYAML)
	environ := envFromMap(map[string]string{"ORB_SECRETS_MANAGER__BOGUSKEY": "x"})
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	got, err := loadWithEnv(logger, []string{p}, environ)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.OrbAgent.SecretsManager.Active != "doppler" {
		t.Errorf("bogus key altered config: active = %q", got.OrbAgent.SecretsManager.Active)
	}
	if !strings.Contains(buf.String(), "boguskey") {
		t.Errorf("expected the unused key logged at debug; log = %q", buf.String())
	}
}

// A generic override that reaches INTO a file-populated map[string]any entry
// (backends/policies) REPLACES the entry value wholesale — file sibling keys
// under it are dropped. This is documented, intentional behavior; the test
// locks it so it can't silently change.
func TestLoad_GenericOverlay_ReplacesBackendEntry(t *testing.T) {
	t.Parallel()
	const body = `
orb:
  backends:
    pktvisor:
      tap: file-tap
`
	p := writeTempConfig(t, body)
	environ := envFromMap(map[string]string{"ORB_BACKENDS__PKTVISOR__FOO": "bar"})

	got, err := loadWithEnv(nil, []string{p}, environ)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	pk, _ := got.OrbAgent.Backends["pktvisor"].(map[string]any)
	if _, hasTap := pk["tap"]; hasTap {
		t.Errorf("expected wholesale replace of the pktvisor entry; file key 'tap' survived: %#v", pk)
	}
	if pk["foo"] != "bar" {
		t.Errorf("expected overlay key foo=bar in replaced entry: %#v", pk)
	}
}

// A malformed generic value on a known key fails the load (fail-fast, not
// silently ignored) — a deliberate override must not be swallowed.
func TestLoad_MalformedOverlayValue_Errors(t *testing.T) {
	t.Parallel()
	p := writeTempConfig(t, sampleYAML)
	cases := []map[string]string{
		{"ORB_SECRETS_MANAGER__SOURCES__VAULT__TIMEOUT": "abc"}, // string -> *int cannot coerce
		{"ORB_SECRETS_MANAGER__ACTIVE__X": "vault"},             // extra segment nests a map under a string leaf
	}
	for _, bad := range cases {
		environ := envFromMap(bad)
		if _, err := loadWithEnv(nil, []string{p}, environ); err == nil {
			t.Errorf("expected error for malformed overlay %v, got nil", bad)
		}
	}
}

// A path set BOTH as a scalar and as a parent of a deeper key is rejected
// deterministically, regardless of env order.
func TestLoad_GenericOverlay_ScalarParentCollision_Errors(t *testing.T) {
	t.Parallel()
	p := writeTempConfig(t, sampleYAML)
	orders := [][]string{
		{"ORB_SECRETS_MANAGER__ACTIVE=vault", "ORB_SECRETS_MANAGER__ACTIVE__X=y"},
		{"ORB_SECRETS_MANAGER__ACTIVE__X=y", "ORB_SECRETS_MANAGER__ACTIVE=vault"},
	}
	for _, env := range orders {
		environ := func() []string { return env }
		if _, err := loadWithEnv(nil, []string{p}, environ); err == nil {
			t.Errorf("expected collision error for %v, got nil", env)
		}
	}
}
