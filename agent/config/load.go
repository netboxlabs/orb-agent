package config

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/providers/confmap"
	env "github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/v2"
	"gopkg.in/yaml.v3"
)

// Load reads the --config file(s) with the existing yaml.v3 decode (unchanged
// from the legacy cmd/main loop) and then applies the friendly env aliases and
// the generic ORB_* overlay on top, in precedence order file < aliases < generic.
// ${VAR} placeholders are left literal for the managers to resolve lazily.
func Load(logger *slog.Logger, files []string) (Config, error) {
	return loadWithEnv(logger, files, os.Getenv, os.ReadFile, os.Environ)
}

// loadWithEnv is the testable core. getenv/readFile back the alias builder and
// environ backs the generic ORB_* overlay, so tests inject a controlled
// environment; production Load wires os.Getenv/os.ReadFile/os.Environ.
func loadWithEnv(
	logger *slog.Logger,
	files []string,
	getenv func(string) string,
	readFile func(string) ([]byte, error),
	environ func() []string,
) (Config, error) {
	var cfg Config

	// Layer 1: files, via the legacy yaml.v3 struct decode. This preserves
	// multi-file replace semantics, type-aware string scalars (no octal/hex/bool
	// coercion), and YAML 1.1 bool leniency — byte-identical to today.
	for _, f := range files {
		if err := decodeFile(f, &cfg); err != nil {
			return Config{}, err
		}
	}

	// Layers 2+3: build the env/alias overlay in one koanf instance. Aliases
	// load first, then the generic ORB_* overlay, so the generic form wins.
	k := koanf.New(".")
	aliases, err := aliasOverrides(getenv, readFile)
	if err != nil {
		return Config{}, err
	}
	if err := k.Load(confmap.Provider(aliases, "."), nil); err != nil {
		return Config{}, fmt.Errorf("applying alias overrides: %w", err)
	}
	if err := k.Load(env.Provider(".", env.Opt{
		Prefix:      envPrefix,
		EnvironFunc: environ,
		TransformFunc: func(name, val string) (string, any) {
			key, ok := envKeyToConfigPath(name)
			if !ok {
				return "", nil
			}
			return key, val
		},
	}), nil); err != nil {
		return Config{}, fmt.Errorf("applying env overrides: %w", err)
	}

	// No env/alias input: leave the yaml.Decode result untouched (identical to
	// the legacy loader). koanf is only involved when there is something to overlay.
	if len(k.Keys()) > 0 {
		var md mapstructure.Metadata
		if err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
			// Tag is load-bearing: koanf sets DecoderConfig.TagName from it and
			// FORCES "koanf" when Tag is empty (overwriting any TagName set below).
			// Our structs carry only yaml tags, so this MUST be "yaml" or the
			// entire overlay silently no-ops.
			Tag: "yaml",
			DecoderConfig: &mapstructure.DecoderConfig{
				Result:           &cfg, // overlay ONTO the decoded struct; unmentioned fields survive (ZeroFields defaults false)
				WeaklyTypedInput: true, // string env values -> int/bool/etc.
				Metadata:         &md,
			},
		}); err != nil {
			return Config{}, fmt.Errorf("applying env overlay to config: %w", err)
		}
		if logger != nil && len(md.Unused) > 0 {
			logger.Debug("ignoring unknown ORB_ config overrides", "keys", md.Unused)
		}
	}

	if len(files) > 0 {
		cfg.OrbAgent.ConfigFile = files[0]
	}
	return cfg, nil
}

// decodeFile decodes one YAML config file into cfg using the same yaml.v3 path
// as the legacy cmd/main loader (a later file's values replace earlier ones).
func decodeFile(path string, cfg *Config) (err error) {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open config file %s: %w", path, err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close config file %s: %w", path, cerr)
		}
	}()
	if derr := yaml.NewDecoder(file).Decode(cfg); derr != nil {
		return fmt.Errorf("failed to parse config file %s: %w", path, derr)
	}
	return nil
}
