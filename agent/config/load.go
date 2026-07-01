package config

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/go-viper/mapstructure/v2"
	"gopkg.in/yaml.v3"
)

// Load reads the --config file(s) with the existing yaml.v3 decode (unchanged
// from the legacy cmd/main loop) and then applies the generic ORB_* env overlay
// on top, in precedence order file < env. ${VAR} placeholders are left literal
// for the managers to resolve lazily.
func Load(logger *slog.Logger, files []string) (Config, error) {
	return loadWithEnv(logger, files, os.Environ)
}

// loadWithEnv is the testable core. environ backs the generic ORB_* overlay, so
// tests inject a controlled environment; production Load wires os.Environ.
func loadWithEnv(logger *slog.Logger, files []string, environ func() []string) (Config, error) {
	var cfg Config

	// Layer 1: files, via the legacy yaml.v3 struct decode. This preserves
	// multi-file replace semantics, type-aware string scalars (no octal/hex/bool
	// coercion), and YAML 1.1 bool leniency — byte-identical to today.
	for _, f := range files {
		if err := decodeFile(f, &cfg); err != nil {
			return Config{}, err
		}
	}

	// Layer 2: the generic ORB_* overlay, applied via mapstructure directly.
	overlay, err := envToNestedMap(environ())
	if err != nil {
		return Config{}, err
	}

	// No env input: leave the yaml.Decode result untouched (identical to the
	// legacy loader). mapstructure is only involved when there is something to
	// overlay.
	if len(overlay) > 0 {
		var md mapstructure.Metadata
		dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			Result:           &cfg, // overlay ONTO the decoded struct; unmentioned fields survive (ZeroFields defaults false)
			TagName:          "yaml",
			WeaklyTypedInput: true, // string env values -> int/bool/etc.
			Metadata:         &md,
		})
		if err != nil {
			return Config{}, fmt.Errorf("building config decoder: %w", err)
		}
		if err := dec.Decode(overlay); err != nil {
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
