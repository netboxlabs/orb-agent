package config

import (
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strconv"

	"github.com/go-viper/mapstructure/v2"
	"gopkg.in/yaml.v3"
)

// Load reads the --config file(s) with the existing yaml.v3 decode (unchanged
// from the legacy cmd/main loop) and then applies the generic ORB_* env overlay
// on top, in precedence order file < env. ${VAR} placeholders are left literal
// for the managers to resolve lazily.
func Load(files []string, logger *slog.Logger) (Config, error) {
	return loadWithEnv(files, logger, os.Environ)
}

// loadWithEnv is the testable core. environ backs the generic ORB_* overlay, so
// tests inject a controlled environment; production Load wires os.Environ.
func loadWithEnv(files []string, logger *slog.Logger, environ func() []string) (Config, error) {
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
	overlay, err := envToNestedMap(environ(), logger)
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
			DecodeHook:       decimalIntHook(),
		})
		if err != nil {
			return Config{}, fmt.Errorf("building config decoder: %w", err)
		}
		if err := dec.Decode(overlay); err != nil {
			return Config{}, fmt.Errorf("applying env overlay to config: %w", err)
		}
		if logger != nil && len(md.Unused) > 0 {
			logger.Warn("ignoring unknown ORB_ config overrides", "keys", md.Unused)
		}
	}

	if len(files) > 0 {
		cfg.OrbAgent.ConfigFile = files[0]
	}
	return cfg, nil
}

// decimalIntHook forces base-10 parsing for string -> (signed) integer
// mapstructure conversions. Without it, WeaklyTypedInput's default
// strconv.ParseInt(s, 0, ...) auto-detects base from a leading "0"/"0x",
// so an ORB_* override like TIMEOUT=08 fails (invalid octal digit) and
// TIMEOUT=010 silently becomes decimal 8 instead of 10. Operators write
// env var numbers in decimal, so we intercept the string->int conversion
// (fired for both the pointer kind and, after mapstructure dereferences it,
// the element kind — see decodePtr in the mapstructure source) and parse
// it ourselves with base 10. Bool/float conversions are untouched.
func decimalIntHook() mapstructure.DecodeHookFunc {
	return func(from, to reflect.Kind, data any) (any, error) {
		if from != reflect.String {
			return data, nil
		}
		switch to {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			s := data.(string)
			if s == "" {
				return data, nil
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parsing %q as a base-10 integer: %w", s, err)
			}
			return n, nil
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			s := data.(string)
			if s == "" {
				return data, nil
			}
			n, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parsing %q as a base-10 unsigned integer: %w", s, err)
			}
			return n, nil
		default:
			return data, nil
		}
	}
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
