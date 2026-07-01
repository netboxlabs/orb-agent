package config

import (
	"errors"
	"fmt"
	"strings"
)

// aliasOverrides builds a flat map of dot-delimited koanf keys from the friendly
// secrets-manager env aliases. getenv/readFile are injected for testability
// (production passes os.Getenv / os.ReadFile). For any secret-bearing alias,
// a "<NAME>_FILE" variant reads the value from that file path instead
// (Kubernetes Secret volumes, Docker secrets, Vault CSI).
func aliasOverrides(getenv func(string) string, readFile func(string) ([]byte, error)) (map[string]any, error) {
	out := map[string]any{}
	set := func(key, val string) {
		if val != "" {
			out[key] = val
		}
	}
	// resolve returns the value of NAME, or the trimmed contents of NAME_FILE
	// when set (file takes precedence).
	resolve := func(name string) (string, error) {
		if path := getenv(name + "_FILE"); path != "" {
			b, err := readFile(path)
			if err != nil {
				return "", fmt.Errorf("reading %s_FILE (%s): %w", name, path, err)
			}
			return strings.TrimSpace(string(b)), nil
		}
		return getenv(name), nil
	}

	set("orb.secrets_manager.active", getenv("ORB_SECRETS_MANAGER"))

	// Vault (reuses Vault's own standard env var names).
	set("orb.secrets_manager.sources.vault.address", getenv("VAULT_ADDR"))
	set("orb.secrets_manager.sources.vault.namespace", getenv("VAULT_NAMESPACE"))
	set("orb.secrets_manager.sources.vault.mount", getenv("VAULT_MOUNT"))
	token, err := resolve("VAULT_TOKEN")
	if err != nil {
		return nil, err
	}
	role := getenv("VAULT_K8S_ROLE")
	// token auth and kubernetes auth are mutually exclusive; refuse rather than
	// silently pick one and leave stray secret material in auth_args.
	if token != "" && role != "" {
		return nil, errors.New("VAULT_TOKEN and VAULT_K8S_ROLE are mutually exclusive; set only one")
	}
	if token != "" {
		out["orb.secrets_manager.sources.vault.auth"] = "token"
		out["orb.secrets_manager.sources.vault.auth_args.token"] = token
	}
	// Kubernetes auth (pod ServiceAccount token; no static token in env).
	if role != "" {
		out["orb.secrets_manager.sources.vault.auth"] = "kubernetes"
		out["orb.secrets_manager.sources.vault.auth_args.role"] = role
	}

	// Doppler.
	doppler, err := resolve("DOPPLER_TOKEN")
	if err != nil {
		return nil, err
	}
	set("orb.secrets_manager.sources.doppler.token", doppler)

	return out, nil
}
