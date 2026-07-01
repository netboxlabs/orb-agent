package config

import "testing"

func TestEnvKeyToConfigPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		env    string
		want   string
		wantOK bool
	}{
		{"active", "ORB_SECRETS_MANAGER__ACTIVE", "orb.secrets_manager.active", true},
		{"nested vault addr", "ORB_SECRETS_MANAGER__SOURCES__VAULT__ADDRESS", "orb.secrets_manager.sources.vault.address", true},
		{"auth_args token (single _ preserved)", "ORB_SECRETS_MANAGER__SOURCES__VAULT__AUTH_ARGS__TOKEN", "orb.secrets_manager.sources.vault.auth_args.token", true},
		{"backend key with single _", "ORB_BACKENDS__NETWORK_DISCOVERY", "orb.backends.network_discovery", true},
		{"bare ORB_ alias skipped (no __)", "ORB_SECRETS_MANAGER", "", false},
		{"non-ORB skipped", "VAULT_ADDR", "", false},
		{"non-ORB path skipped", "PATH", "", false},
		{"trailing delimiter skipped (empty segment)", "ORB_FOO__", "", false},
		{"doubled delimiter skipped (empty segment)", "ORB_A____B", "", false},
		{"trailing delimiter on real path skipped", "ORB_SECRETS_MANAGER__ACTIVE__", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := envKeyToConfigPath(tc.env)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("envKeyToConfigPath(%q) = (%q, %v); want (%q, %v)", tc.env, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
