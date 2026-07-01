package config

import (
	"errors"
	"reflect"
	"testing"
)

func fakeEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestAliasOverrides_Vault(t *testing.T) {
	t.Parallel()
	got, err := aliasOverrides(fakeEnv(map[string]string{
		"ORB_SECRETS_MANAGER": "vault",
		"VAULT_ADDR":          "http://127.0.0.1:8200",
		"VAULT_TOKEN":         "root",
		"VAULT_NAMESPACE":     "ns1",
	}), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]any{
		"orb.secrets_manager.active":                        "vault",
		"orb.secrets_manager.sources.vault.address":         "http://127.0.0.1:8200",
		"orb.secrets_manager.sources.vault.namespace":       "ns1",
		"orb.secrets_manager.sources.vault.auth":            "token",
		"orb.secrets_manager.sources.vault.auth_args.token": "root",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v\nwant %#v", got, want)
	}
}

func TestAliasOverrides_VaultKubernetes(t *testing.T) {
	t.Parallel()
	got, err := aliasOverrides(fakeEnv(map[string]string{
		"ORB_SECRETS_MANAGER": "vault",
		"VAULT_ADDR":          "http://vault:8200",
		"VAULT_K8S_ROLE":      "orb-agent",
	}), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["orb.secrets_manager.sources.vault.auth"] != "kubernetes" ||
		got["orb.secrets_manager.sources.vault.auth_args.role"] != "orb-agent" {
		t.Errorf("kubernetes auth not mapped: %#v", got)
	}
}

func TestAliasOverrides_VaultTokenAndK8sRoleConflict(t *testing.T) {
	t.Parallel()
	_, err := aliasOverrides(fakeEnv(map[string]string{
		"VAULT_TOKEN":    "root",
		"VAULT_K8S_ROLE": "orb-agent",
	}), nil)
	if err == nil {
		t.Fatal("expected error when both VAULT_TOKEN and VAULT_K8S_ROLE are set, got nil")
	}
}

func TestAliasOverrides_Doppler(t *testing.T) {
	t.Parallel()
	got, err := aliasOverrides(fakeEnv(map[string]string{"DOPPLER_TOKEN": "dp.tok"}), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["orb.secrets_manager.sources.doppler.token"] != "dp.tok" {
		t.Errorf("doppler token not mapped: %#v", got)
	}
}

func TestAliasOverrides_FileConvention(t *testing.T) {
	t.Parallel()
	read := func(p string) ([]byte, error) {
		if p == "/run/secrets/vault_token" {
			return []byte("filetok\n"), nil
		}
		return nil, errors.New("not found")
	}
	got, err := aliasOverrides(fakeEnv(map[string]string{
		"VAULT_TOKEN_FILE": "/run/secrets/vault_token",
	}), read)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["orb.secrets_manager.sources.vault.auth_args.token"] != "filetok" {
		t.Errorf("token not read/trimmed from file: %#v", got)
	}
}

func TestAliasOverrides_FileUnreadable(t *testing.T) {
	t.Parallel()
	read := func(string) ([]byte, error) { return nil, errors.New("boom") }
	_, err := aliasOverrides(fakeEnv(map[string]string{"VAULT_TOKEN_FILE": "/nope"}), read)
	if err == nil {
		t.Fatal("expected error for unreadable *_FILE, got nil")
	}
}

func TestAliasOverrides_Empty(t *testing.T) {
	t.Parallel()
	got, err := aliasOverrides(fakeEnv(map[string]string{}), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty map, got %#v", got)
	}
}
