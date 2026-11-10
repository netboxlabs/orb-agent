package redact

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/netboxlabs/orb-agent/agent/config"
)

// TestSensitiveData_SimpleMap tests basic map redaction
func TestSensitiveData_SimpleMap(t *testing.T) {
	original := map[string]any{
		"client_secret": "my-secret-123",
		"password":      "my-password",
		"client_id":     "my-client-id",
		"url":           "https://example.com",
	}

	redacted := SensitiveData(original)

	redactedMap, ok := redacted.(map[string]any)
	if !ok {
		t.Fatalf("Expected map[string]any, got %T", redacted)
	}

	// Verify sensitive fields are masked
	if redactedMap["client_secret"] != MaskedSecret {
		t.Errorf("Expected client_secret to be %s, got %v", MaskedSecret, redactedMap["client_secret"])
	}
	if redactedMap["password"] != MaskedSecret {
		t.Errorf("Expected password to be %s, got %v", MaskedSecret, redactedMap["password"])
	}

	// Verify non-sensitive fields are preserved
	if redactedMap["client_id"] != "my-client-id" {
		t.Errorf("Expected client_id to be preserved, got %v", redactedMap["client_id"])
	}
	if redactedMap["url"] != "https://example.com" {
		t.Errorf("Expected url to be preserved, got %v", redactedMap["url"])
	}

	// Verify original is NOT mutated
	if original["client_secret"] != "my-secret-123" {
		t.Error("Original map was mutated!")
	}
}

// TestSensitiveData_NestedMap tests nested structure redaction
func TestSensitiveData_NestedMap(t *testing.T) {
	original := map[string]any{
		"backend": map[string]any{
			"client_secret": "nested-secret",
			"target":        "https://api.example.com",
		},
		"public_key": "public-value",
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)
	backend := redactedMap["backend"].(map[string]any)

	if backend["client_secret"] != MaskedSecret {
		t.Errorf("Expected nested client_secret to be masked, got %v", backend["client_secret"])
	}
	if backend["target"] != "https://api.example.com" {
		t.Errorf("Expected nested target to be preserved, got %v", backend["target"])
	}
}

// TestSensitiveData_FleetManager tests real config type
func TestSensitiveData_FleetManager(t *testing.T) {
	original := config.FleetManager{
		URL:          "https://fleet.example.com",
		ClientID:     "my-client-id",
		ClientSecret: "my-client-secret",
		TokenURL:     "https://auth.example.com",
	}

	redacted := SensitiveData(original)

	redactedMap, ok := redacted.(map[string]any)
	if !ok {
		t.Fatalf("Expected map[string]any, got %T", redacted)
	}

	// Verify sensitive field is masked (using yaml tag name)
	if redactedMap["client_secret"] != MaskedSecret {
		t.Errorf("Expected client_secret to be masked, got %v", redactedMap["client_secret"])
	}

	// Verify non-sensitive fields are preserved (using yaml tag names)
	if redactedMap["url"] != "https://fleet.example.com" {
		t.Errorf("Expected url to be preserved, got %v", redactedMap["url"])
	}
	if redactedMap["client_id"] != "my-client-id" {
		t.Errorf("Expected client_id to be preserved, got %v", redactedMap["client_id"])
	}

	// Verify original struct is NOT mutated
	if original.ClientSecret != "my-client-secret" {
		t.Error("Original struct was mutated!")
	}
}

// TestSensitiveData_GitManager tests GitManager with multiple secrets
func TestSensitiveData_GitManager(t *testing.T) {
	original := config.GitManager{
		URL:        "https://git.example.com",
		Username:   "gituser",
		Password:   "gitpass123",
		PrivateKey: "-----BEGIN RSA PRIVATE KEY-----",
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)

	// Verify both sensitive fields are masked (using yaml tag names)
	if redactedMap["password"] != MaskedSecret {
		t.Errorf("Expected password to be masked, got %v", redactedMap["password"])
	}
	if redactedMap["private_key"] != MaskedSecret {
		t.Errorf("Expected private_key to be masked, got %v", redactedMap["private_key"])
	}

	// Verify non-sensitive fields are preserved (using yaml tag names)
	if redactedMap["username"] != "gituser" {
		t.Errorf("Expected username to be preserved, got %v", redactedMap["username"])
	}
}

// TestSensitiveData_GitHubApp tests that the nested github_app block has its
// private key masked while the non-sensitive identifiers stay readable.
func TestSensitiveData_GitHubApp(t *testing.T) {
	original := config.GitManager{
		URL:  "https://github.com/myorg/policyrepo",
		Auth: "github_app",
		GitHubApp: config.GitHubAppAuth{
			ClientID:       "Iv23liAbCdEfGhIjKlMn",
			InstallationID: "78901234",
			PrivateKey:     "-----BEGIN RSA PRIVATE KEY-----",
		},
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)
	githubApp, ok := redactedMap["github_app"].(map[string]any)
	if !ok {
		t.Fatalf("Expected github_app to be a nested map, got %T", redactedMap["github_app"])
	}

	if githubApp["private_key"] != MaskedSecret {
		t.Errorf("Expected github_app.private_key to be masked, got %v", githubApp["private_key"])
	}

	// client_id and installation_id are not secrets; keeping them readable is
	// what makes a misconfiguration diagnosable from the logs.
	if githubApp["client_id"] != "Iv23liAbCdEfGhIjKlMn" {
		t.Errorf("Expected github_app.client_id to be preserved, got %v", githubApp["client_id"])
	}
	if githubApp["installation_id"] != "78901234" {
		t.Errorf("Expected github_app.installation_id to be preserved, got %v", githubApp["installation_id"])
	}
}

// TestSensitiveData_BackendCommons tests BackendCommons with Diode config
func TestSensitiveData_BackendCommons(t *testing.T) {
	original := config.BackendCommons{}
	original.Diode.Target = "https://diode.example.com"
	original.Diode.ClientID = "diode-client"
	original.Diode.ClientSecret = "diode-secret-123"
	original.Diode.AgentName = "test-agent"

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)
	diode := redactedMap["Diode"].(map[string]any)

	// Verify sensitive field is masked (using yaml tag names)
	if diode["client_secret"] != MaskedSecret {
		t.Errorf("Expected Diode.client_secret to be masked, got %v", diode["client_secret"])
	}

	// Verify non-sensitive fields are preserved (using yaml tag names)
	if diode["target"] != "https://diode.example.com" {
		t.Errorf("Expected Diode.target to be preserved, got %v", diode["target"])
	}
	if diode["client_id"] != "diode-client" {
		t.Errorf("Expected Diode.client_id to be preserved, got %v", diode["client_id"])
	}
}

// TestSensitiveData_Slice tests slice redaction
func TestSensitiveData_Slice(t *testing.T) {
	original := []map[string]any{
		{"client_secret": "secret1", "name": "backend1"},
		{"client_secret": "secret2", "name": "backend2"},
	}

	redacted := SensitiveData(original)

	redactedSlice, ok := redacted.([]any)
	if !ok {
		t.Fatalf("Expected []any, got %T", redacted)
	}

	// Verify each item is redacted
	for i, item := range redactedSlice {
		itemMap := item.(map[string]any)
		if itemMap["client_secret"] != MaskedSecret {
			t.Errorf("Expected item %d client_secret to be masked, got %v", i, itemMap["client_secret"])
		}
		if itemMap["name"] == "" {
			t.Errorf("Expected item %d name to be preserved", i)
		}
	}

	// Verify original is NOT mutated
	if original[0]["client_secret"] != "secret1" {
		t.Error("Original slice was mutated!")
	}
}

// TestSensitiveData_NilValues tests handling of nil values
func TestSensitiveData_NilValues(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  any
	}{
		{"nil input", nil, nil},
		{"nil map", map[string]any(nil), nil},
		{"nil slice", []string(nil), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SensitiveData(tt.input)
			if result != tt.want {
				t.Errorf("Expected %v, got %v", tt.want, result)
			}
		})
	}
}

// TestSensitiveData_EmptyStrings tests that empty strings are preserved
func TestSensitiveData_EmptyStrings(t *testing.T) {
	original := map[string]any{
		"client_secret": "",
		"password":      "",
		"client_id":     "",
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)

	// Empty sensitive fields should remain empty (not masked)
	// This allows distinguishing "no secret configured" from "secret configured (redacted)"
	if redactedMap["client_secret"] != "" {
		t.Errorf("Expected empty client_secret to remain empty, got %v", redactedMap["client_secret"])
	}
	if redactedMap["password"] != "" {
		t.Errorf("Expected empty password to remain empty, got %v", redactedMap["password"])
	}

	// Non-sensitive empty fields should also remain empty
	if redactedMap["client_id"] != "" {
		t.Errorf("Expected empty client_id to remain empty, got %v", redactedMap["client_id"])
	}
}

// TestSensitiveData_CaseVariations tests case-insensitive matching
func TestSensitiveData_CaseVariations(t *testing.T) {
	original := map[string]any{
		"CLIENT_SECRET": "secret1",
		"ClientSecret":  "secret2",
		"client_secret": "secret3",
		"Password":      "pass1",
		"PASSWORD":      "pass2",
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)

	// All case variations should be masked
	for key, value := range redactedMap {
		if value != MaskedSecret {
			t.Errorf("Expected %s to be masked, got %v", key, value)
		}
	}
}

// TestSensitiveData_NumbersUnderASensitiveName masks a number under a
// sensitive name, as YAML decodes a credential written as unquoted digits into
// an untyped map, and keeps a bool, which holds no credential.
func TestSensitiveData_NumbersUnderASensitiveName(t *testing.T) {
	redacted := SensitiveData(map[string]any{
		"password":       135792468,
		"secret_id":      uint64(8675309123),
		"api_key":        1.5,
		"wrapping_token": false,
	}).(map[string]any)

	for _, name := range []string{"password", "secret_id", "api_key"} {
		if redacted[name] != MaskedSecret {
			t.Errorf("Expected %s to be masked, got %v (type %T)", name, redacted[name], redacted[name])
		}
	}
	if redacted["wrapping_token"] != false {
		t.Errorf("Expected wrapping_token to be kept, got %v", redacted["wrapping_token"])
	}
}

// TestSensitiveData_AuthArgsMasksAllButTheFieldsNamingNoCredential masks
// every value of a Vault login's auth_args, whatever its name, nested or
// listed, but those of the fields that name no credential, and keeps a bool.
// A login method the list has no names for is masked whole.
func TestSensitiveData_AuthArgsMasksAllButTheFieldsNamingNoCredential(t *testing.T) {
	redacted := SensitiveData(map[string]any{
		"auth": "aws",
		"auth_args": map[string]any{
			"access_key":           "access",
			"secret_key":           "secret",
			"region":               "us-east-1",
			"port":                 8200,
			"options":              map[string]any{"header": "value"},
			"values":               []any{"listed"},
			"empty":                "",
			"mount_path":           "aws",
			"username":             "agent",
			"role":                 "orb-agent",
			"service_account_file": "/var/run/token",
			"wrapping_token":       false,
		},
	}).(map[string]any)

	if redacted["auth"] != "aws" {
		t.Errorf("Expected auth, outside auth_args, to be kept, got %v", redacted["auth"])
	}
	args := redacted["auth_args"].(map[string]any)
	for _, name := range []string{"access_key", "secret_key", "region", "port"} {
		if args[name] != MaskedSecret {
			t.Errorf("Expected %s to be masked, got %v", name, args[name])
		}
	}
	if header := args["options"].(map[string]any)["header"]; header != MaskedSecret {
		t.Errorf("Expected a nested value to be masked, got %v", header)
	}
	if listed := args["values"].([]any)[0]; listed != MaskedSecret {
		t.Errorf("Expected a listed value to be masked, got %v", listed)
	}
	if args["empty"] != "" {
		t.Errorf("Expected an empty value to stay empty, got %v", args["empty"])
	}
	for name, want := range map[string]any{
		"mount_path": "aws", "username": "agent", "role": "orb-agent", "service_account_file": "/var/run/token", "wrapping_token": false,
	} {
		if args[name] != want {
			t.Errorf("Expected %s to be kept as %v, got %v", name, want, args[name])
		}
	}
}

// TestSensitiveData_MasksAURLsUserInfo masks the user and password of a URL
// under any name, as a Vault address carries them for a proxy that asks for
// basic auth, together, and keeps the rest of the URL and a URL without
// either. The user is half of the proxy's login, and the whole of it when the
// password is empty.
func TestSensitiveData_MasksAURLsUserInfo(t *testing.T) {
	redacted := SensitiveData(map[string]any{
		"address": "https://proxyuser:Pr0xy-pa55word@vault.example.com:8200/v1",
		"url":     "https://git.example.com/repo.git",
		"user":    "https://proxyuser@vault.example.com",
		"text":    "not a URL: user:pass@host",
	}).(map[string]any)

	if redacted["address"] != "https://********@vault.example.com:8200/v1" {
		t.Errorf("Expected the address's user and password to be masked, got %v", redacted["address"])
	}
	if redacted["user"] != "https://********@vault.example.com" {
		t.Errorf("Expected a user with no password, which can be a token, to be masked, got %v", redacted["user"])
	}
	// A word of a text that is a user and a password before an @ is masked.
	if redacted["text"] != "not a URL: ********@host" {
		t.Errorf("Expected the user and password in the text to be masked, got %v", redacted["text"])
	}
	for name, want := range map[string]string{
		"url": "https://git.example.com/repo.git",
	} {
		if redacted[name] != want {
			t.Errorf("Expected %s to be kept as %q, got %v", name, want, redacted[name])
		}
	}
	for in, want := range map[string]string{
		"https://u:p@h": "https://********@h",
		// An empty password, after which the user is the whole login.
		"https://u:@h": "https://********@h",
		// A token given as the user, with no password.
		"https://ghp_T0ken@github.com/org/repo.git": "https://********@github.com/org/repo.git",
		// A password with a / ? # % or space that is not escaped, which no
		// URL parser reads: everything between :// and the last @ is masked.
		"https://u:pa/ss@vault:8200":   "https://********@vault:8200",
		"https://u:pa?ss@vault:8200":   "https://********@vault:8200",
		"https://u:pa#ss@vault:8200":   "https://********@vault:8200",
		"https://u:pa%zzss@vault:8200": "https://********@vault:8200",
		"https://u:pa ss@vault:8200":   "https://********@vault:8200",
		// A token given as the user with a / ? or # that is not escaped,
		// which a parser reads as the host and a path, query or fragment:
		// an @ after :// that is not the end of user info is masked as one.
		"https://T0k/en@vault:8200": "https://********@vault:8200",
		"https://T0k?en@vault:8200": "https://********@vault:8200",
		"https://T0k#en@vault:8200": "https://********@vault:8200",
		// A URL written without //, whose part before its last @ holds a :,
		// as a user and a password do: all of that part is masked, since a
		// parser reads a user, or a token, as the URL's scheme.
		"https:u:s3cret@vault.example.com":   "********@vault.example.com",
		"u:s3cret@vault.example.com:8200":    "********@vault.example.com:8200",
		"https:u:s3cret@vault.example.com?x": "********@vault.example.com?x",
		"https:/u:s3cret@vault.example.com":  "********@vault.example.com",
		"mailto:ops@example.com":             "********@example.com",
		// A token as git's user, before x-oauth-basic, made of what a scheme
		// can hold or not.
		"ghp_T0ken:x-oauth-basic@github.com:org/r.git": "********@github.com:org/r.git",
		"T0ken123:x-oauth-basic@github.com:org/r.git":  "********@github.com:org/r.git",
		"glpat-T0ken:x@gitlab.com:org/r.git":           "********@gitlab.com:org/r.git",
		// An e-mail address, with no : before its @, is not one, nor is a
		// path with a / before its first :.
		"ops@example.com": "ops@example.com",
		"a/b:c@d":         "a/b:c@d",
		// git's scp-like address, user@host:path, which no parser reads: what
		// is before its last @ is masked, whether a token or git's own user.
		"ghp_T0ken@github.com:org/repo.git": "********@github.com:org/repo.git",
		"git@github.com:org/repo.git":       "********@github.com:org/repo.git",
		// A path with a / before its first : is not one, nor is a text with
		// a space there, nor one with nothing before its @.
		"./a@b:c":                        "./a@b:c",
		"Contact ops@example.com: today": "Contact ops@example.com: today",
		"@scope:value":                   "@scope:value",
		// So is an @ in a path, at the cost of the host it hides.
		"https://registry.example.com/@scope/pkg": "https://********@scope/pkg",
		// A URL written without a scheme, from its //, which a parser reads
		// as a user and a host.
		"//proxyuser:Pr0xy-pa55word@127.0.0.1:1": "//********@127.0.0.1:1",
		"//T0ken@vault:8200":                     "//********@vault:8200",
		"//u:pa/ss@vault:8200":                   "//********@vault:8200",
		// Even when a :// comes later, in its query or fragment.
		"//u:p@h/?next=https://x":  "//********@h/?next=https://x",
		"//u:p@h#https://x":        "//********@h#https://x",
		"//vault.example.com:8200": "//vault.example.com:8200",
	} {
		if got := URL(in); got != want {
			t.Errorf("URL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestURL_MasksEveryURLAStringHolds(t *testing.T) {
	for in, want := range map[string]string{
		"https://u4:p4@a.invalid,https://u5:p5@b.invalid": "https://********@a.invalid,https://********@b.invalid",
		"https://u4:p4@a.invalid;//u5:p5@b.invalid":       "https://********@a.invalid;//********@b.invalid",
		"u4:p4@a.invalid,https://u5:p5@b.invalid":         "********@a.invalid,https://********@b.invalid",
		"https://u4:p4@a.invalid,https://b.invalid":       "https://********@a.invalid,https://b.invalid",
		"https://a.invalid,https://b.invalid":             "https://a.invalid,https://b.invalid",
		// URLs written without //, in a list.
		"u1:p1@h1\nu2:p2@h2": "********@h1\n********@h2",
		"git@github.com:org/a.git tok:x-oauth-basic@github.com:org/b.git": "********@github.com:org/a.git ********@github.com:org/b.git",
		// Read as one URL, the string has everything from its first // or
		// : to its last @ masked, where no parser tells where its user info
		// ends: a password that holds a separator, a , or a // is masked
		// whole, at the cost of the hosts it hides.
		"https://u4:p4@a.invalid, https://u5:p5@b.invalid": "https://********@b.invalid",
		"https://u4@a.invalid\nssh://u5@b.invalid/r.git":   "https://********@b.invalid/r.git",
		"app:S3cret@kafka1:9092, app:S3cret@kafka2:9092":   "********@kafka2:9092",
		"app:S3cret@kafka1:9092,app:S3cret@kafka2:9092":    "********@kafka2:9092",
		"https://u:p,//x@h":                         "https://********@h",
		"https://u:p, https://x@h":                  "https://********@h",
		"https://a.invalid,https://u5:p5@b.invalid": "https://********@b.invalid",
		"https://u:p://x@h":                         "https://********@h",
		"user:p@ss,//word@h":                        "********@h",
		"u1:p1@h1,u2:abc=//def@h2":                  "********@h2",
		"https://u1:p1@h1 u2:p,//x@h2":              "https://********@h2",
		// A password with a space is masked; the user before it can't be
		// told from a text's word, and is kept.
		"user:pa ss@host": "user:********@host",
		// A secret reference is kept as written, whatever is masked around it.
		"https://u:p@h/x ${vault://kv//a/b}": "https://********@h/x ${vault://kv//a/b}",
		"${vault://kv//a/b},https://u:p@h":   "${vault://kv//a/b}********@h",
		"${vault://m/p/k}tok@":               "${vault://m/p/k}********@",
		// ${...} with a scheme no secrets manager resolves is no reference.
		"${https://u:p@h}": "${https://********@h}",
		// git's scp-like address with nothing after its :, read as one URL.
		"tok@:": "********@:",
		// In a text, a user and a password start after the separator before
		// them, as after a flag's =.
		"-Dhttp.proxy=u:p@proxy:3128":          "-Dhttp.proxy=********@proxy:3128",
		"ghp_T0ken:abc==@github.com:o/r":       "********@github.com:o/r",
		"${vault://kv//db/user}@db:5432":       "${vault://kv//db/user}@db:5432",
		"https://user:${vault://kv/p/k}@h":     "https://********${vault://kv/p/k}@h",
		"${vault://secret/data/git/token}":     "${vault://secret/data/git/token}",
		"tok:${vault://kv/p/k}@github.com:o/r": "********${vault://kv/p/k}@github.com:o/r",
		// An image's name before its digest can't be told from a user and a
		// password, or git's user, before a host named sha256: it is masked as
		// one, but where a / comes before its first :.
		"localhost:5000/img:tag@" + testDigest:      "********@" + testDigest,
		"nginx:1.25@" + testDigest:                  "********@" + testDigest,
		"img@" + testDigest:                         "********@" + testDigest,
		"ghcr.io/o/i:v1@" + testDigest:              "ghcr.io/o/i:v1@" + testDigest,
		"https://u:p@reg.example/img@" + testDigest: "https://********@reg.example/img@" + testDigest,
	} {
		if got := URL(in); got != want {
			t.Errorf("URL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSensitiveData_MasksEveryURLInAValueOrAKey(t *testing.T) {
	redacted := SensitiveData(map[string]any{
		"qa_url_list": "https://u4:p4@a.invalid,https://u5:p5@b.invalid",
		"qa_map":      map[string]any{"https://u6:p6@c.invalid": "x"},
		"urls":        []any{"https://u7:p7@d.invalid", "ok"},
		// A key is masked, but its value is still told sensitive by the key
		// as written.
		"git@github.com:org/r.git": map[string]any{"password": "s3cret"},
	}).(map[string]any)

	if got := redacted["qa_url_list"]; got != "https://********@a.invalid,https://********@b.invalid" {
		t.Errorf("Expected both URLs of the list masked, got %v", got)
	}
	if got := redacted["qa_map"]; !reflect.DeepEqual(got, map[string]any{"https://********@c.invalid": "x"}) {
		t.Errorf("Expected the URL used as a key masked, got %v", got)
	}
	if got := redacted["urls"]; !reflect.DeepEqual(got, []any{"https://********@d.invalid", "ok"}) {
		t.Errorf("Expected the URL in a list masked, got %v", got)
	}
	if got := redacted["********@github.com:org/r.git"]; !reflect.DeepEqual(got, map[string]any{"password": MaskedSecret}) {
		t.Errorf("Expected the key masked and its password masked, got %v", redacted)
	}
	for _, canary := range []string{"u4", "p4", "u5", "p5", "u6", "p6", "u7", "p7", "s3cret"} {
		if strings.Contains(fmt.Sprint(redacted), canary) {
			t.Errorf("Expected %q nowhere, got %v", canary, redacted)
		}
	}
}

// testDigest is an image digest: sha256 and its 64 hex digits.
const testDigest = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// TestURL_ShowsNoCredentialNearWhatLooksLikeAReferenceOrADigest masks the
// user info by a ${ that no } closes before it, and before what looks like
// an image digest.
func TestURL_ShowsNoCredentialNearWhatLooksLikeAReferenceOrADigest(t *testing.T) {
	for _, in := range []string{
		"password=${vault://kv//a/b;url=https://u:S3cret@h}",
		"${vault://kv//a/b,u:S3cret@h}",
		`{"a":"${vault://kv//a/b","u":"https://u:S3cret@h"}`,
		"${vault://kv//a/b https://u:S3cret}ss@h",
		"${vault://kv/a/b https://u:S3cret@h}",
		"https://u:S3cret@sha256:12345",
		"u:S3cret@sha256:abcdef",
		"https://u:S3cret@sha256:" + strings.Repeat("a", 64) + ":443",
		// git's scp-like host:path, with a host named sha256 and a path of
		// 64 hex digits: what is before the @ is a user info, not an image.
		"S3cret:x-oauth-basic@" + testDigest,
		"u:S3cret/x@" + testDigest,
		"https://u:S3cret@" + testDigest,
		"S3cret@" + testDigest,
	} {
		if got := URL(in); strings.Contains(got, "S3cret") {
			t.Errorf("URL(%q) = %q, which shows the password", in, got)
		}
	}
}

// TestURL_KeepsAReferenceWithAnAtSignAsWritten keeps a secret reference whose
// path or field holds an @, which a Vault path can.
func TestURL_KeepsAReferenceWithAnAtSignAsWritten(t *testing.T) {
	for in, want := range map[string]string{
		"${vault://secret/path/field@name}": "${vault://secret/path/field@name}",
		"${vault://kv/path@v2/key}":         "${vault://kv/path@v2/key}",
		// Read as one URL, as before, its user info runs to the reference's
		// @: the host before the reference is masked with it.
		"https://u:p@h ${vault://kv/a@b/c}":  "https://********${vault://kv/a@b/c}",
		"https://u:${vault://kv/a@b/c}@host": "https://********${vault://kv/a@b/c}@host",
	} {
		if got := URL(in); got != want {
			t.Errorf("URL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestURL_TakesTimeInLineWithTheString masks a long string with many
// references in about the time a short one takes per byte.
func TestURL_TakesTimeInLineWithTheString(t *testing.T) {
	s := strings.Repeat("${vault://a} u:p@h ", 1<<20/19)
	start := time.Now()
	URL(s)
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("URL of a 1 MiB string with a reference every 19 bytes took %v", took)
	}
}

// TestSensitiveData_KeepsEveryKeyMaskedIntoAnother keeps both entries of two
// keys masked into the same one, the same way at every run.
func TestSensitiveData_KeepsEveryKeyMaskedIntoAnother(t *testing.T) {
	for range 20 {
		redacted := SensitiveData(map[string]any{
			"https://u1:p1@h/x":    "a",
			"https://u2:p2@h/x":    "b",
			"https://********@h/x": "c",
		}).(map[string]any)
		want := map[string]any{
			"https://********@h/x":     "c",
			"https://********@h/x (2)": "a",
			"https://********@h/x (3)": "b",
		}
		if !reflect.DeepEqual(redacted, want) {
			t.Fatalf("Expected every entry kept, in the order of the keys as written, got %v", redacted)
		}
		// Keys written the same, of different types, in the order of their types.
		mixed := SensitiveData(map[any]any{1: "int", "1": "string"})
		if want := map[string]any{"1": "int", "1 (2)": "string"}; !reflect.DeepEqual(mixed, want) {
			t.Fatalf("Expected keys written the same kept in the order of their types, got %v", mixed)
		}
	}
}

// TestSensitiveData_MasksAURLUsedAsAKeyInAuthArgs masks a key of a Vault
// login's auth_args, and of a map under it, as a key anywhere else.
func TestSensitiveData_MasksAURLUsedAsAKeyInAuthArgs(t *testing.T) {
	args := SensitiveData(map[string]any{
		"auth_args": map[string]any{
			"https://u1:p1@h": "s3cret",
			"role":            "reader",
			"extra":           map[string]any{"https://u2:p2@h": "s3cret"},
		},
	}).(map[string]any)["auth_args"].(map[string]any)

	want := map[string]any{
		"https://********@h": MaskedSecret,
		"role":               "reader",
		"extra":              map[string]any{"https://********@h": MaskedSecret},
	}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("Expected the URL keys masked, got %v", args)
	}
}

func TestEndpoint_MasksTheUserInfoOfAValueKnownToBeAURLOrAnAddress(t *testing.T) {
	for in, want := range map[string]string{
		// Written from its scheme's :// or from its //: as URL masks it.
		"https://u:p@h:8200/v1": "https://********@h:8200/v1",
		"https://T0ken@h":       "https://********@h",
		"//u:p@h":               "//********@h",
		// An empty authority, as gRPC's dns:/// and unix:/// write one, keeps
		// its third /.
		"dns:///u:p@collector:4317":      "dns:///********@collector:4317",
		"unix:///u:p@sock":               "unix:///********@sock",
		"dns:///collector:4317":          "dns:///collector:4317",
		"https://collector.example:4318": "https://collector.example:4318",
		// Written without //, which a parser reads as a scheme and an opaque
		// part, the user being the scheme: everything before the last @ is
		// masked.
		"grpcuser:Grpc-pa55@collector.example:4317": "********@collector.example:4317",
		"Tok3n@collector.example":                   "********@collector.example",
		"Tok3n@collector.example:4317":              "********@collector.example:4317",
		"svc7:hunter2@ccp.example.com:443":          "********@ccp.example.com:443",
		"https:svc7:hunter2@ccp.example.com":        "********@ccp.example.com",
		"u:p@h/path?next=https://x":                 "********@h/path?next=https://x",
		" https://user:pw@collector.example:4318":   "********@collector.example:4318",
		"collector.example:4317":                    "collector.example:4317",
		"":                                          "",
	} {
		if got := Endpoint(in); got != want {
			t.Errorf("Endpoint(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSensitiveData_AuthArgsKeepsOnlyAStringUnderAKeptName keeps a field of
// a Vault login's auth_args only as its login reads it: under the exact name,
// and a string. A Vault login matches the names exactly.
func TestSensitiveData_AuthArgsKeepsOnlyAStringUnderAKeptName(t *testing.T) {
	args := SensitiveData(map[string]any{
		"auth_args": map[string]any{
			"Mount_Path": "s3cret",
			"role":       map[string]any{"x": "s3cret"},
			"username":   []any{"s3cret"},
		},
	}).(map[string]any)["auth_args"].(map[string]any)

	if args["Mount_Path"] != MaskedSecret {
		t.Errorf("Expected Mount_Path, not a kept name, to be masked, got %v", args["Mount_Path"])
	}
	if x := args["role"].(map[string]any)["x"]; x != MaskedSecret {
		t.Errorf("Expected a map under role to be masked, got %v", x)
	}
	if u := args["username"].([]any)[0]; u != MaskedSecret {
		t.Errorf("Expected a list under username to be masked, got %v", u)
	}
}

// TestSensitiveData_NonStringValues tests non-string sensitive fields
func TestSensitiveData_NonStringValues(t *testing.T) {
	original := map[string]any{
		"token_port":  8080,
		"secret_flag": true,
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)

	// Non-string sensitive fields should be preserved (not masked)
	// Note: reflection returns int64 for int types, not uint64
	if redactedMap["token_port"] != int64(8080) {
		t.Errorf("Expected token_port to be preserved, got %v (type %T)", redactedMap["token_port"], redactedMap["token_port"])
	}
	if redactedMap["secret_flag"] != true {
		t.Errorf("Expected secret_flag to be preserved, got %v", redactedMap["secret_flag"])
	}
}

// TestSensitiveData_URLValues tests url.Values redaction (map[string][]string)
func TestSensitiveData_URLValues(t *testing.T) {
	// Simulate url.Values structure: map[string][]string
	original := map[string]any{
		"client_id":     []string{"my-client-id"},
		"client_secret": []string{"my-secret-123"},
		"grant_type":    []string{"client_credentials"},
		"scope":         []string{"read write"},
	}

	redacted := SensitiveData(original)

	redactedMap := redacted.(map[string]any)

	// Verify sensitive field (slice) is masked
	clientSecretSlice, ok := redactedMap["client_secret"].([]any)
	if !ok {
		t.Fatalf("Expected client_secret to be []any, got %T", redactedMap["client_secret"])
	}
	if len(clientSecretSlice) != 1 {
		t.Fatalf("Expected client_secret slice to have 1 element, got %d", len(clientSecretSlice))
	}
	if clientSecretSlice[0] != MaskedSecret {
		t.Errorf("Expected client_secret[0] to be %s, got %v", MaskedSecret, clientSecretSlice[0])
	}

	// Verify non-sensitive fields are preserved
	clientIDSlice := redactedMap["client_id"].([]any)
	if clientIDSlice[0] != "my-client-id" {
		t.Errorf("Expected client_id to be preserved, got %v", clientIDSlice[0])
	}

	grantTypeSlice := redactedMap["grant_type"].([]any)
	if grantTypeSlice[0] != "client_credentials" {
		t.Errorf("Expected grant_type to be preserved, got %v", grantTypeSlice[0])
	}

	// Verify original is NOT mutated
	if original["client_secret"].([]string)[0] != "my-secret-123" {
		t.Error("Original map was mutated!")
	}
}

// TestIsSensitiveField tests the field name pattern matching
func TestIsSensitiveField(t *testing.T) {
	tests := []struct {
		fieldName string
		want      bool
	}{
		{"client_secret", true},
		{"clientSecret", true},
		{"CLIENT_SECRET", true},
		{"password", true},
		{"Password", true},
		{"private_key", true},
		{"privateKey", true},
		{"access_token", true},
		{"accessToken", true},
		{"token", true},
		{"Token", true},
		{"api_key", true},
		{"apiKey", true},
		{"secret", true},
		{"bearer", true},
		{"jwt", true},
		{"secret_id", true}, // A Vault AppRole's credential
		{"role_id", true},   // Its role: Vault accepts it alone for a role that binds no secret_id
		{"client_id", false},
		{"username", false},
		{"url", false},
		{"target", false},
		{"token_url", false},         // Should NOT match - not exact "token"
		{"secret_name", false},       // Should NOT match - not exact "secret"
		{"my_custom_secret", true},   // Should match - ends with "_secret"
		{"my_custom_token", true},    // Should match - ends with "_token"
		{"my_custom_password", true}, // Should match - ends with "_password"
		{"oauth_private_key", true},  // Should match - ends with "_private_key"
		{"oauth_api_key", true},      // Should match - ends with "_api_key"
		{"partition_key", false},     // Should NOT match - not a sensitive key type
		{"sort_key", false},          // Should NOT match - not a sensitive key type
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			result := isSensitiveField(tt.fieldName)
			if result != tt.want {
				t.Errorf("isSensitiveField(%q) = %v, want %v", tt.fieldName, result, tt.want)
			}
		})
	}
}

// TestArgs tests command-line argument redaction
func TestArgs(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "basic client secret",
			input: []string{"--diode-client-secret", "secret123", "--host", "localhost"},
			want:  []string{"--diode-client-secret", MaskedSecret, "--host", "localhost"},
		},
		{
			name:  "multiple sensitive flags",
			input: []string{"--client-id", "id123", "--client-secret", "secret123", "--password", "pass123"},
			want:  []string{"--client-id", "id123", "--client-secret", MaskedSecret, "--password", MaskedSecret},
		},
		{
			name:  "no sensitive flags",
			input: []string{"--host", "localhost", "--port", "8080"},
			want:  []string{"--host", "localhost", "--port", "8080"},
		},
		{
			name:  "sensitive flag at end without value",
			input: []string{"--host", "localhost", "--client-secret"},
			want:  []string{"--host", "localhost", "--client-secret"},
		},
		{
			name:  "sensitive flag followed by another flag (security: mask anyway)",
			input: []string{"--client-secret", "--host", "localhost"},
			want:  []string{"--client-secret", MaskedSecret, "localhost"},
		},
		{
			name:  "empty args",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "nil args",
			input: nil,
			want:  nil,
		},
		{
			name:  "token flag",
			input: []string{"--token", "mytoken123", "--url", "https://example.com"},
			want:  []string{"--token", MaskedSecret, "--url", "https://example.com"},
		},
		{
			name:  "api-key flag",
			input: []string{"--api-key", "key123"},
			want:  []string{"--api-key", MaskedSecret},
		},
		{
			name:  "private key with PEM format (starts with dashes)",
			input: []string{"--private-key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "--host", "localhost"},
			want:  []string{"--private-key", MaskedSecret, "--host", "localhost"},
		},
		{
			name:  "password that starts with dash",
			input: []string{"--password", "-myWeirdPassword123"},
			want:  []string{"--password", MaskedSecret},
		},
		{
			name:  "token that starts with double dash",
			input: []string{"--token", "--someTokenValue"},
			want:  []string{"--token", MaskedSecret},
		},
		{
			name:  "client secret followed by flag-like value",
			input: []string{"--client-secret", "-x-custom-header-value", "--url", "https://example.com"},
			want:  []string{"--client-secret", MaskedSecret, "--url", "https://example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Store original for mutation check
			var originalCopy []string
			if tt.input != nil {
				originalCopy = make([]string, len(tt.input))
				copy(originalCopy, tt.input)
			}

			result := Args(tt.input)

			if !reflect.DeepEqual(result, tt.want) {
				t.Errorf("Args() = %v, want %v", result, tt.want)
			}

			// Verify original is NOT mutated
			if tt.input != nil && !reflect.DeepEqual(tt.input, originalCopy) {
				t.Error("Original args slice was mutated!")
			}
		})
	}
}

// TestArgs_RealBackendExamples tests real backend argument patterns
func TestArgs_RealBackendExamples(t *testing.T) {
	// Simulate snmp-discovery backend args
	snmpArgs := []string{
		"--dry-run",
		"--dry-run-output-dir", "/tmp/output",
		"--diode-app-name-prefix", "test-agent",
		"--host", "localhost",
		"--port", "8070",
	}
	result := Args(snmpArgs)
	// No sensitive data, should be unchanged
	if !reflect.DeepEqual(result, snmpArgs) {
		t.Error("Non-sensitive snmp args were modified")
	}

	// Simulate with diode credentials
	diodeArgs := []string{
		"--diode-target", "https://diode.example.com",
		"--diode-client-id", "client123",
		"--diode-client-secret", "secret123",
		"--diode-app-name-prefix", "test-agent",
		"--host", "localhost",
		"--port", "8070",
	}
	result = Args(diodeArgs)
	expected := []string{
		"--diode-target", "https://diode.example.com",
		"--diode-client-id", "client123",
		"--diode-client-secret", MaskedSecret,
		"--diode-app-name-prefix", "test-agent",
		"--host", "localhost",
		"--port", "8070",
	}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Diode args redaction failed.\nGot:  %v\nWant: %v", result, expected)
	}
}

// TestIsSensitiveArg tests CLI flag pattern matching
func TestIsSensitiveArg(t *testing.T) {
	tests := []struct {
		arg  string
		want bool
	}{
		{"--diode-client-secret", true},
		{"--client-secret", true},
		{"--CLIENT-SECRET", true},
		{"--password", true},
		{"--Password", true},
		{"--token", true},
		{"--api-key", true},
		{"--auth-token", true},
		{"--private-key", true},
		{"--bearer", true},
		{"--jwt", true},
		{"--my-custom-secret", true},
		{"--my-custom-password", true},
		{"--my-custom-token", true},
		{"--my-custom-api-key", true},
		{"--my-custom-private-key", true},
		{"--sort-key", false},      // Should not match - not a sensitive key type
		{"--partition-key", false}, // Should not match - not a sensitive key type
		{"--host", false},
		{"--port", false},
		{"--client-id", false},
		{"--url", false},
		{"--target", false},
		{"--dry-run", false},
	}

	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			result := isSensitiveArg(tt.arg)
			if result != tt.want {
				t.Errorf("isSensitiveArg(%q) = %v, want %v", tt.arg, result, tt.want)
			}
		})
	}
}
