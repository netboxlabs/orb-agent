package secretsmgr

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"

	"github.com/netboxlabs/orb-agent/agent/config"
)

var _ Manager = (*vaultManager)(nil)

type vaultManager struct {
	pollingBase

	config    config.VaultManager
	preLogger *slog.Logger
	client    *vault.Client
	auth      authMethod
	token     *vault.Secret
}

func (v *vaultManager) Start(ctx context.Context) error {
	if v.config.Mount != "" && hasEmptySegment(v.config.Mount) {
		return fmt.Errorf("invalid sources.vault.mount %q: contains an empty path segment", v.config.Mount)
	}

	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = v.config.Address
	if v.config.Timeout == nil || *v.config.Timeout == 0 {
		vaultCfg.Timeout = 60 * time.Second
	} else {
		vaultCfg.Timeout = time.Duration(*v.config.Timeout) * time.Second
	}

	if v.config.Auth == "" {
		return fmt.Errorf("no auth method specified")
	}

	var err error
	v.client, err = vault.NewClient(vaultCfg)
	if err != nil {
		return err
	}

	if v.config.Namespace != "" {
		v.client.SetNamespace(v.config.Namespace)
	}

	v.auth, err = newAuthentication(v.config.Auth, v.config.AuthArgs)
	if err != nil {
		return err
	}

	v.token, err = v.auth.vaultAuthenticate(ctx, v.client)
	if err != nil {
		return err
	}

	v.init(ctx, v.preLogger, "vault", v.fetch)

	if err := v.startScheduler(v.config.Schedule); err != nil {
		return err
	}
	return v.addTokenLifecycleWatcher()
}

func (v *vaultManager) addTokenLifecycleWatcher() error {
	if v.token == nil || v.token.Auth == nil ||
		!v.token.Auth.Renewable || v.token.Auth.LeaseDuration == 0 {
		return nil
	}

	lw, err := v.client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret:        v.token,
		RenewBehavior: vault.RenewBehaviorIgnoreErrors,
	})
	if err != nil {
		return err
	}

	go lw.Start()

	go func() {
		for {
			select {
			case <-v.ctx.Done():
				lw.Stop()
				return

			case err := <-lw.DoneCh():
				if err != nil {
					v.logger.Error("Token renewal failed", "error", err)
				}
			case output := <-lw.RenewCh():
				v.logger.Info("Token renewed", "renewedAt", output.RenewedAt)
			}
		}
	}()

	return nil
}

// vaultRef captures a parsed ${vault://...} reference.
type vaultRef struct {
	mount string
	path  string
	field string
}

// parseBody resolves a placeholder body into (mount, path, field) using one of
// three grammars, in priority order:
//
//  1. Fully qualified — "<mount>//<path-segments>/<field>". The first "//"
//     terminates the mount, so multi-segment mounts (e.g. "foo/bar") work
//     unambiguously.
//  2. Short form — "<path-segments>/<field>". Requires sources.vault.mount to
//     be configured; the configured mount is used and the body carries only
//     path/field.
//  3. Legacy form — "<mount>/<path-segments>/<field>". Single-segment mount.
//     Preserved verbatim for backward compatibility with existing
//     placeholders that pre-date this grammar; used only when neither "//"
//     appears nor a default mount is configured.
func (v *vaultManager) parseBody(body string) (vaultRef, error) {
	if body == "" {
		return vaultRef{}, fmt.Errorf("invalid vault reference: empty body")
	}

	if idx := strings.Index(body, "//"); idx >= 0 {
		mount := body[:idx]
		rest := body[idx+2:]
		if mount == "" {
			return vaultRef{}, fmt.Errorf("invalid vault reference %q: empty mount before '//'", body)
		}
		if err := validateMount(mount, body); err != nil {
			return vaultRef{}, err
		}
		return splitPathField(mount, rest, body)
	}

	if v.config.Mount != "" {
		if hasEmptySegment(v.config.Mount) {
			return vaultRef{}, fmt.Errorf("invalid sources.vault.mount %q: contains an empty path segment", v.config.Mount)
		}
		return splitPathField(v.config.Mount, body, body)
	}

	parts := strings.Split(body, "/")
	if len(parts) < 3 {
		return vaultRef{}, fmt.Errorf("invalid vault reference %q: legacy form requires '<mount>/<path>/<field>'; for multi-segment mounts use '<mount>//<path>/<field>' or set sources.vault.mount", body)
	}
	mount := parts[0]
	if mount == "" {
		return vaultRef{}, fmt.Errorf("invalid vault reference %q: empty mount", body)
	}
	return splitPathField(mount, strings.Join(parts[1:], "/"), body)
}

// hasEmptySegment reports whether s, split by "/", contains any empty
// segment — i.e. a leading "/", a trailing "/", or consecutive "//".
// Used to reject malformed mounts before they reach the Vault client.
func hasEmptySegment(s string) bool {
	for _, seg := range strings.Split(s, "/") {
		if seg == "" {
			return true
		}
	}
	return false
}

// validateMount rejects mounts that contain empty path segments (leading,
// trailing, or consecutive "/"). Catches inputs like "/foo/bar" or "foo//"
// that would otherwise reach the Vault client with a malformed mount.
func validateMount(mount, original string) error {
	if hasEmptySegment(mount) {
		return fmt.Errorf("invalid vault reference %q: mount contains an empty path segment", original)
	}
	return nil
}

// splitPathField extracts (path, field) from the part of the body that lives
// after the mount, validating that no segment is empty (no leading, trailing,
// or consecutive "/").
func splitPathField(mount, rest, original string) (vaultRef, error) {
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return vaultRef{}, fmt.Errorf("invalid vault reference %q: expected at least one path segment and a field after the mount", original)
	}
	field := parts[len(parts)-1]
	pathParts := parts[:len(parts)-1]
	if field == "" {
		return vaultRef{}, fmt.Errorf("invalid vault reference %q: empty field", original)
	}
	for _, seg := range pathParts {
		if seg == "" {
			return vaultRef{}, fmt.Errorf("invalid vault reference %q: empty path segment", original)
		}
	}
	return vaultRef{mount: mount, path: strings.Join(pathParts, "/"), field: field}, nil
}

// fetch retrieves a secret from Vault. See parseBody for the supported
// reference grammars.
func (v *vaultManager) fetch(body string) (string, error) {
	ref, err := v.parseBody(body)
	if err != nil {
		return "", err
	}
	resolved := fmt.Sprintf("mount=%q path=%q field=%q", ref.mount, ref.path, ref.field)
	secret, err := v.client.KVv2(ref.mount).Get(v.ctx, ref.path)
	if err != nil {
		return "", fmt.Errorf("failed to get secret path %s (%s): %w", body, resolved, err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("secret not found: %s (%s)", body, resolved)
	}
	value, ok := secret.Data[ref.field]
	if !ok {
		return "", fmt.Errorf("secret not found: %s (%s)", body, resolved)
	}
	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("secret is not a string: %s (%s)", body, resolved)
	}
	if strValue == "" {
		return "", fmt.Errorf("secret is empty: %s (%s)", body, resolved)
	}
	return strValue, nil
}
