package secretsmgr

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"

	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/redact"
)

var _ Manager = (*vaultManager)(nil)

type vaultManager struct {
	pollingBase

	config    config.VaultManager
	preLogger *slog.Logger
	client    *vault.Client
	auth      authMethod
	token     *vault.Secret

	// loginMu serializes logging in again, which the token's watcher and the
	// reads Vault refuses for the token can each start: the client's token
	// changes only under it once the manager started.
	loginMu sync.Mutex
	// loginFailing is set while logging in again fails, so that the agent
	// says it once, at ERROR, until a login works again.
	loginFailing bool
	// tokenEndedSaid is set once the agent said the token it was given
	// ended, which token auth cannot log in again for.
	tokenEndedSaid bool
	// stopWatch stops the watcher of the token the client holds.
	stopWatch func()
	// lastTry is when the agent last tried to log in again for a read, or
	// failed to log in again: it tries at most once every loginInterval.
	lastTry time.Time
	// now reads the time, which tests set.
	now func() time.Time
}

// loginInterval is the least time between two tries to log in again for a
// read, and after a login that failed. A token whose policy does not let it
// look itself up cannot tell Vault's refusal of a path it may not read from
// the end of the token, and a login that fails, as for a password rotated in
// a directory, counts against the account: neither is tried at every read.
// It is under a minute so that each poll of a schedule of one minute can try.
const loginInterval = 50 * time.Second

// errAddressNotAURL refuses a Vault address no URL parser reads. The parse
// error would quote the address, and a password it carries with it.
var errAddressNotAURL = errors.New("sources.vault.address is not a URL: a / ? # % or space in the user or password it carries must be percent-encoded")

// withoutUserInfo returns a Vault address without the user and password it
// carries, as it does for a proxy that asks for basic auth in front of Vault,
// and the Authorization header that sends them. The Vault client would send
// them from the address, but it quotes its address in the text of every
// error it returns, which the agent logs and reports.
func withoutUserInfo(address string) (string, string, error) {
	u, err := url.Parse(address)
	if err != nil {
		return "", "", errAddressNotAURL
	}
	if u.User == nil {
		if strings.Contains(address, "@") {
			// A parser read the @ as part of a path, query or fragment, as
			// when a user holds a / ? or # that is not escaped: the client
			// would call the user as the host, and quote the address.
			return "", "", errAddressNotAURL
		}
		return address, "", nil
	}
	password, _ := u.User.Password()
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+password))
	u.User = nil
	return u.String(), header, nil
}

func (v *vaultManager) Start(ctx context.Context) error {
	if v.config.Mount != "" && hasEmptySegment(v.config.Mount) {
		return fmt.Errorf("invalid sources.vault.mount %q: contains an empty path segment", v.config.Mount)
	}

	// The address is checked before it is logged: one no URL parser reads as
	// one is refused, and where its user info ends is a guess.
	address, basicAuth, err := withoutUserInfo(v.config.Address)
	if err != nil {
		return err
	}
	if v.now == nil {
		v.now = time.Now
	}
	v.preLogger.Info("starting secrets manager", "active", "vault", "address", redact.URL(v.config.Address))

	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = address
	if v.config.Timeout == nil || *v.config.Timeout == 0 {
		vaultCfg.Timeout = 60 * time.Second
	} else {
		vaultCfg.Timeout = time.Duration(*v.config.Timeout) * time.Second
	}

	if v.config.Auth == "" {
		return fmt.Errorf("no auth method specified")
	}

	v.client, err = vault.NewClient(vaultCfg)
	if err != nil {
		return err
	}
	if basicAuth != "" {
		v.client.AddHeader("Authorization", basicAuth)
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
	if err := v.watchToken(v.token); err != nil {
		return err
	}
	// Authentication above round-tripped to the server, so the connection is
	// genuinely validated at this point — unlike the other managers, which
	// only reach their backend on first fetch.
	v.preLogger.Info("secrets manager connection established", "active", "vault")
	return nil
}

// watchToken renews the token the agent logged in with, while Vault renews
// it, and logs in again once Vault renews it no longer: at its max TTL, or
// when renewals keep failing. Without it the token ends, and every read with
// it, until a restart. It stops the watcher of the token it replaces: one
// left running would renew a token the agent no longer uses until its max
// TTL. The caller holds v.loginMu, or is the manager's start.
func (v *vaultManager) watchToken(secret *vault.Secret) error {
	if v.stopWatch != nil {
		v.stopWatch()
		v.stopWatch = nil
	}
	if secret == nil || secret.Auth == nil ||
		!secret.Auth.Renewable || secret.Auth.LeaseDuration == 0 {
		return nil
	}

	lw, err := v.client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret:        secret,
		RenewBehavior: vault.RenewBehaviorIgnoreErrors,
	})
	if err != nil {
		return err
	}

	stop := make(chan struct{})
	var once sync.Once
	v.stopWatch = func() { once.Do(func() { close(stop) }) }

	go lw.Start()

	go func() {
		defer lw.Stop()
		for {
			select {
			case <-v.ctx.Done():
				return

			case <-stop:
				return

			case err := <-lw.DoneCh():
				attrs := []any{}
				if err != nil {
					attrs = append(attrs, "error", err)
				}
				v.logger.Info("the Vault token can be renewed no longer", attrs...)
				v.loginAgain(secret.Auth.ClientToken)
				return

			case output := <-lw.RenewCh():
				v.logger.Info("Token renewed", "renewedAt", output.RenewedAt)
			}
		}
	}()

	return nil
}

// loginAgainIfEnded logs in again in place of the token stale, a read with
// which Vault refused, if Vault no longer accepts it. Vault answers a 403
// both for a token that ended and for a path the token may not read, so it
// is asked about the token first: a valid token is not logged in again for,
// at every read of such a path. A token whose policy does not let it look
// itself up gets a 403 for that too, so the agent tries this at most once
// every loginInterval. It reports whether the read is worth trying again.
func (v *vaultManager) loginAgainIfEnded(stale string) bool {
	v.loginMu.Lock()
	defer v.loginMu.Unlock()
	if v.client.Token() != stale {
		return true
	}
	if v.triedLately() {
		return false
	}
	_, err := v.client.Auth().Token().LookupSelfWithContext(v.ctx)
	if err == nil || !isForbidden(err) {
		return false
	}
	v.lastTry = v.now()
	return v.loginAgainLocked(stale)
}

// loginAgain logs in again in place of the token stale, which Vault renews no
// longer, unless a login failed less than loginInterval ago.
func (v *vaultManager) loginAgain(stale string) bool {
	v.loginMu.Lock()
	defer v.loginMu.Unlock()
	if v.client.Token() != stale {
		return true
	}
	if v.triedLately() {
		return false
	}
	return v.loginAgainLocked(stale)
}

// triedLately reports whether the agent tried to log in again for a read, or
// failed to log in again, less than loginInterval ago. The caller holds
// v.loginMu.
func (v *vaultManager) triedLately() bool {
	return !v.lastTry.IsZero() && v.now().Sub(v.lastTry) < loginInterval
}

// loginAgainLocked logs in again in place of the token stale, unless a login
// already replaced it, and reports whether the client holds another token.
// An auth method that cannot log in again is said once. A login that fails
// is said once, at ERROR, and tried again at a read loginInterval later. The
// caller holds v.loginMu.
func (v *vaultManager) loginAgainLocked(stale string) bool {
	if v.client.Token() != stale {
		return true
	}
	if reason := cannotLoginAgain(v.auth); reason != "" {
		if !v.tokenEndedSaid {
			v.tokenEndedSaid = true
			v.logger.Error("the agent's Vault token ends, and " + reason +
				": secrets from Vault fail to resolve once it ended, until the agent is restarted with valid credentials")
		}
		return false
	}
	secret, err := v.auth.vaultAuthenticate(v.ctx, v.client)
	if err != nil {
		v.lastTry = v.now()
		if v.ctx.Err() != nil {
			// The agent is stopping: the login was cut short, not refused.
			return false
		}
		if !v.loginFailing {
			v.loginFailing = true
			v.logger.Error("failed to log in to Vault again: secrets from Vault fail to resolve until a login works",
				"auth", v.config.Auth, "error", err)
		} else {
			v.logger.Debug("failed to log in to Vault again", "auth", v.config.Auth, "error", err)
		}
		return false
	}
	v.loginFailing = false
	v.token = secret
	v.logger.Info("logged in to Vault again", "auth", v.config.Auth)
	if err := v.watchToken(secret); err != nil {
		v.logger.Warn("the Vault token from the new login is not renewed", "error", err)
	}
	return true
}

// cannotLoginAgain returns why the agent cannot log in again with auth, or
// "" when it can.
func cannotLoginAgain(auth authMethod) string {
	switch a := auth.(type) {
	case *AuthToken:
		return "token auth cannot log in again"
	case *AuthAppRole:
		if a.WrappingToken {
			return "a wrapped secret_id cannot log in again: Vault unwraps it once"
		}
	}
	return ""
}

// isForbidden reports whether err is Vault's 403.
func isForbidden(err error) bool {
	var respErr *vault.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden
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
	token := v.client.Token()
	secret, err := v.client.KVv2(ref.mount).Get(v.ctx, ref.path)
	if err != nil && isForbidden(err) && v.loginAgainIfEnded(token) {
		// The token the read was made with ended: read again with the one
		// from the new login.
		secret, err = v.client.KVv2(ref.mount).Get(v.ctx, ref.path)
	}
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
