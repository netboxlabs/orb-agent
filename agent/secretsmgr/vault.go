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
	// lookupDenied is set when Vault refused the token the client holds a
	// lookup of itself right after the login that gave it: a read Vault
	// refuses then makes the agent log in again only past tokenEnd.
	lookupDenied bool
	// lookupDeniedSaid is set once the agent said so, at WARN.
	lookupDeniedSaid bool
	// tokenEnd is when the token the client holds ends, as far as the agent
	// knows: the end of the lease its login gave, moved by each renewal its
	// watcher reports, and the time its watcher ended without replacing it.
	// It is zero for a token with no lease, which does not end.
	tokenEnd time.Time
	// stopWatch stops the watcher of the token the client holds.
	stopWatch func()
	// lastTry is when the agent last tried to log in again for a read, or
	// failed to log in again: it tries at most once every loginInterval.
	lastTry time.Time
	// now reads the time, which tests set.
	now func() time.Time
}

// loginInterval is the least time between two tries to log in again for a
// read, and after a login that failed. A login that fails, as for a password
// rotated in a directory, counts against the account: it is not tried at
// every read. It is under a minute so that each poll of a schedule of one
// minute can try.
const loginInterval = 50 * time.Second

// lookupTimeout is how long the agent waits on Vault for the lookup of a
// token right after its login, which holds up the start or the read that
// logged in: one Vault does not answer leaves whether the token may look
// itself up unknown.
const lookupTimeout = 5 * time.Second

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
	v.tokenEnd = v.leaseEnd(v.token)

	v.init(ctx, v.preLogger, "vault", v.fetch)
	v.checkLookupLocked()

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
				v.renewed(secret.Auth.ClientToken, output.Secret)
			}
		}
	}()

	return nil
}

// loginAgainIfEnded logs in again in place of the token stale, a read with
// which Vault refused, if Vault no longer accepts it. Vault answers a 403
// both for a token that ended and for a path the token may not read, so it
// is asked about the token first: a valid token is not logged in again for,
// at every read of such a path. A token Vault refused that question right
// after its login (see checkLookupLocked) would be refused it again: it is
// taken to have ended only past the end the agent knows for it. It reports
// whether the read is worth trying again.
func (v *vaultManager) loginAgainIfEnded(stale string) bool {
	v.loginMu.Lock()
	defer v.loginMu.Unlock()
	if v.client.Token() != stale {
		return true
	}
	if v.triedLately() {
		return false
	}
	if v.lookupDenied {
		if v.tokenEnd.IsZero() || v.now().Before(v.tokenEnd) {
			return false
		}
	} else if _, err := v.client.Auth().Token().LookupSelfWithContext(v.ctx); err == nil || !isForbidden(err) {
		return false
	}
	v.lastTry = v.now()
	return v.loginAgainLocked(stale)
}

// checkLookupLocked asks Vault about the token the agent just logged in with,
// waiting lookupTimeout at most. A token whose policy does not let it look
// itself up, as a role with token_no_default_policy gives, gets a 403 for it
// while it is valid, and can't tell a path it may not read from its own end.
// The agent says so once. Any other error leaves it unknown, and the token is
// asked about at reads as any other. An auth method that cannot log in again
// is not asked about. The caller holds v.loginMu, or is the manager's start.
func (v *vaultManager) checkLookupLocked() {
	v.lookupDenied = false
	if cannotLoginAgain(v.auth) != "" {
		return
	}
	ctx, cancel := context.WithTimeout(v.ctx, lookupTimeout)
	defer cancel()
	if _, err := v.client.Auth().Token().LookupSelfWithContext(ctx); !isForbidden(err) {
		return
	}
	v.lookupDenied = true
	if !v.lookupDeniedSaid {
		v.lookupDeniedSaid = true
		v.logger.Warn("the agent's Vault token may not look itself up (auth/token/lookup-self): "+
			"the agent cannot tell a path the token may not read from the end of the token, so a read "+
			"Vault refuses makes it log in again only once the token's lease ended",
			"auth", v.config.Auth)
	}
}

// leaseEnd returns when the lease secret gives a token ends, or zero for a
// token with no lease.
func (v *vaultManager) leaseEnd(secret *vault.Secret) time.Time {
	if secret == nil || secret.Auth == nil || secret.Auth.LeaseDuration <= 0 {
		return time.Time{}
	}
	return v.now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second)
}

// renewed moves the end the agent knows for the token to the end of the
// lease a renewal of it gave, while the client still holds it.
func (v *vaultManager) renewed(token string, renewal *vault.Secret) {
	v.loginMu.Lock()
	defer v.loginMu.Unlock()
	if v.client.Token() == token {
		v.tokenEnd = v.leaseEnd(renewal)
	}
}

// revokeReplaced revokes the token stale, which a login replaced, so that it
// does not stay valid in Vault until its own TTL. It does not hold up the
// login: a token whose policy does not let it revoke itself, or one that
// ended, is refused, and the agent goes on.
func (v *vaultManager) revokeReplaced(stale string) {
	client, err := v.client.CloneWithHeaders()
	if err != nil {
		v.logger.Debug("the Vault token a login replaced was not revoked", "error", err)
		return
	}
	client.SetToken(stale)
	go func() {
		if err := client.Auth().Token().RevokeSelfWithContext(v.ctx, ""); err != nil {
			v.logger.Debug("the Vault token a login replaced was not revoked", "error", err)
		}
	}()
}

// loginAgain logs in again in place of the token stale, which Vault renews no
// longer, unless a login failed less than loginInterval ago. When it does
// not, nothing renews the token or logs in again for it any more: the agent
// takes it to have ended, so that a read Vault refuses logs in again.
func (v *vaultManager) loginAgain(stale string) bool {
	v.loginMu.Lock()
	defer v.loginMu.Unlock()
	if v.client.Token() != stale {
		return true
	}
	if !v.triedLately() && v.loginAgainLocked(stale) {
		return true
	}
	v.tokenEnd = v.now()
	return false
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
// is said once, at ERROR, and is not tried again for loginInterval: then by
// the next read Vault refuses (see loginAgainIfEnded). The caller holds
// v.loginMu.
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
	v.tokenEnd = v.leaseEnd(secret)
	v.logger.Info("logged in to Vault again", "auth", v.config.Auth)
	v.revokeReplaced(stale)
	if err := v.watchToken(secret); err != nil {
		v.logger.Warn("the Vault token from the new login is not renewed", "error", err)
	}
	v.checkLookupLocked()
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
