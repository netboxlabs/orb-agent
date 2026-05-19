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

// fetch retrieves a secret from the vault. The body must be a slash-delimited
// path of the form "<mount>/<path-segments>/<field>".
func (v *vaultManager) fetch(body string) (string, error) {
	parts := strings.Split(body, "/")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid vault path format: %s", body)
	}
	secret, err := v.client.KVv2(parts[0]).Get(v.ctx, strings.Join(parts[1:len(parts)-1], "/"))
	if err != nil {
		return "", fmt.Errorf("failed to get secret path %s: %w", body, err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("secret not found: %s", body)
	}
	value, ok := secret.Data[parts[len(parts)-1]]
	if !ok {
		return "", fmt.Errorf("secret not found: %s", body)
	}
	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("secret is not a string: %s", body)
	}
	if strValue == "" {
		return "", fmt.Errorf("secret is empty: %s", body)
	}
	return strValue, nil
}
