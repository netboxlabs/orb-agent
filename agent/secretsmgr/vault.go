package secretsmgr

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-co-op/gocron/v2"
	vault "github.com/hashicorp/vault/api"

	"github.com/netboxlabs/orb-agent/agent/config"
)

var _ Manager = (*vaultManager)(nil)

type vaultManager struct {
	logger    *slog.Logger
	config    config.VaultManager
	ctx       context.Context
	client    *vault.Client
	usedVars  map[string]cachedSecret
	callback  func(map[string]bool)
	auth      authMethod
	token     *vault.Secret
	scheduler gocron.Scheduler
}

func (v *vaultManager) Start(ctx context.Context) error {
	v.ctx = ctx
	v.usedVars = make(map[string]cachedSecret)

	config := vault.DefaultConfig()

	config.Address = v.config.Address
	if v.config.Timeout == nil || *v.config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	} else {
		config.Timeout = time.Duration(*v.config.Timeout) * time.Second
	}

	if v.config.Auth == "" {
		return fmt.Errorf("no auth method specified")
	}

	var err error
	v.client, err = vault.NewClient(config)
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

	if v.config.Schedule != nil {
		s, err := gocron.NewScheduler()
		if err != nil {
			return fmt.Errorf("failed to create scheduler: %w", err)
		}

		v.scheduler = s
		task := gocron.NewTask(v.pollSecrets)

		if _, err = v.scheduler.NewJob(gocron.CronJob(*v.config.Schedule, false), task,
			gocron.WithSingletonMode(gocron.LimitModeReschedule)); err != nil {
			return fmt.Errorf("failed to create polling job: %w", err)
		}

		v.logger.Info("Starting vault secret polling", "cron interval", *v.config.Schedule)
		v.scheduler.Start()
	}

	if err = v.addTokenLifecycleWatcher(); err != nil {
		return err
	}

	return nil
}

// RegisterUpdatePoliciesCallback registers a callback function to be called when secrets are updated
func (v *vaultManager) RegisterUpdatePoliciesCallback(callback func(map[string]bool)) {
	v.callback = callback
}

// SolvePolicySecrets processes a policy payload and replaces vault references with their values.
func (v *vaultManager) SolvePolicySecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	newPayload := payload
	processed, err := processValue(payload.Data, "vault", payload.ID, v.resolveBody)
	if err != nil {
		return payload, err
	}
	newPayload.Data = processed
	return newPayload, nil
}

func (v *vaultManager) pollSecrets() {
	if len(v.usedVars) == 0 || v.callback == nil {
		return
	}

	v.logger.Debug("Polling vault secrets for changes", "secretCount", len(v.usedVars))
	changedPolicyIDs := make(map[string]bool)

	// Check each cached secret
	for path, cachedSecret := range v.usedVars {
		currentValue, err := v.getSecret(path)
		if err != nil {
			v.logger.Error("Failed to retrieve secret during polling", "path", path, "error", err)
			for id := range cachedSecret.policyIDs {
				changedPolicyIDs[id] = false
			}
			continue
		}

		if currentValue != cachedSecret.Value {
			v.logger.Info("Detected changed secret", "path", path)
			cachedSecret.Value = currentValue
			v.usedVars[path] = cachedSecret
			for id := range cachedSecret.policyIDs {
				changedPolicyIDs[id] = true
			}
		}
	}

	if len(changedPolicyIDs) > 0 {
		v.logger.Info("Calling update callback for changed secrets", "policyCount", len(changedPolicyIDs))
		v.callback(changedPolicyIDs)
	}
}

// SolveConfigSecrets processes the configuration secrets and replaces vault references with their values.
func (v *vaultManager) SolveConfigSecrets(backends map[string]any, configManager config.ManagerConfig) (map[string]any, config.ManagerConfig, error) {
	processedBackends, err := processValue(backends, "vault", "_backends", v.resolveBody)
	if err != nil {
		return backends, configManager, fmt.Errorf("failed to process backends: %w", err)
	}
	newBackends, ok := processedBackends.(map[string]any)
	if !ok {
		return backends, configManager, fmt.Errorf("failed to cast processed backends to map[string]any")
	}

	configManagerMap, err := structToMap(configManager)
	if err != nil {
		return backends, configManager, fmt.Errorf("failed to convert config manager to map: %w", err)
	}
	processedConfigManagerMap, err := processValue(configManagerMap, "vault", "_config_manager", v.resolveBody)
	if err != nil {
		return backends, configManager, fmt.Errorf("failed to process config manager: %w", err)
	}
	newConfigManager, err := mapToStruct[config.ManagerConfig](processedConfigManagerMap)
	if err != nil {
		return backends, configManager, fmt.Errorf("failed to convert processed map to config manager: %w", err)
	}

	// Do not track updates on config vars
	v.usedVars = make(map[string]cachedSecret)

	return newBackends, newConfigManager, nil
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

// resolveBody is the Vault-specific resolver passed to the shared walker.
// "body" is the substring after "vault://" and before "}", i.e. the kv path.
func (v *vaultManager) resolveBody(body, policyID string) (string, error) {
	if secrets, exists := v.usedVars[body]; exists {
		secrets.policyIDs[policyID] = true
		v.usedVars[body] = secrets
		return secrets.Value, nil
	}

	value, err := v.getSecret(body)
	if err != nil {
		return "", err
	}

	v.usedVars[body] = cachedSecret{
		Value:     value,
		policyIDs: map[string]bool{policyID: true},
	}
	return value, nil
}

// processString delegates to the shared resolver walker using the vault scheme.
func (v *vaultManager) processString(s string, id string) (string, error) {
	return processString(s, "vault", id, v.resolveBody)
}

// processMap delegates to the shared resolver walker using the vault scheme.
func (v *vaultManager) processMap(m map[string]any, id string) (map[string]any, error) {
	return processMap(m, "vault", id, v.resolveBody)
}

// processSlice delegates to the shared resolver walker using the vault scheme.
func (v *vaultManager) processSlice(s []any, id string) ([]any, error) {
	return processSlice(s, "vault", id, v.resolveBody)
}

// getSecret retrieves a secret from the vault
func (v *vaultManager) getSecret(path string) (string, error) {
	// Split the path by forward slashes
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid vault path format: %s", path)
	}
	secret, err := v.client.KVv2(parts[0]).Get(v.ctx, strings.Join(parts[1:len(parts)-1], "/"))
	if err != nil {
		return "", fmt.Errorf("failed to get secret path %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("secret not found: %s", path)
	}
	value, ok := secret.Data[parts[len(parts)-1]]
	if !ok {
		return "", fmt.Errorf("secret not found: %s", path)
	}
	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("secret is not a string: %s", path)
	}
	if strValue == "" {
		return "", fmt.Errorf("secret is empty: %s", path)
	}
	return strValue, nil
}
