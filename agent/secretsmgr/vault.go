package secretsmgr

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
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

type cachedSecret struct {
	Value     string          // The actual secret value
	policyIDs map[string]bool // The IDs of policies that have used this secret
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

		v.logger.Info("Starting vault secret polling", slog.String("cron interval", *v.config.Schedule))
		v.scheduler.Start()
	}

	if err = v.addTokenLifecycleWatcher(); err != nil {
		return err
	}

	return nil
}

// RegisterUpdateCallback registers a callback function to be called when secrets are updated
func (v *vaultManager) RegisterUpdateCallback(callback func(map[string]bool)) {
	v.callback = callback
}

// SolveSecrets processes a policy payload and replaces vault references with environment variables
func (v *vaultManager) SolveSecrets(payload config.PolicyPayload) (config.PolicyPayload, error) {
	// Create a copy of the payload
	newPayload := payload

	// Process the Data field
	processedData, err := v.processValue(payload.Data, payload.ID)
	if err != nil {
		return payload, err
	}

	newPayload.Data = processedData
	return newPayload, nil
}

func (v *vaultManager) pollSecrets() {
	if len(v.usedVars) == 0 || v.callback == nil {
		return
	}

	v.logger.Debug("Polling vault secrets for changes", slog.Int("secretCount", len(v.usedVars)))
	changedPolicyIDs := make(map[string]bool)

	// Check each cached secret
	for path, cachedSecret := range v.usedVars {
		currentValue, err := v.getSecret(path)
		if err != nil {
			v.logger.Error("Failed to retrieve secret during polling", slog.String("path", path), slog.Any("error", err))
			for id := range cachedSecret.policyIDs {
				changedPolicyIDs[id] = false
			}
			continue
		}

		if currentValue != cachedSecret.Value {
			v.logger.Info("Detected changed secret", slog.String("path", path))
			cachedSecret.Value = currentValue
			v.usedVars[path] = cachedSecret
			for id := range cachedSecret.policyIDs {
				changedPolicyIDs[id] = true
			}
		}
	}

	if len(changedPolicyIDs) > 0 {
		v.logger.Info("Calling update callback for changed secrets", slog.Int("policyCount", len(changedPolicyIDs)))
		v.callback(changedPolicyIDs)
	}
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
					v.logger.Error("Token renewal failed", slog.Any("error", err))
				}
			case output := <-lw.RenewCh():
				v.logger.Info("Token renewed", slog.Time("renewedAt", output.RenewedAt))
			}
		}
	}()

	return nil
}

func (v *vaultManager) processValue(value any, id string) (any, error) {
	switch val := value.(type) {
	case string:
		return v.processString(val, id)
	case map[string]any:
		return v.processMap(val, id)
	case []any:
		return v.processSlice(val, id)
	default:
		return val, nil
	}
}

// processString processes a string and replaces vault references
func (v *vaultManager) processString(s string, id string) (string, error) {
	re := regexp.MustCompile(`\${vault://([^}]+)}`)
	if !re.MatchString(s) {
		return s, nil
	}

	match := re.FindStringSubmatchIndex(s)
	if len(match) < 4 {
		return "", fmt.Errorf("failed to find vault reference in string: %s", s)
	}

	vaultPath := s[match[2]:match[3]]

	if secrets, exists := v.usedVars[vaultPath]; exists {
		secrets.policyIDs[id] = true
		v.usedVars[vaultPath] = secrets
		return secrets.Value, nil
	}

	secret, err := v.getSecret(vaultPath)
	if err != nil {
		return "", err
	}

	v.usedVars[vaultPath] = cachedSecret{
		Value:     secret,
		policyIDs: map[string]bool{id: true},
	}

	return secret, nil
}

// processMap processes a map recursively and replaces vault references in its values
func (v *vaultManager) processMap(m map[string]any, id string) (map[string]any, error) {
	result := make(map[string]any)
	for key, val := range m {
		processedVal, err := v.processValue(val, id)
		if err != nil {
			return nil, fmt.Errorf("failed to process value for key %s: %w", key, err)
		}
		result[key] = processedVal
	}
	return result, nil
}

// processSlice processes a slice recursively and replaces vault references in its elements
func (v *vaultManager) processSlice(s []any, id string) ([]any, error) {
	result := make([]any, len(s))
	for i, val := range s {
		processedVal, err := v.processValue(val, id)
		if err != nil {
			return nil, fmt.Errorf("failed to process value at index %d: %w", i, err)
		}
		result[i] = processedVal
	}
	return result, nil
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
