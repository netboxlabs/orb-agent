package secretsmgr

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
	"go.uber.org/zap"

	"github.com/netboxlabs/orb-agent/agent/config"
)

var _ Manager = (*vaultManager)(nil)

type vaultManager struct {
	logger   *zap.Logger
	config   config.VaultManager
	ctx      context.Context
	client   *vault.Client
	usedVars map[string]cachedSecret
}

type cachedSecret struct {
	Value     string         // The actual secret value
	policyIDs map[string]any // The IDs of policies that have used this secret
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

	var err error
	v.client, err = vault.NewClient(config)
	if err != nil {
		return err
	}

	if v.config.Namespace != "" {
		v.client.SetNamespace(v.config.Namespace)
	}

	// Authenticate
	v.client.SetToken(v.config.Token)

	// Validate token by calling LookupSelf
	_, err = v.client.Auth().Token().LookupSelf()
	if err != nil {
		return err
	}
	return nil
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
	if match == nil || len(match) < 4 {
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
		policyIDs: map[string]any{id: true},
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
