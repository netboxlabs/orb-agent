package secretsmgr

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
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
	mu       sync.RWMutex
	client   *vault.Client
	usedVars map[string]cachedSecret
}

type cachedSecret struct {
	Value       string    // The actual secret value
	EnvVar      string    // Environment variable name
	LastFetched time.Time // When the secret was last fetched
}

func (v *vaultManager) Start(ctx context.Context) error {
	v.ctx = ctx
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

	// Create a map to track vault paths to environment variables
	envVarMap := make(map[string]string)

	// Process the Data field
	processedData, err := v.processValue(payload.Data, envVarMap)
	if err != nil {
		return payload, err
	}

	newPayload.Data = processedData
	return newPayload, nil
}

func (v *vaultManager) processValue(value any, envVarMap map[string]string) (any, error) {
	switch val := value.(type) {
	case string:
		return v.processString(val, envVarMap)
	case map[string]any:
		return v.processMap(val, envVarMap)
	case []any:
		return v.processSlice(val, envVarMap)
	default:
		return val, nil
	}
}

// processString processes a string and replaces vault references
func (v *vaultManager) processString(s string, envVarMap map[string]string) (string, error) {
	// Define a regular expression to match vault references
	// This pattern matches ${vault://vault/item/field} format
	re := regexp.MustCompile(`\${vault://([^}]+)}`)

	// Check if the string contains a vault reference
	if !re.MatchString(s) {
		return s, nil
	}

	// Replace all vault references in the string
	result := re.ReplaceAllStringFunc(s, func(match string) string {
		// Extract the vault path
		vaultPath := re.FindStringSubmatch(match)[1]

		// Check if we've already processed this vault path
		if envVar, exists := envVarMap[vaultPath]; exists {
			return "${" + envVar + "}"
		}

		// Retrieve the secret from the vault
		secret, err := v.getSecret(vaultPath)
		if err != nil {
			// Log the error and return the original match
			fmt.Printf("Error retrieving secret for %s: %v\n", vaultPath, err)
			return match
		}

		// Generate a unique environment variable name
		envVar := v.generateEnvVarName()

		// Set the environment variable
		if err != os.Setenv(envVar, secret) {
			fmt.Printf("Error setting environment variable %s: %v\n", envVar, err)
			return match
		}

		// Store the mapping for future reference
		envVarMap[vaultPath] = envVar
		v.logger.Error("Set environment variable: " + envVar + " for secret: " + secret)
		// Return the reference to the environment variable
		// return "${" + envVar + "}"
		return secret
	})

	return result, nil
}

// processMap processes a map recursively and replaces vault references in its values
func (v *vaultManager) processMap(m map[string]any, envVarMap map[string]string) (map[string]any, error) {
	result := make(map[string]any)

	for key, val := range m {
		processedVal, err := v.processValue(val, envVarMap)
		if err != nil {
			return nil, fmt.Errorf("failed to process value for key %s: %w", key, err)
		}
		result[key] = processedVal
	}

	return result, nil
}

// processSlice processes a slice recursively and replaces vault references in its elements
func (v *vaultManager) processSlice(s []any, envVarMap map[string]string) ([]any, error) {
	result := make([]any, len(s))

	for i, val := range s {
		processedVal, err := v.processValue(val, envVarMap)
		if err != nil {
			return nil, fmt.Errorf("failed to process value at index %d: %w", i, err)
		}
		result[i] = processedVal
	}

	return result, nil
}

// generateEnvVarName generates a unique environment variable name using timestamp, random bytes and a retry mechanism
func (v *vaultManager) generateEnvVarName() string {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Initialize the usedVars map if not already done
	if v.usedVars == nil {
		v.usedVars = make(map[string]cachedSecret)
	}

	// Generate a unique name with retries to avoid collisions
	for attempts := 0; attempts < 10; attempts++ {
		// Get current timestamp
		timestamp := time.Now().UnixNano()

		// Generate 4 random bytes
		randomBytes := make([]byte, 4)
		if _, err := rand.Read(randomBytes); err != nil {
			continue
		}

		return fmt.Sprintf("TMP_%d_%s", timestamp, hex.EncodeToString(randomBytes))
	}

	// Ultimate fallback - extremely unlikely to reach this point
	return fmt.Sprintf("TMP_%d_%d", time.Now().UnixNano(), time.Now().Add(time.Nanosecond).UnixNano())
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
		return "", fmt.Errorf("failed to get secret %s: %w", path, err)
	}
	// Check if the secret is nil
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
