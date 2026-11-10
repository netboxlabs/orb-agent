package secretsmgr

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/hashicorp/vault/api/auth/kubernetes"
	"github.com/hashicorp/vault/api/auth/ldap"
	"github.com/hashicorp/vault/api/auth/userpass"
	"go.yaml.in/yaml/v3"

	"github.com/netboxlabs/orb-agent/agent/config"
)

type authMethod interface {
	vaultAuthenticate(context.Context, *vault.Client) (*vault.Secret, error)
}

func newAuthentication(auth string, authArgs map[string]any) (authMethod, error) {
	var authObj authMethod

	switch auth {
	case "token":
		authObj = &AuthToken{}
	case "approle":
		authObj = &AuthAppRole{}
	case "userpass":
		authObj = &AuthUserPass{}
	case "kubernetes":
		authObj = &AuthKubernetes{}
	case "ldap":
		authObj = &AuthLDAP{}
	case "aws", "azure", "gcp":
		return nil, fmt.Errorf("auth method %s is not currently implemented", auth)
	default:
		return nil, fmt.Errorf("unsupported auth method: %s", auth)
	}

	if err := config.ResolveEnvInMap(authArgs); err != nil {
		return nil, fmt.Errorf("failed to resolve env in auth_args: %w", err)
	}

	// Convert the map to YAML
	yamlData, err := yaml.Marshal(authArgs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal auth_args: %w", err)
	}

	// Unmarshal YAML into the auth structure
	if err := yaml.Unmarshal(yamlData, authObj); err != nil {
		var typeErr *yaml.TypeError
		if errors.As(err, &typeErr) {
			// yaml.v3 quotes a value it cannot decode, which can be a
			// credential put in the wrong field: name the field and the type
			// it takes instead.
			return nil, fmt.Errorf("failed to unmarshal '%s' auth_args: %s", auth, mistypedArgs(authObj, authArgs))
		}
		return nil, fmt.Errorf("failed to unmarshal '%s' auth_args: %w", auth, err)
	}

	return authObj, nil
}

// mistypedArgs names each value of authArgs that does not decode into the
// field of authObj it sets, by the field and the type it takes, never by the
// value.
func mistypedArgs(authObj authMethod, authArgs map[string]any) string {
	var mistyped []string
	t := reflect.TypeOf(authObj).Elem()
	for i := range t.NumField() {
		field := t.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		value, ok := authArgs[name]
		if !ok {
			continue
		}
		data, err := yaml.Marshal(value)
		if err == nil {
			err = yaml.Unmarshal(data, reflect.New(field.Type).Interface())
		}
		if err != nil {
			mistyped = append(mistyped, fmt.Sprintf("auth_args.%s: expected %s", name, typeName(field.Type)))
		}
	}
	if len(mistyped) == 0 {
		return "a value has the wrong type"
	}
	return strings.Join(mistyped, "; ")
}

// typeName names the type a field of an auth method takes.
func typeName(t reflect.Type) string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Bool:
		return "a bool"
	case reflect.String:
		return "a string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "a number"
	default:
		return "a " + t.Kind().String()
	}
}

// AuthToken authenticates against Vault with a token.
type AuthToken struct {
	Token string `yaml:"token"`
}

// UnmarshalYAML for AuthToken validates required fields after unmarshaling
func (a *AuthToken) UnmarshalYAML(value *yaml.Node) error {
	type tempAuthToken AuthToken
	temp := tempAuthToken{}
	if err := value.Decode(&temp); err != nil {
		return err
	}
	*a = AuthToken(temp)
	if a.Token == "" {
		return fmt.Errorf("missing required field 'token'")
	}
	return nil
}

func (a *AuthToken) vaultAuthenticate(_ context.Context, cli *vault.Client) (*vault.Secret, error) {
	cli.SetToken(a.Token)
	secret, err := cli.Auth().Token().LookupSelf()
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// AuthAppRole authenticates against Vault with AppRole.
type AuthAppRole struct {
	RoleID        string  `yaml:"role_id"`
	SecretID      string  `yaml:"secret_id"`
	WrappingToken bool    `yaml:"wrapping_token,omitempty"`
	MountPath     *string `yaml:"mount_path,omitempty"`
}

// UnmarshalYAML for AuthAppRole validates required fields after unmarshaling
func (a *AuthAppRole) UnmarshalYAML(value *yaml.Node) error {
	type tempAuthAppRole AuthAppRole
	temp := tempAuthAppRole{}
	if err := value.Decode(&temp); err != nil {
		return err
	}
	*a = AuthAppRole(temp)
	if a.RoleID == "" {
		return fmt.Errorf("missing required field 'role_id'")
	}
	if a.SecretID == "" {
		return fmt.Errorf("missing required field 'secret_id'")
	}
	return nil
}

func (a *AuthAppRole) vaultAuthenticate(ctx context.Context, cli *vault.Client) (*vault.Secret, error) {
	secret := &approle.SecretID{FromString: string(a.SecretID)}

	var opts []approle.LoginOption
	if a.WrappingToken {
		opts = append(opts, approle.WithWrappingToken())
	}
	if a.MountPath != nil && *a.MountPath != "" {
		opts = append(opts, approle.WithMountPath(*a.MountPath))
	}

	auth, err := approle.NewAppRoleAuth(a.RoleID, secret, opts...)
	if err != nil {
		return nil, fmt.Errorf("auth.approle: %w", err)
	}
	s, err := cli.Auth().Login(ctx, auth)
	if err != nil {
		return nil, fmt.Errorf("auth.approle: %w", err)
	}
	return s, nil
}

// AuthUserPass authenticates against Vault with Userpass.
type AuthUserPass struct {
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	MountPath string `yaml:"mount_path"`
}

// UnmarshalYAML for AuthUserPass validates required fields after unmarshaling
func (a *AuthUserPass) UnmarshalYAML(value *yaml.Node) error {
	type tempAuthUserPass AuthUserPass
	temp := tempAuthUserPass{}
	if err := value.Decode(&temp); err != nil {
		return err
	}
	*a = AuthUserPass(temp)
	if a.Username == "" {
		return fmt.Errorf("missing required field 'username'")
	}
	if a.Password == "" {
		return fmt.Errorf("missing required field 'password'")
	}
	return nil
}

func (a *AuthUserPass) vaultAuthenticate(ctx context.Context, cli *vault.Client) (*vault.Secret, error) {
	secret := &userpass.Password{FromString: string(a.Password)}

	var opts []userpass.LoginOption

	if a.MountPath != "" {
		opts = append(opts, userpass.WithMountPath(a.MountPath))
	}

	auth, err := userpass.NewUserpassAuth(a.Username, secret, opts...)
	if err != nil {
		return nil, fmt.Errorf("auth.userpass: %w", err)
	}
	s, err := cli.Auth().Login(ctx, auth)
	if err != nil {
		return nil, fmt.Errorf("auth.userpass: %w", err)
	}
	return s, nil
}

// AuthKubernetes authenticates against Vault with Kubernetes.
type AuthKubernetes struct {
	Role                    string `yaml:"role"`
	ServiceAccountTokenFile string `yaml:"service_account_file"`
	MountPath               string `yaml:"mount_path"`
}

// UnmarshalYAML for AuthKubernetes validates required fields after unmarshaling
func (a *AuthKubernetes) UnmarshalYAML(value *yaml.Node) error {
	type tempAuthKubernetes AuthKubernetes
	temp := tempAuthKubernetes{}
	if err := value.Decode(&temp); err != nil {
		return err
	}
	*a = AuthKubernetes(temp)
	if a.Role == "" {
		return fmt.Errorf("missing required field 'role'")
	}
	return nil
}

func (a *AuthKubernetes) vaultAuthenticate(ctx context.Context, cli *vault.Client) (*vault.Secret, error) {
	var opts []kubernetes.LoginOption

	if a.ServiceAccountTokenFile != "" {
		opts = append(opts, kubernetes.WithServiceAccountTokenPath(a.ServiceAccountTokenFile))
	}
	if a.MountPath != "" {
		opts = append(opts, kubernetes.WithMountPath(a.MountPath))
	}

	auth, err := kubernetes.NewKubernetesAuth(a.Role, opts...)
	if err != nil {
		return nil, fmt.Errorf("auth.kubernetes: %w", err)
	}
	s, err := cli.Auth().Login(ctx, auth)
	if err != nil {
		return nil, fmt.Errorf("auth.kubernetes: %w", err)
	}
	return s, nil
}

// AuthLDAP authenticates against Vault with LDAP.
type AuthLDAP struct {
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	MountPath string `yaml:"mount_path"`
}

// UnmarshalYAML for AuthLDAP validates required fields after unmarshaling
func (a *AuthLDAP) UnmarshalYAML(value *yaml.Node) error {
	type tempAuthLDAP AuthLDAP
	temp := tempAuthLDAP{}
	if err := value.Decode(&temp); err != nil {
		return err
	}
	*a = AuthLDAP(temp)
	if a.Username == "" {
		return fmt.Errorf("missing required field 'username'")
	}
	if a.Password == "" {
		return fmt.Errorf("missing required field 'password'")
	}
	return nil
}

func (a *AuthLDAP) vaultAuthenticate(ctx context.Context, cli *vault.Client) (*vault.Secret, error) {
	secret := &ldap.Password{FromString: string(a.Password)}

	var opts []ldap.LoginOption

	if a.MountPath != "" {
		opts = append(opts, ldap.WithMountPath(a.MountPath))
	}

	auth, err := ldap.NewLDAPAuth(a.Username, secret, opts...)
	if err != nil {
		return nil, fmt.Errorf("auth.ldap: %w", err)
	}
	s, err := cli.Auth().Login(ctx, auth)
	if err != nil {
		return nil, fmt.Errorf("auth.ldap: %w", err)
	}
	return s, nil
}
