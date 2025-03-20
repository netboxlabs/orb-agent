package secretsmgr

import (
	"context"
	"fmt"

	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/hashicorp/vault/api/auth/aws"
	"github.com/hashicorp/vault/api/auth/azure"
	"github.com/hashicorp/vault/api/auth/gcp"
	"github.com/hashicorp/vault/api/auth/kubernetes"
	"github.com/hashicorp/vault/api/auth/ldap"
	"github.com/hashicorp/vault/api/auth/userpass"
)

type authMethod interface {
	vaultAuthenticate(context.Context, *vault.Client) error
}

func NewAuthentication(auth string, auth_args map[string]any) (authMethod, error) {
	switch auth {
	case "token":
		return &AuthToken{}, nil
	case "aws":
		return &aws.Auth{}, nil
	case "azure":
		return &azure.Auth{}, nil
	case "gcp":
		return &gcp.Auth{}, nil
	case "kubernetes":
		return &kubernetes.Auth{}, nil
	case "ldap":
		return &ldap.Auth{}, nil
	case "userpass":
		return &userpass.Auth{}, nil
	case "approle":
		return &approle.Auth{}, nil
	default:
		return nil, fmt.Errorf("unsupported auth method: %s", auth)
	}
}

// AuthToken authenticates against Vault with a token.
type AuthToken struct {
	Token string `yaml:"token"`
}

func (a *AuthToken) vaultAuthenticate(ctx context.Context, cli *vault.Client) error {
	cli.SetToken(a.Token)
	_, err := cli.Auth().Token().LookupSelf()
	if err != nil {
		return err
	}
	return nil
}
