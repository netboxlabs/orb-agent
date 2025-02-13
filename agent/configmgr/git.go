package configmgr

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"

	gitv5 "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

var _ Manager = (*gitConfigManager)(nil)

type gitConfigManager struct {
	logger *zap.Logger
	pMgr   policymgr.PolicyManager
	config config.GitManager
}

func (gc *gitConfigManager) applyPolicy(file *object.File, backends map[string]backend.Backend) error {
	// Read policy file from Git storage
	reader, err := file.Reader()
	if err != nil {
		return err
	}
	defer func() {
		if err := reader.Close(); err != nil {
			gc.logger.Error("failed to close file", zap.Error(err))
		}
	}()

	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	var policies map[string]map[string]interface{}
	err = yaml.Unmarshal(data, &policies)
	if err != nil {
		return err
	}

	for beName, policy := range policies {
		_, ok := backends[beName]
		if !ok {
			return errors.New("backend not found: " + beName)
		}
		gc.logger.Info("Applying policy", zap.String("file", file.Name))
		for pName, data := range policy {
			id := uuid.NewString()
			payload := config.PolicyPayload{Action: "manage", Name: pName, DatasetID: id, Backend: beName, Version: 1, Data: data}
			gc.pMgr.ManagePolicy(payload)
		}

	}

	return nil
}

func (gc *gitConfigManager) processSelector(file *object.File, cfg config.Config) (bool, error) {
	// Read file contents from the object storage
	reader, err := file.Reader()
	if err != nil {
		return false, err
	}
	defer func() {
		if err := reader.Close(); err != nil {
			gc.logger.Error("failed to close file", zap.Error(err))
		}
	}()

	data, err := io.ReadAll(reader)
	if err != nil {
		return false, err
	}

	var metadata map[string]interface{}
	err = yaml.Unmarshal(data, &metadata)
	if err != nil {
		return false, err
	}

	// Example: Check if selector.yaml has a specific key-value pair
	if values, exists := metadata["tags"]; exists {
		mValues, ok := values.(map[string]interface{})
		if !ok {
			return false, nil
		}
		if len(mValues) != len(cfg.OrbAgent.Tags) {
			return false, nil
		}
		for key, value := range cfg.OrbAgent.Tags {
			if val, exists := mValues[key]; !exists || val != value {
				return false, nil
			}
		}
		gc.logger.Info("Selector matches", zap.String("file", file.Name))
		return true, nil
	}

	return false, nil
}

func (gc *gitConfigManager) Start(cfg config.Config, backends map[string]backend.Backend) error {
	var authMethod transport.AuthMethod
	var err error

	if gc.config.Auth == "basic" {
		authMethod = &http.BasicAuth{
			Username: gc.config.Username,
			Password: gc.config.Password,
		}
	} else if gc.config.Auth == "ssh" {
		if gc.config.PrivateKey != "" {
			authMethod, err = ssh.NewPublicKeysFromFile("git", gc.config.PrivateKey, gc.config.Password)
		} else {
			authMethod, err = ssh.NewSSHAgentAuth("git")
		}
	}

	if err != nil {
		return err
	}

	r, err := gitv5.Clone(memory.NewStorage(), nil, &gitv5.CloneOptions{
		Auth: authMethod,
		URL:  gc.config.URL,
	})
	if err != nil {
		return err
	}

	ref, err := r.Head()
	if err != nil {
		return err
	}

	// Get the latest commit
	commit, err := r.CommitObject(ref.Hash())
	if err != nil {
		return err
	}

	// Get the tree (file structure) of the commit
	tree, err := commit.Tree()
	if err != nil {
		return err
	}

	// Traverse and process the repository
	err = tree.Files().ForEach(func(f *object.File) error {
		if filepath.Base(f.Name) == "selector.yaml" {
			dir := filepath.Dir(f.Name)

			// Read and process selector.yaml
			matches, err := gc.processSelector(f, cfg)
			if err != nil {
				return err
			}

			if matches {
				// Apply policies in the same directory
				err = tree.Files().ForEach(func(f *object.File) error {
					if filepath.Dir(f.Name) == dir && strings.HasSuffix(f.Name, ".yaml") && !strings.HasSuffix(f.Name, "selector.yaml") {
						return gc.applyPolicy(f, backends)
					}
					return nil
				})
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (gc *gitConfigManager) GetContext(ctx context.Context) context.Context {
	return ctx
}
