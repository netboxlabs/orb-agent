package configmgr

import (
	"context"
	"errors"
	"io"

	gitv5 "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
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

// applyPolicy reads and applies a specific policy file
func (gc *gitConfigManager) applyPolicy(file *object.File, backends map[string]backend.Backend) error {
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

	var policies map[string]map[string]any
	err = yaml.Unmarshal(data, &policies)
	if err != nil {
		return err
	}

	for beName, policy := range policies {
		if _, ok := backends[beName]; !ok {
			return errors.New("backend not found: " + beName)
		}
		gc.logger.Info("Applying policy", zap.String("file", file.Name))
		for pName, data := range policy {
			id := uuid.NewString()
			payload := config.PolicyPayload{
				Action:    "manage",
				Name:      pName,
				DatasetID: id,
				Backend:   beName,
				Version:   1,
				Data:      data,
			}
			gc.pMgr.ManagePolicy(payload)
		}
	}

	return nil
}

// processSelector reads and matches the root selector.yaml against the agent's metadata
func (gc *gitConfigManager) processSelector(file *object.File, cfg config.Config) ([]string, error) {
	reader, err := file.Reader()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := reader.Close(); err != nil {
			gc.logger.Error("failed to close file", zap.Error(err))
		}
	}()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	var selectors map[string]struct {
		Selector map[string]string `yaml:"selector"`
		Policies map[string]struct {
			Enabled *bool  `yaml:"enabled"`
			Path    string `yaml:"path"`
		} `yaml:"policies"`
	}
	err = yaml.Unmarshal(data, &selectors)
	if err != nil {
		return nil, err
	}

	// Check for matching selector
	for selectorName, entry := range selectors {
		matches := true
		for key, value := range entry.Selector {
			if cfgValue, exists := cfg.OrbAgent.Labels[key]; !exists || cfgValue != value {
				matches = false
				break
			}
		}

		if matches {
			gc.logger.Info("Selector matched", zap.String("selector", selectorName))
			policyPaths := make([]string, 0)
			for _, policy := range entry.Policies {
				if policy.Enabled != nil && !*policy.Enabled {
					continue
				}
				policyPaths = append(policyPaths, policy.Path)
			}
			return policyPaths, nil
		}
	}

	return nil, nil // No match found
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

	// Open an in-memory repository
	repo, err := gitv5.Init(memory.NewStorage(), nil)
	if err != nil {
		return err
	}

	// Add the remote
	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{gc.config.URL},
	})
	if err != nil {
		return err
	}

	// Fetch all branches and references
	err = repo.Fetch(&gitv5.FetchOptions{
		RemoteName: "origin",
		Auth:       authMethod,
	})
	if err != nil && err != gitv5.NoErrAlreadyUpToDate {
		return err
	}

	// Get the remote reference list
	remote, err := repo.Remote("origin")
	if err != nil {
		return err
	}

	refs, err := remote.List(&gitv5.ListOptions{Auth: authMethod})
	if err != nil {
		return err
	}

	// Find the default branch
	branchName := gc.config.Branch
	if branchName == "" {
		for _, ref := range refs {
			if ref.Name().IsBranch() {
				branchName = ref.Name().Short()
				gc.logger.Info("detected default branch", zap.String("branch", branchName))
				break
			}
		}

		if branchName == "" {
			return errors.New("failed to detect default branch, repository might be empty")
		}
	}

	gc.logger.Info("cloning repository", zap.String("url", gc.config.URL), zap.String("branch", branchName))

	// Now clone the repository with the determined branch
	r, err := gitv5.Clone(memory.NewStorage(), nil, &gitv5.CloneOptions{
		Auth:          authMethod,
		URL:           gc.config.URL,
		ReferenceName: plumbing.NewBranchReferenceName(branchName),
		SingleBranch:  true,
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

	// Locate the selector.yaml file in the root directory
	var selectorFile *object.File
	err = tree.Files().ForEach(func(f *object.File) error {
		if f.Name == "selector.yaml" {
			selectorFile = f
			return nil
		}
		return nil
	})
	if err != nil {
		return err
	}

	if selectorFile == nil {
		return errors.New("selector.yaml not found in repository root")
	}

	// Process the selector file
	matchingPolicies, err := gc.processSelector(selectorFile, cfg)
	if err != nil {
		return err
	}
	if matchingPolicies == nil {
		gc.logger.Info("No matching selector found. No will be policies applied.")
		return nil
	}

	// Apply the matched policies
	for _, policyPath := range matchingPolicies {
		// Try to get the exact file from the tree
		f, err := tree.File(policyPath)
		if err != nil {
			return errors.New("policy file not found: " + policyPath)
		}

		// Apply the policy if the file exists
		err = gc.applyPolicy(f, backends)
		if err != nil {
			return err
		}
	}

	return nil
}

func (gc *gitConfigManager) GetContext(ctx context.Context) context.Context {
	return ctx
}
