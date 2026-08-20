package configmgr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"

	"github.com/go-co-op/gocron/v2"
	gitv5 "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/policymgr"
)

var _ Manager = (*gitConfigManager)(nil)

type gitConfigManager struct {
	logger           *slog.Logger
	pMgr             policymgr.PolicyManager
	config           config.GitManager
	scheduler        gocron.Scheduler
	repo             *gitv5.Repository
	lastRef          plumbing.Hash
	authMethod       transport.AuthMethod
	version          int32
	matchPolicyPaths []string
	namespace        uuid.UUID
	tempDir          string         // non-empty when using system git fallback (Azure DevOps)
	githubApp        *githubAppAuth // non-nil when auth is github_app; also stored in authMethod
}

// GitAuthMode is the authentication method the Git ConfigManager uses against
// the policy repository, taken verbatim from config_manager.sources.git.auth.
type GitAuthMode string

// Supported values of GitAuthMode. Anything else is a typo and is rejected at
// startup rather than silently falling back to unauthenticated access.
const (
	// GitAuthNone is the zero value: no auth, for public repositories.
	GitAuthNone GitAuthMode = ""
	// GitAuthBasic is HTTPS with a username and a password or token.
	GitAuthBasic GitAuthMode = "basic"
	// GitAuthSSH is an SSH private key, or the SSH agent when no key is set.
	GitAuthSSH GitAuthMode = "ssh"
	// GitAuthGitHubApp mints short-lived GitHub App installation tokens.
	GitAuthGitHubApp GitAuthMode = "github_app"
)

// annotateAuthError attaches the last GitHub App token failure to a go-git
// error. When SetAuth cannot mint, go-git only ever reports
// transport.ErrAuthenticationRequired, which does not say why.
func (gc *gitConfigManager) annotateAuthError(err error) error {
	if err == nil || gc.githubApp == nil {
		return err
	}
	if mintErr := gc.githubApp.lastError(); mintErr != nil {
		return fmt.Errorf("%w (github_app token refresh also failed: %v)", err, mintErr)
	}
	return err
}

type (
	policyPath string
	policyData map[string]map[string]any
	policyKey  struct {
		Backend string
		Name    string
	}
)

func (gc *gitConfigManager) readPolicies(tree *object.Tree, matchingPolicies []string) (map[policyPath]policyData, error) {
	policiesByPath := make(map[policyPath]policyData)
	allPolicies := make(map[string]map[string]any)
	for _, path := range matchingPolicies {
		// Try to get the exact file from the tree
		file, err := tree.File(path)
		if err != nil {
			return nil, errors.New("policy file not found: " + path)
		}

		reader, err := file.Reader()
		if err != nil {
			return nil, err
		}
		defer func() {
			if err := reader.Close(); err != nil {
				gc.logger.Error("failed to close file", "error", err)
			}
		}()

		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}

		var policies map[string]map[string]any
		if err = yaml.Unmarshal(data, &policies); err != nil {
			return nil, err
		}

		for beName, policy := range policies {
			if _, ok := allPolicies[beName]; !ok {
				allPolicies[beName] = make(map[string]any)
			}
			for pName, data := range policy {
				if _, ok := allPolicies[beName][pName]; ok {
					return nil, errors.New("policy already exists for backend: " + pName)
				}
				allPolicies[beName][pName] = data
			}
		}
		policiesByPath[policyPath(path)] = policies
	}
	return policiesByPath, nil
}

func (gc *gitConfigManager) removePolicies(policiesByPath map[policyPath]policyData) {
	// Build a lookup map from policiesByPath
	definedPolicies := make(map[policyKey]struct{})
	for _, policies := range policiesByPath {
		for beName, newPolicy := range policies {
			for pName := range newPolicy {
				key := policyKey{Backend: beName, Name: pName}
				definedPolicies[key] = struct{}{}
			}
		}
	}

	appliedPolicies, err := gc.pMgr.GetRepo().GetAll()
	if err != nil {
		gc.logger.Error("failed to get applied policies", "error", err)
		return
	}

	// Remove policies that are not in the matching policies
	for _, policy := range appliedPolicies {
		key := policyKey{Backend: policy.Backend, Name: policy.Name}
		if _, exists := definedPolicies[key]; !exists {
			if err := gc.pMgr.RemovePolicy(policy.ID, policy.Name, policy.Backend); err != nil {
				gc.logger.Error("failed to remove policy", "error", err)
			}
		}
	}
}

func (gc *gitConfigManager) applyPolicies(policies policyData, backends map[string]backend.Backend) error {
	for beName, policy := range policies {
		if _, ok := backends[beName]; !ok {
			return errors.New("backend not found: " + beName)
		}
		for pName, data := range policy {
			policyID := uuid.NewSHA1(gc.namespace, []byte(pName+beName)).String()
			payload := config.PolicyPayload{
				ID:        policyID,
				Action:    "manage",
				Name:      pName,
				DatasetID: uuid.NewString(),
				Backend:   beName,
				Version:   gc.version,
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
			gc.logger.Error("failed to close file", "error", err)
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
	if err = yaml.Unmarshal(data, &selectors); err != nil {
		return nil, err
	}

	// Use a set (map) to store unique policy paths
	policyPathsSet := make(map[string]struct{})

	// Iterate through all selectors and collect all matching ones
	for selectorName, entry := range selectors {
		matches := true
		for key, value := range entry.Selector {
			if cfgValue, exists := cfg.OrbAgent.Labels[key]; !exists || cfgValue != value {
				matches = false
				break
			}
		}
		if matches {
			gc.logger.Info("Selector matched", "selector", selectorName)
			for pName, policy := range entry.Policies {
				if policy.Enabled != nil && !*policy.Enabled {
					continue
				}
				if _, exists := policyPathsSet[policy.Path]; exists {
					gc.logger.Warn("Policy path already exists", "selector", selectorName,
						"policy", pName, "path", policy.Path)
				}
				policyPathsSet[policy.Path] = struct{}{}
			}
		}
	}

	// Convert map keys to a slice
	var policyPaths []string
	for path := range policyPathsSet {
		policyPaths = append(policyPaths, path)
	}

	return policyPaths, nil
}

func (gc *gitConfigManager) schedule(cfg config.Config, backends map[string]backend.Backend) {
	gc.logger.Debug("Running scheduled Git Config Manager task")

	// Fetch latest updates from remote
	if gc.tempDir != "" {
		// Azure DevOps fallback: use system git
		if err := gc.fetchWithSystemGit(); err != nil {
			gc.logger.Error("Failed to fetch latest changes", "error", err)
			return
		}
	} else {
		err := gc.repo.Fetch(&gitv5.FetchOptions{
			RemoteName:      "origin",
			Auth:            gc.authMethod,
			InsecureSkipTLS: gc.config.SkipTLS,
			RefSpecs:        []gitconfig.RefSpec{"refs/heads/*:refs/heads/*"},
		})
		if err != nil && err != gitv5.NoErrAlreadyUpToDate {
			gc.logger.Error("Failed to fetch latest changes", "error", gc.annotateAuthError(err))
			return
		}
	}

	// Get the latest reference (HEAD)
	ref, err := gc.repo.Reference(plumbing.ReferenceName("refs/heads/"+gc.config.Branch), true)
	if err != nil {
		gc.logger.Error("Failed to get latest branch reference", "error", err)
		return
	}

	// Check if HEAD has changed
	if gc.lastRef == ref.Hash() {
		gc.logger.Debug("No changes detected in remote repository")
		return
	}

	// Get the latest commit
	commit, err := gc.repo.CommitObject(ref.Hash())
	if err != nil {
		gc.logger.Error("Failed to get commit object", "error", err)
		return
	}

	tree, err := commit.Tree()
	if err != nil {
		gc.logger.Error("Failed to get commit tree", "error", err)
		return
	}

	selectorFile, err := tree.File("selector.yaml")
	if err != nil {
		gc.logger.Warn("selector.yaml not found in latest commit")
		gc.removePolicies(make(map[policyPath]policyData))
		gc.matchPolicyPaths = make([]string, 0)
		gc.lastRef = ref.Hash()
		return
	}

	// Get the last commit's tree
	oldCommit, err := gc.repo.CommitObject(gc.lastRef)
	if err != nil {
		gc.logger.Error("Failed to get old commit object", "error", err)
		return
	}

	oldTree, err := oldCommit.Tree()
	if err != nil {
		gc.logger.Error("Failed to get old commit tree", "error", err)
		return
	}

	// Check for file changes
	changes, err := oldTree.Diff(tree)
	if err != nil {
		gc.logger.Error("Failed to get diff", "error", err)
		return
	}

	// Update last seen commit hash
	gc.lastRef = ref.Hash()

	matchingPolicies, err := gc.processSelector(selectorFile, cfg)
	if err != nil {
		gc.logger.Error("Failed to process selector", "error", err)
		return
	}

	// Check if selector.yaml or policies has changed
	changed := false
	for _, change := range changes {
		if change.To.Name == "selector.yaml" || slices.Contains(matchingPolicies, change.To.Name) {
			changed = true
			break
		}
	}
	if !changed {
		gc.logger.Info("No changes in selector.yaml or policies")
		return
	}

	policiesByPath, err := gc.readPolicies(tree, matchingPolicies)
	if err != nil {
		gc.logger.Error("Failed to read policies", "error", err)
		return
	}

	// Remove policies that are not in the matching policies
	gc.removePolicies(policiesByPath)

	// Apply new policies
	for _, policy := range matchingPolicies {
		if slices.Contains(gc.matchPolicyPaths, policy) {
			continue
		}
		policies := policiesByPath[policyPath(policy)]
		if err = gc.applyPolicies(policies, backends); err != nil {
			gc.logger.Error("failed to apply policies", "error", err)
		}
	}

	gc.matchPolicyPaths = matchingPolicies

	// Apply only changed policies
	gc.version++
	for _, change := range changes {
		for path, policies := range policiesByPath {
			if change.To.Name == string(path) {
				if err = gc.applyPolicies(policies, backends); err != nil {
					gc.logger.Error("Failed to apply policies", "error", err)
				}
			}
		}
	}
}

func (gc *gitConfigManager) Start(ctx context.Context, cfg config.Config, backends map[string]backend.Backend) error {
	var err error
	var startOK bool
	gc.version = 1
	gc.config = cfg.OrbAgent.ConfigManager.Sources.Git

	if gc.config.URL == "" {
		return errors.New("URL is required for Git Config Manager")
	}
	gc.config.URL, err = config.ResolveEnv(gc.config.URL)
	if err != nil {
		return err
	}

	switch GitAuthMode(gc.config.Auth) {
	case GitAuthNone:
	case GitAuthBasic:
		if gc.config.Password, err = config.ResolveEnv(gc.config.Password); err != nil {
			return err
		}
		gc.authMethod = &http.BasicAuth{
			Username: gc.config.Username,
			Password: gc.config.Password,
		}
	case GitAuthSSH:
		if gc.config.PrivateKey != "" {
			if gc.config.Password, err = config.ResolveEnv(gc.config.Password); err != nil {
				return err
			}
			gc.authMethod, err = ssh.NewPublicKeysFromFile("git", gc.config.PrivateKey, gc.config.Password)
		} else {
			gc.authMethod, err = ssh.NewSSHAgentAuth("git")
		}
	case GitAuthGitHubApp:
		if err = requireGitHubHTTPSURL(gc.config.URL); err != nil {
			return err
		}
		if gc.githubApp, err = newGitHubAppAuth(gc.logger, gc.config.GitHubApp, gc.config.SkipTLS); err != nil {
			return err
		}
		// Mint once now so a bad key, app id or installation id fails startup with
		// a specific error, the same way basic and ssh fail fast. SetAuth returns
		// no error, so this is the only place those problems can be surfaced.
		if _, err = gc.githubApp.token(ctx); err != nil {
			return err
		}
		gc.authMethod = gc.githubApp
	default:
		return fmt.Errorf(
			"unsupported git auth mode %q; expected basic, ssh, github_app, or empty",
			gc.config.Auth,
		)
	}

	if err != nil {
		return err
	}

	var branchName string

	if IsAzureDevOpsURL(gc.config.URL) {
		gc.logger.Info("Azure DevOps URL detected, using system git fallback", "url", gc.config.URL)
		branchName = gc.config.Branch // may be empty; cloneWithSystemGit handles that

		var dir string
		dir, gc.repo, err = gc.cloneWithSystemGit(branchName)
		if err != nil {
			return err
		}
		gc.tempDir = dir
		defer func() {
			if !startOK {
				_ = os.RemoveAll(gc.tempDir)
				gc.tempDir = ""
			}
		}()

		// If no branch was specified, read the actual branch from HEAD
		if branchName == "" {
			head, err := gc.repo.Head()
			if err != nil {
				return fmt.Errorf("failed to read HEAD after system git clone: %w", err)
			}
			branchName = head.Name().Short()
			gc.logger.Info("detected default branch", "branch", branchName)
		}
	} else {
		// Open an in-memory repository
		repo, err := gitv5.Init(memory.NewStorage(), nil)
		if err != nil {
			return err
		}

		// Add the remote
		if _, err = repo.CreateRemote(&gitconfig.RemoteConfig{
			Name: "origin",
			URLs: []string{gc.config.URL},
		}); err != nil {
			return err
		}

		// Fetch all branches and references
		if err = repo.Fetch(&gitv5.FetchOptions{
			RemoteName:      "origin",
			Auth:            gc.authMethod,
			InsecureSkipTLS: gc.config.SkipTLS,
		}); err != nil && err != gitv5.NoErrAlreadyUpToDate {
			return gc.annotateAuthError(err)
		}

		// Get the remote reference list
		remote, err := repo.Remote("origin")
		if err != nil {
			return err
		}

		refs, err := remote.List(&gitv5.ListOptions{Auth: gc.authMethod, InsecureSkipTLS: gc.config.SkipTLS})
		if err != nil {
			return gc.annotateAuthError(err)
		}

		// Find the default branch
		branchName = gc.config.Branch
		if branchName == "" {
			for _, ref := range refs {
				if ref.Name().IsBranch() {
					branchName = ref.Name().Short()
					gc.logger.Info("detected default branch", "branch", branchName)
					break
				}
			}

			if branchName == "" {
				return errors.New("failed to detect default branch, repository might be empty")
			}
		}

		gc.logger.Info("cloning repository", "url", gc.config.URL, "branch", branchName)

		// Now clone the repository with the determined branch
		gc.repo, err = gitv5.Clone(memory.NewStorage(), nil, &gitv5.CloneOptions{
			Auth:            gc.authMethod,
			URL:             gc.config.URL,
			ReferenceName:   plumbing.NewBranchReferenceName(branchName),
			SingleBranch:    true,
			InsecureSkipTLS: gc.config.SkipTLS,
		})
		if err != nil {
			return gc.annotateAuthError(err)
		}
	}

	gc.config.Branch = branchName
	gc.namespace = uuid.NewSHA1(uuid.Nil, []byte(gc.config.URL))

	ref, err := gc.repo.Head()
	if err != nil {
		return err
	}

	// Get the latest commit
	gc.lastRef = ref.Hash()
	commit, err := gc.repo.CommitObject(gc.lastRef)
	if err != nil {
		return err
	}

	// Get the tree (file structure) of the commit
	tree, err := commit.Tree()
	if err != nil {
		return err
	}

	// Locate the selector.yaml file in the root directory
	selectorFile, err := tree.File("selector.yaml")
	if err != nil {
		return errors.New("selector.yaml not found in repository root")
	}

	// Process the selector file
	matchingPolicies, err := gc.processSelector(selectorFile, cfg)
	if err != nil {
		return err
	}
	if matchingPolicies == nil {
		if gc.config.Schedule == nil {
			return errors.New("no policies match the selector; skipping policy application")
		}
		gc.logger.Info("No matching policies were found; scheduler will retry policy application", "schedule", *gc.config.Schedule)
	}

	// Read all policies
	policiesByPath, err := gc.readPolicies(tree, matchingPolicies)
	if err != nil {
		return err
	}

	// Apply the matched policies
	for path, policies := range policiesByPath {
		gc.logger.Info("Applying policies from " + string(path))
		if err = gc.applyPolicies(policies, backends); err != nil {
			return err
		}
	}

	gc.matchPolicyPaths = matchingPolicies

	// start scheduler
	if gc.config.Schedule != nil {
		s, err := gocron.NewScheduler()
		if err != nil {
			return err
		}
		gc.scheduler = s
		task := gocron.NewTask(gc.schedule, cfg, backends)
		if _, err = gc.scheduler.NewJob(gocron.CronJob(*gc.config.Schedule, false), task,
			gocron.WithSingletonMode(gocron.LimitModeReschedule)); err != nil {
			return err
		}
		gc.scheduler.Start()
	}

	startOK = true
	return nil
}

// GetContext returns a context for git config manager (no-op for now).
func (gc *gitConfigManager) GetContext(ctx context.Context) context.Context {
	return ctx
}

// Stop cleans up resources held by the git config manager.
func (gc *gitConfigManager) Stop(_ context.Context) error {
	if gc.tempDir != "" {
		if err := os.RemoveAll(gc.tempDir); err != nil {
			gc.logger.Error("failed to remove git temp dir", "path", gc.tempDir, "error", err)
		}
		gc.tempDir = ""
	}
	return nil
}
