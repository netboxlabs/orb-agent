package configmgr

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gitv5 "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/agent/backend"
	"github.com/netboxlabs/orb-agent/agent/config"
)

const (
	urlUser     = "orbuser"
	urlPassword = "canary-password-1234"
	urlToken    = "canary-token-5678"

	// refusedURL is a port nothing listens on, so a connection to it is refused.
	refusedURL = "http://127.0.0.1:1"
)

// gitHTTPServer serves the bare repositories under its root over git's smart
// HTTP protocol, through git http-backend. status, when set, is the answer to
// every request instead; refuse answers every request with a 401 that asks for
// basic auth, as a host does that turns down the credentials it is sent.
type gitHTTPServer struct {
	*httptest.Server
	status atomic.Int32
	refuse atomic.Bool
}

// skipOrFail skips the test, or fails it on CI, where what it needs is
// installed and a skip would hide that it did not run.
func skipOrFail(t *testing.T, why string) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatal(why)
	}
	t.Skip(why)
}

// isolateGit keeps system git away from the user's and the system's git
// config, and so from their credential helpers, and from asking for a
// password: at a terminal, or through an askpass program.
func isolateGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		skipOrFail(t, "system git not found")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
	t.Setenv("GIT_ASKPASS", "")
	t.Setenv("SSH_ASKPASS", "")
}

func newGitHTTPServer(t *testing.T, root string) *gitHTTPServer {
	t.Helper()
	isolateGit(t)
	out, err := exec.Command("git", "--exec-path").Output()
	require.NoError(t, err)
	backendPath := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(backendPath); err != nil {
		skipOrFail(t, "git http-backend not found")
	}
	backend := &cgi.Handler{
		Path: backendPath,
		Env:  []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"},
	}
	s := &gitHTTPServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status := s.status.Load(); status != 0 {
			w.WriteHeader(int(status))
			return
		}
		if s.refuse.Load() {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		backend.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// withUserInfo returns the URL of path on s, with userInfo before its host.
func (s *gitHTTPServer) withUserInfo(userInfo, path string) string {
	return strings.Replace(s.URL, "://", "://"+userInfo+"@", 1) + path
}

// writeBareRepo writes, at root/name, a bare repository with one commit whose
// selector.yaml selects policy.yaml for the label env: test.
func writeBareRepo(t *testing.T, root, name string) {
	t.Helper()
	isolateGit(t)
	src := t.TempDir()
	repo, err := gitv5.PlainInit(src, false)
	require.NoError(t, err)
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	files := map[string]string{
		"selector.yaml": "s:\n  selector:\n    env: test\n  policies:\n    p:\n      path: policy.yaml\n",
		"policy.yaml":   "backend1:\n  p:\n    key: value\n",
	}
	for path, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(src, path), []byte(content), 0o644))
		_, err = worktree.Add(path)
		require.NoError(t, err)
	}
	_, err = worktree.Commit("initial commit", &gitv5.CommitOptions{
		Author: &object.Signature{Name: "tester", Email: "tester@example.com", When: time.Now()},
	})
	require.NoError(t, err)
	out, err := exec.Command("git", "clone", "--quiet", "--bare", src, filepath.Join(root, name)).CombinedOutput()
	require.NoError(t, err, "bare clone failed: %s", out)
}

// startGit starts a Git config manager for repoURL that logs through a
// recordingHandler, and returns it with the handler and Start's error.
func startGit(t *testing.T, repoURL string) (*gitConfigManager, *recordingHandler, error) {
	t.Helper()
	h := &recordingHandler{}
	pMgr := new(mockPolicyManagerForFleet)
	pMgr.On("ManagePolicy", mock.Anything).Return()
	gc := &gitConfigManager{logger: slog.New(h), pMgr: pMgr}
	cfg := gitConfig(repoURL)
	err := gc.Start(t.Context(), cfg, map[string]backend.Backend{"backend1": nil})
	t.Cleanup(func() { _ = gc.Stop(t.Context()) })
	return gc, h, err
}

func gitConfig(repoURL string) config.Config {
	return config.Config{OrbAgent: config.OrbAgent{
		Labels: map[string]string{"env": "test"},
		ConfigManager: config.ManagerConfig{
			Active:  "git",
			Sources: config.Sources{Git: config.GitManager{URL: repoURL}},
		},
	}}
}

// logged returns every record h kept, one per line, with its attributes.
func (h *recordingHandler) logged() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var b strings.Builder
	for _, r := range h.records {
		fmt.Fprintf(&b, "%s %s %v\n", r.level, r.msg, r.attrs)
	}
	return b.String()
}

func requireLogged(t *testing.T, h *recordingHandler, level slog.Level, msg string) {
	t.Helper()
	require.NotEmpty(t, h.matching(level, msg), "no %s record %q in:\n%s", level, msg, h.logged())
}

func assertNoCredential(t *testing.T, text string, credentials ...string) {
	t.Helper()
	for _, c := range credentials {
		assert.NotContains(t, text, c)
	}
}

func TestGitStartLogsTheRepositoryURLWithoutItsCredential(t *testing.T) {
	root := t.TempDir()
	writeBareRepo(t, root, "repo.git")
	srv := newGitHTTPServer(t, root)

	for name, tc := range userInfos {
		t.Run(name, func(t *testing.T) {
			_, h, err := startGit(t, srv.withUserInfo(tc.userInfo, "/repo.git"))
			require.NoError(t, err)
			requireLogged(t, h, slog.LevelInfo, "cloning repository")
			assertNoCredential(t, h.logged(), tc.credential)
		})
	}
}

// userInfos are the ways a credential is written in a repository URL.
var userInfos = map[string]struct{ userInfo, credential string }{
	"a password":        {urlUser + ":" + urlPassword, urlPassword},
	"a token as a user": {urlToken, urlToken},
	// As GitHub documents an OAuth token in a URL, and Azure DevOps a PAT.
	"a token as a user, with a password": {urlToken + ":x-oauth-basic", urlToken},
}

func TestGitStartLogsAnAzureDevOpsURLWithoutItsCredential(t *testing.T) {
	isolateGit(t)
	for name, tc := range userInfos {
		t.Run(name, func(t *testing.T) {
			repoURL := strings.Replace(refusedURL, "://", "://"+tc.userInfo+"@", 1) + "/dev.azure.com/org/_git/repo"

			_, h, err := startGit(t, repoURL)
			require.Error(t, err)
			requireLogged(t, h, slog.LevelInfo, "Azure DevOps URL detected")
			assertNoCredential(t, h.logged(), tc.credential)
			assertNoCredential(t, err.Error(), tc.credential)
		})
	}
}

// TestGitStartRefusesAURLWhoseUserInfoIsNotReadAsOne pins that a URL whose
// credential no parser reads as user info, but as a host or a port, is
// refused before go-git or git look that host up, and that the error quotes
// none of it.
func TestGitStartRefusesAURLWhoseUserInfoIsNotReadAsOne(t *testing.T) {
	for name, tc := range map[string]struct{ repoURL, credential string }{
		"a / in a password":  {"http://" + urlUser + ":canaryABC/DEF+ghi=@127.0.0.1:1/repo.git", "canaryABC"},
		"a ? in a password":  {"http://" + urlUser + ":canaryABC?DEF@127.0.0.1:1/repo.git", "canaryABC"},
		"a ? in a token":     {"http://canaryTOKEN?rest@127.0.0.1:1/repo.git", "canaryTOKEN"},
		"a # in a token":     {"http://canaryTOKEN#rest@127.0.0.1:1/repo.git", "canaryTOKEN"},
		"a bad % in a token": {"http://canaryTOKEN%zzrest@127.0.0.1:1/repo.git", "canaryTOKEN"},
		// go-git reads these as scp-like, with the token as the host.
		"no scheme":                  {"canaryTOKEN:x-oauth-basic@127.0.0.1/org/repo.git", "canaryTOKEN"},
		"no scheme, with a password": {"https:canaryTOKEN:rest@127.0.0.1/org/repo.git", "canaryTOKEN"},
		"no scheme, written from //": {"//canaryTOKEN:rest@127.0.0.1:1/repo.git", "canaryTOKEN"},
	} {
		t.Run(name, func(t *testing.T) {
			_, h, err := startGit(t, tc.repoURL)
			require.ErrorContains(t, err, "percent-encode")
			assertNoCredential(t, err.Error(), tc.credential, "rest")
			assertNoCredential(t, h.logged(), tc.credential)
		})
	}
}

// TestGitStartTakesAURLWithAnAtInItsPath pins that a URL is not refused for
// an @ in its path, which is not user info.
func TestGitStartTakesAURLWithAnAtInItsPath(t *testing.T) {
	root := t.TempDir()
	writeBareRepo(t, root, "a@b.git")
	srv := newGitHTTPServer(t, root)

	_, _, err := startGit(t, srv.URL+"/a@b.git")
	require.NoError(t, err)
}

// TestGitStartTakesAnAzureDevOpsURLGoCannotParse pins that user info Go's
// parser rejects but git takes, such as a ^ in a password, still reaches an
// Azure DevOps repository through system git, with the URL masked in the log.
func TestGitStartTakesAnAzureDevOpsURLGoCannotParse(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "dev.azure.com"), 0o755))
	writeBareRepo(t, root, "dev.azure.com/repo.git")
	srv := newGitHTTPServer(t, root)

	_, h, err := startGit(t, srv.withUserInfo(urlUser+":canary^pass", "/dev.azure.com/repo.git"))
	require.NoError(t, err)
	requireLogged(t, h, slog.LevelInfo, "Azure DevOps URL detected")
	assertNoCredential(t, h.logged(), "canary^pass")
}

// TestGitStartNamesWhatElseIsWrongWithAURL pins that a URL Go cannot parse
// for a fault outside its user info is not refused as if the user info were
// at fault: its error names the cause, with the user info masked.
func TestGitStartNamesWhatElseIsWrongWithAURL(t *testing.T) {
	for name, tc := range map[string]struct{ repoURL, cause string }{
		"a port that is not a number":   {"ssh://" + urlToken + "@github.com:org/repo.git", `invalid port ":org"`},
		"a bad % outside its user info": {"http://" + urlToken + "@127.0.0.1:1/a%zz.git", "invalid URL escape"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := startGit(t, tc.repoURL)
			require.ErrorContains(t, err, tc.cause)
			assert.NotContains(t, err.Error(), "percent-encode")
			assertNoCredential(t, err.Error(), urlToken)
		})
	}
}

func TestGitStartErrorCarriesNoCredentialOfTheRepositoryURL(t *testing.T) {
	root := t.TempDir()
	writeBareRepo(t, root, "repo.git")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "dev.azure.com"), 0o755))
	writeBareRepo(t, root, "dev.azure.com/repo.git")

	t.Run("an HTTP error from the host", func(t *testing.T) {
		srv := newGitHTTPServer(t, root)
		srv.status.Store(http.StatusInternalServerError)
		for name, tc := range userInfos {
			t.Run(name, func(t *testing.T) {
				_, _, err := startGit(t, srv.withUserInfo(tc.userInfo, "/repo.git"))
				require.ErrorContains(t, err, "500")
				assertNoCredential(t, err.Error(), urlUser, urlPassword, urlToken)
			})
		}
	})

	t.Run("a host that does not answer", func(t *testing.T) {
		for name, tc := range userInfos {
			t.Run(name, func(t *testing.T) {
				repoURL := strings.Replace(refusedURL, "://", "://"+tc.userInfo+"@", 1) + "/repo.git"
				_, _, err := startGit(t, repoURL)
				require.ErrorContains(t, err, "connection refused")
				assertNoCredential(t, err.Error(), urlUser, urlPassword, urlToken)
			})
		}
	})

	t.Run("a URL Go cannot parse", func(t *testing.T) {
		// An unescaped space is not allowed in a URL's user info.
		_, _, err := startGit(t, "http://"+urlUser+":canary pass@127.0.0.1:1/repo.git")
		require.ErrorContains(t, err, "invalid userinfo")
		assertNoCredential(t, err.Error(), "canary pass")
	})

	t.Run("an Azure DevOps URL git refuses for its plaintext credentials", func(t *testing.T) {
		srv := newGitHTTPServer(t, root)
		t.Setenv("GIT_CONFIG_COUNT", "1")
		t.Setenv("GIT_CONFIG_KEY_0", "transfer.credentialsInUrl")
		t.Setenv("GIT_CONFIG_VALUE_0", "die")
		_, _, err := startGit(t, srv.withUserInfo(urlToken+":"+urlPassword, "/dev.azure.com/repo.git"))
		require.ErrorContains(t, err, "plaintext credentials")
		assertNoCredential(t, err.Error(), urlToken, urlPassword)
	})

	t.Run("an Azure DevOps host that refuses the credential", func(t *testing.T) {
		srv := newGitHTTPServer(t, root)
		srv.refuse.Store(true)
		_, _, err := startGit(t, srv.withUserInfo(urlToken, "/dev.azure.com/repo.git"))
		require.ErrorContains(t, err, "system git clone failed")
		assertNoCredential(t, err.Error(), urlToken)
	})
}

func TestGitScheduledFetchLogsNoCredentialOfTheRepositoryURL(t *testing.T) {
	root := t.TempDir()
	writeBareRepo(t, root, "repo.git")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "dev.azure.com"), 0o755))
	writeBareRepo(t, root, "dev.azure.com/repo.git")

	for name, tc := range map[string]struct {
		path  string
		fails func(*gitHTTPServer)
	}{
		"through go-git": {"/repo.git", func(s *gitHTTPServer) {
			s.status.Store(http.StatusInternalServerError)
		}},
		"through system git": {"/dev.azure.com/repo.git", func(s *gitHTTPServer) {
			s.refuse.Store(true)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newGitHTTPServer(t, root)
			repoURL := srv.withUserInfo(urlToken, tc.path)
			gc, h, err := startGit(t, repoURL)
			require.NoError(t, err)

			tc.fails(srv)
			gc.schedule(gitConfig(repoURL), map[string]backend.Backend{"backend1": nil})

			requireLogged(t, h, slog.LevelError, "Failed to fetch latest changes")
			assertNoCredential(t, h.logged(), urlToken)
		})
	}
}
