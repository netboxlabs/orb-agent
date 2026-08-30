package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestManagerRootedAt(root string) *Manager {
	return NewManager(context.Background(), testLogger, Options{ProfilesRoot: root})
}

// cachedDirs counts the profile sets the manager is holding. Taken under the
// cache's own lock so the count is read the way the manager writes it.
func cachedDirs(m *Manager) int {
	m.collectorsMu.Lock()
	defer m.collectorsMu.Unlock()
	return len(m.collectorsByDir)
}

// ---------------------------------------------------------------------------
// validateProfilesDir: confinement to the configured root
// ---------------------------------------------------------------------------

// Without a root there is nowhere an override is known to be safe, so the
// feature is off rather than open to every directory on the host.
func TestValidateProfilesDir_RejectsAnOverrideWithNoRootConfigured(t *testing.T) {
	_, err := validateProfilesDir("", "/etc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--snmp-profiles-root")
}

func TestValidateProfilesDir_AcceptsTheRootAndWhatIsUnderIt(t *testing.T) {
	root := "/opt/profiles"
	tests := []struct {
		name string
		dir  string
		want string
	}{
		{name: "the root itself", dir: "/opt/profiles", want: "/opt/profiles"},
		{name: "a trailing separator", dir: "/opt/profiles/", want: "/opt/profiles"},
		{name: "a subdirectory", dir: "/opt/profiles/vendor-a", want: "/opt/profiles/vendor-a"},
		{name: "a nested subdirectory", dir: "/opt/profiles/vendor-a/switches", want: "/opt/profiles/vendor-a/switches"},
		{name: "a relative path is read against the root", dir: "vendor-a", want: "/opt/profiles/vendor-a"},
		{name: "a dot-slash relative path", dir: "./vendor-a", want: "/opt/profiles/vendor-a"},
		{name: "a bare dot is the root", dir: ".", want: "/opt/profiles"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateProfilesDir(root, tt.dir)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// The value arrives in a request body, so anything the root does not contain is
// refused before it is stat-ed or walked.
func TestValidateProfilesDir_RejectsWhatTheRootDoesNotContain(t *testing.T) {
	root := "/opt/profiles"
	tests := []struct {
		name string
		dir  string
	}{
		{name: "the filesystem root", dir: "/"},
		{name: "an unrelated absolute path", dir: "/etc"},
		{name: "the root's parent", dir: "/opt"},
		{name: "a sibling sharing the root's name prefix", dir: "/opt/profiles-other"},
		{name: "a leading traversal", dir: "../etc"},
		{name: "a traversal out of the root", dir: "/opt/profiles/../../etc"},
		{name: "an interior traversal", dir: "vendor-a/../../etc"},
		{name: "dots inside a name", dir: "/opt/profiles/a..b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateProfilesDir(root, tt.dir)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "SNMP profiles directory")
		})
	}
}

// ---------------------------------------------------------------------------
// StartPolicy: the override reaches the same check
// ---------------------------------------------------------------------------

func TestStartPolicy_RejectsProfilesDirOutsideTheRoot(t *testing.T) {
	m := newTestManagerRootedAt(t.TempDir())
	pol := minimalPolicy(v2cAuth())
	pol.Config.ProfilesDir = t.TempDir()

	require.Error(t, m.StartPolicy("policy-a", pol))
	assert.Empty(t, m.policies)
	assert.Zero(t, cachedDirs(m), "a rejected directory must not have been loaded")
}

func TestStartPolicy_AcceptsProfilesDirUnderTheRoot(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vendor-a")
	require.NoError(t, os.Mkdir(dir, 0o750))

	m := newTestManagerRootedAt(root)
	t.Cleanup(func() { require.NoError(t, m.Stop()) })
	pol := minimalPolicy(v2cAuth())
	pol.Config.ProfilesDir = dir

	require.NoError(t, m.StartPolicy("policy-a", pol))
	assert.True(t, m.HasPolicy("policy-a"))
}

// ---------------------------------------------------------------------------
// collector lifetime
// ---------------------------------------------------------------------------

// A collector holds a fully resolved profile set, so one retained per directory
// a request happened to name is unbounded memory for anyone who can POST. It
// lives exactly as long as a policy using it.
func TestStartPolicy_DropsTheCollectorWhenTheStartFails(t *testing.T) {
	root := t.TempDir()
	m := newTestManagerRootedAt(root)
	t.Cleanup(func() { require.NoError(t, m.Stop()) })

	require.NoError(t, m.StartPolicy("policy-a", minimalPolicy(v2cAuth())))
	require.Equal(t, 1, cachedDirs(m))

	// Each of these names a real directory and is refused after its profile set
	// has been built, because the policy name is already taken.
	for _, name := range []string{"vendor-a", "vendor-b", "vendor-c"} {
		dir := filepath.Join(root, name)
		require.NoError(t, os.Mkdir(dir, 0o750))
		pol := minimalPolicy(v2cAuth())
		pol.Config.ProfilesDir = dir
		require.Error(t, m.StartPolicy("policy-a", pol))
	}

	assert.Equal(t, 1, cachedDirs(m), "only the running policy's profile set may be retained")
}

// The cache exists for this: two policies naming one directory read the
// profiles once between them.
func TestStartPolicy_SharesOneCollectorAcrossPoliciesNamingOneDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vendor-a")
	require.NoError(t, os.Mkdir(dir, 0o750))

	m := newTestManagerRootedAt(root)
	t.Cleanup(func() { require.NoError(t, m.Stop()) })
	pol := minimalPolicy(v2cAuth())
	pol.Config.ProfilesDir = dir

	require.NoError(t, m.StartPolicy("policy-a", pol))
	require.NoError(t, m.StartPolicy("policy-b", pol))

	assert.Equal(t, 1, cachedDirs(m))
	assert.Same(t, m.policies["policy-a"].metricsCollector, m.policies["policy-b"].metricsCollector)
}

func TestStopPolicy_DropsTheCollectorWithTheLastPolicyUsingIt(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vendor-a")
	require.NoError(t, os.Mkdir(dir, 0o750))

	m := newTestManagerRootedAt(root)
	pol := minimalPolicy(v2cAuth())
	pol.Config.ProfilesDir = dir
	require.NoError(t, m.StartPolicy("policy-a", pol))
	require.NoError(t, m.StartPolicy("policy-b", pol))

	require.NoError(t, m.StopPolicy("policy-a"))
	assert.Equal(t, 1, cachedDirs(m), "the profile set stays while another policy uses it")

	require.NoError(t, m.StopPolicy("policy-b"))
	assert.Zero(t, cachedDirs(m), "the last policy to go takes the profile set with it")
}

func TestStop_DropsEveryCollector(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vendor-a")
	require.NoError(t, os.Mkdir(dir, 0o750))

	m := newTestManagerRootedAt(root)
	overridden := minimalPolicy(v2cAuth())
	overridden.Config.ProfilesDir = dir
	require.NoError(t, m.StartPolicy("policy-a", minimalPolicy(v2cAuth())))
	require.NoError(t, m.StartPolicy("policy-b", overridden))
	require.Equal(t, 2, cachedDirs(m))

	require.NoError(t, m.Stop())

	assert.Zero(t, cachedDirs(m))
}
