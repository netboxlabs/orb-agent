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
// validateProfilesDir: confinement survives symlinks
// ---------------------------------------------------------------------------

// resolved is the path with every symlink component followed, which is what the
// confinement compares and what the loader ends up walking.
func resolved(t *testing.T, path string) string {
	t.Helper()
	got, err := filepath.EvalSymlinks(path)
	require.NoError(t, err)
	return got
}

// The ".." substring test is the barrier static analysis recognises, so it has
// to stay ahead of both containment checks and of any filesystem access. Each
// case below would be refused by a later check too, so the ".." message is what
// proves the barrier reached it first.
func TestValidateProfilesDir_RefusesDotsBeforeAnythingElse(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "a..b"), 0o750))
	outside := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(outside, "a..b"), 0o750))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "link")))

	tests := []struct {
		name string
		dir  string
	}{
		{name: "ahead of the name containment check", dir: "../a..b"},
		{name: "ahead of the canonical containment check", dir: filepath.Join(root, "link", "a..b")},
		{name: "and refused even where both would accept", dir: filepath.Join(root, "a..b")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateProfilesDir(root, tt.dir)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `must not contain ".."`)
		})
	}
}

// A symlink inside the root pointing out of it is the escape a lexical check
// misses: the name stays under the root while os.Stat and filepath.WalkDir
// follow the link into the external tree.
func TestValidateProfilesDir_RejectsWhatResolvesOutOfTheRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(outside, "secrets"), 0o750))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "link")))

	tests := []struct {
		name string
		dir  string
	}{
		{name: "the link itself", dir: filepath.Join(root, "link")},
		{name: "a directory under the link", dir: filepath.Join(root, "link", "secrets")},
		{name: "the link named relative to the root", dir: "link/secrets"},
		{name: "an absent path under the link", dir: filepath.Join(root, "link", "missing")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateProfilesDir(root, tt.dir)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "SNMP profiles directory")
		})
	}
}

// A link that stays inside the root is a legitimate way to arrange a profile
// tree, so it is accepted, and what comes back is the path that was checked
// rather than the name that was asked for.
func TestValidateProfilesDir_AcceptsWhatResolvesInsideTheRoot(t *testing.T) {
	root := t.TempDir()
	vendor := filepath.Join(root, "vendor-a")
	require.NoError(t, os.Mkdir(vendor, 0o750))
	require.NoError(t, os.Symlink(vendor, filepath.Join(root, "link")))

	got, err := validateProfilesDir(root, filepath.Join(root, "link"))
	require.NoError(t, err)
	assert.Equal(t, resolved(t, vendor), got, "the checked path is the one handed on")
}

// The operator's root may itself be reached through a symlink. Both sides are
// canonicalised, so an override under it is not rejected for the root's own
// spelling.
func TestValidateProfilesDir_AcceptsAnOverrideUnderASymlinkedRoot(t *testing.T) {
	target := t.TempDir()
	vendor := filepath.Join(target, "vendor-a")
	require.NoError(t, os.Mkdir(vendor, 0o750))
	root := filepath.Join(t.TempDir(), "root-link")
	require.NoError(t, os.Symlink(target, root))

	got, err := validateProfilesDir(root, filepath.Join(root, "vendor-a"))
	require.NoError(t, err)
	assert.Equal(t, resolved(t, vendor), got)
}

// A path inside the root that simply does not exist has nothing to resolve. It
// stays accepted so the loader reports the directory as missing, rather than
// the confinement reporting a resolution failure the operator cannot act on.
func TestValidateProfilesDir_AcceptsAnAbsentPathInsideTheRoot(t *testing.T) {
	root := t.TempDir()

	got, err := validateProfilesDir(root, filepath.Join(root, "missing", "deeper"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(resolved(t, root), "missing", "deeper"), got)
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

// The end of the escape: a policy naming a link inside the root must not have
// the tree behind it read.
func TestStartPolicy_RejectsProfilesDirReachedThroughASymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "external.yaml"), []byte("name: external\n"), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "link")))

	m := newTestManagerRootedAt(root)
	t.Cleanup(func() { require.NoError(t, m.Stop()) })
	pol := minimalPolicy(v2cAuth())
	pol.Config.ProfilesDir = filepath.Join(root, "link")

	require.Error(t, m.StartPolicy("policy-a", pol))
	assert.Empty(t, m.policies)
	assert.Zero(t, cachedDirs(m), "the external tree must not have been walked")
}

// A directory inside the root that is not there is an operator mistake, and the
// message has to name it as missing rather than as a path that cannot be
// resolved.
func TestStartPolicy_ReportsAnAbsentProfilesDirInsideTheRoot(t *testing.T) {
	root := t.TempDir()
	m := newTestManagerRootedAt(root)
	t.Cleanup(func() { require.NoError(t, m.Stop()) })
	pol := minimalPolicy(v2cAuth())
	pol.Config.ProfilesDir = filepath.Join(root, "missing")

	err := m.StartPolicy("policy-a", pol)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SNMP profiles directory not found")
	assert.Zero(t, cachedDirs(m))
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

// closeSpy is a cached collector that records how the manager released it.
// Only the release path is exercised, so the embedded Collector is never
// called.
type closeSpy struct {
	Collector
	m      *Manager
	closes int
	// lockFree records whether the cache lock was free while Close ran.
	lockFree bool
}

func (s *closeSpy) Close() {
	// Unregister waits out a collection cycle that is already running, so the
	// manager must not hold the cache lock across it.
	if s.m.collectorsMu.TryLock() {
		s.m.collectorsMu.Unlock()
		s.lockFree = true
	}
	s.closes++
}

// Deleting the cache entry does not free the collector: the meter still holds
// a callback closing over it, and calls it on every export. The last policy to
// go has to release it, and cannot do so under the cache lock.
func TestReleaseCollector_ReleasesTheCollectorWithTheLastPolicyUsingIt(t *testing.T) {
	m := newTestManager()
	spy := &closeSpy{m: m}
	m.collectorsByDir["vendor-a"] = &cachedCollector{collector: spy, refs: 2}

	m.releaseCollector("vendor-a")
	require.Zero(t, spy.closes, "a collector another policy is still using must not be released")

	m.releaseCollector("vendor-a")
	assert.Equal(t, 1, spy.closes, "the last policy to go must give the callbacks back to the meter")
	assert.True(t, spy.lockFree, "the release must run with the cache lock dropped")

	m.releaseCollector("vendor-a")
	assert.Equal(t, 1, spy.closes, "a collector already released must not be released again")
}

// StopPolicy is the routine trigger: a policy replaced under the same name
// stops, and what it was using has to go with it rather than staying
// registered for the rest of the process.
func TestStopPolicy_ReleasesTheCollectorItStopsUsing(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vendor-a")
	require.NoError(t, os.Mkdir(dir, 0o750))

	m := newTestManagerRootedAt(root)
	pol := minimalPolicy(v2cAuth())
	pol.Config.ProfilesDir = dir
	require.NoError(t, m.StartPolicy("policy-a", pol))

	m.collectorsMu.Lock()
	spy := &closeSpy{m: m}
	// The cache is keyed by the canonical path, which is what the confinement
	// hands the manager.
	m.collectorsByDir[resolved(t, dir)].collector = spy
	m.collectorsMu.Unlock()

	require.NoError(t, m.StopPolicy("policy-a"))

	assert.Equal(t, 1, spy.closes, "stopping the only policy must release what it was using")
	assert.True(t, spy.lockFree, "the release must run with the cache lock dropped")
}
