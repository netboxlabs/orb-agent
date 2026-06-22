#!/usr/bin/env python
# Copyright 2026 NetBox Labs Inc
"""NetBox Labs - PackageFinder Unit Tests."""

import importlib
import sys
import types
from pathlib import Path

import pytest

import worker.package_finder as pf
from worker.package_finder import PackageFinder, install_finder
from worker.package_finder import maybe_evict as _maybe_evict

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_bundle(root: Path, bundle_name: str, version: str, module_name: str) -> Path:
    """Create a bundle directory with a current symlink and an importable package."""
    version_dir = root / bundle_name / version
    pkg_dir = version_dir / module_name
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "__init__.py").write_text(f'VERSION = "{version}"\n')

    current = root / bundle_name / "current"
    if current.is_symlink():
        current.unlink()
    current.symlink_to(version_dir)

    return version_dir


def _make_single_file_bundle(root: Path, bundle_name: str, version: str, module_name: str) -> Path:
    """Create a bundle directory with a current symlink and a single-file module."""
    version_dir = root / bundle_name / version
    version_dir.mkdir(parents=True)
    (version_dir / f"{module_name}.py").write_text(f'VERSION = "{version}"\n')

    current = root / bundle_name / "current"
    if current.is_symlink():
        current.unlink()
    current.symlink_to(version_dir)

    return version_dir


def _remove_from_sys_modules(*names: str):
    """Remove module names (and submodules) from sys.modules."""
    for name in names:
        for key in list(sys.modules):
            if key == name or key.startswith(f"{name}."):
                del sys.modules[key]


# ---------------------------------------------------------------------------
# PackageFinder.find_spec
# ---------------------------------------------------------------------------

class TestPackageFinderFindSpec:
    """Tests for PackageFinder.find_spec."""

    def test_resolves_package_from_current_symlink(self, tmp_path, monkeypatch):
        """find_spec returns a valid spec for a package inside a current/ symlink."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path))
        _make_bundle(tmp_path, "nbl-custom-worker", "0.1.0", "nbl_custom_worker")

        finder = PackageFinder()
        spec = finder.find_spec("nbl_custom_worker", None)

        assert spec is not None
        assert spec.name == "nbl_custom_worker"

    def test_resolves_single_file_module(self, tmp_path, monkeypatch):
        """find_spec resolves a single-file module (module.py) from a bundle."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path))
        _make_single_file_bundle(tmp_path, "nbl-simple", "1.0.0", "nbl_simple")

        finder = PackageFinder()
        spec = finder.find_spec("nbl_simple", None)

        assert spec is not None
        assert spec.name == "nbl_simple"

    def test_returns_none_when_bundles_root_missing(self, tmp_path, monkeypatch):
        """find_spec returns None when BUNDLES_ROOT does not exist."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path / "nonexistent"))

        finder = PackageFinder()
        assert finder.find_spec("nbl_custom_worker", None) is None

    def test_returns_none_when_module_not_in_any_bundle(self, tmp_path, monkeypatch):
        """find_spec returns None for a module not present in any bundle."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path))
        _make_bundle(tmp_path, "nbl-custom-worker", "0.1.0", "nbl_custom_worker")

        finder = PackageFinder()
        assert finder.find_spec("nbl_something_else", None) is None

    def test_skips_broken_symlink(self, tmp_path, monkeypatch):
        """find_spec skips a bundle whose current/ symlink is broken."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path))

        # Create a dangling symlink
        bundle_dir = tmp_path / "nbl-broken"
        bundle_dir.mkdir()
        current = bundle_dir / "current"
        current.symlink_to(tmp_path / "nbl-broken" / "nonexistent_version")

        finder = PackageFinder()
        assert finder.find_spec("nbl_broken", None) is None

    def test_module_is_importable_after_finder_installed(self, tmp_path, monkeypatch):
        """A module resolved by PackageFinder can actually be imported."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path))
        _make_bundle(tmp_path, "nbl-test-pkg", "0.2.0", "nbl_test_pkg")
        _remove_from_sys_modules("nbl_test_pkg")

        finder = PackageFinder()
        # Temporarily install just for this test
        sys.meta_path.append(finder)
        try:
            mod = importlib.import_module("nbl_test_pkg")
            assert mod.VERSION == "0.2.0"
        finally:
            sys.meta_path.remove(finder)
            _remove_from_sys_modules("nbl_test_pkg")


# ---------------------------------------------------------------------------
# PackageFinder._active_bundle_dirs
# ---------------------------------------------------------------------------

class TestActiveBundleDirs:
    """Tests for PackageFinder._active_bundle_dirs."""

    def test_returns_empty_when_root_missing(self, tmp_path, monkeypatch):
        """_active_bundle_dirs returns [] when BUNDLES_ROOT does not exist."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path / "missing"))
        assert PackageFinder()._active_bundle_dirs() == []

    def test_returns_only_valid_current_dirs(self, tmp_path, monkeypatch):
        """_active_bundle_dirs returns only bundles with a valid current/ symlink."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path))
        _make_bundle(tmp_path, "nbl-good", "1.0.0", "nbl_good")

        # Bundle with broken symlink
        bad = tmp_path / "nbl-bad"
        bad.mkdir()
        (bad / "current").symlink_to(tmp_path / "nbl-bad" / "ghost")

        dirs = PackageFinder()._active_bundle_dirs()
        assert len(dirs) == 1
        assert dirs[0] == tmp_path / "nbl-good" / "current"


# ---------------------------------------------------------------------------
# _maybe_evict
# ---------------------------------------------------------------------------

class TestMaybeEvict:
    """Tests for the _maybe_evict eviction helper."""

    def test_noop_when_bundle_not_present(self, tmp_path, monkeypatch):
        """_maybe_evict does nothing when the package has no bundle directory."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path))
        # Should not raise even if module is in sys.modules
        fake = types.ModuleType("nbl_no_bundle")
        sys.modules["nbl_no_bundle"] = fake
        try:
            _maybe_evict("nbl_no_bundle")  # no bundle dir → silent return
            assert "nbl_no_bundle" in sys.modules
        finally:
            sys.modules.pop("nbl_no_bundle", None)

    def test_noop_when_module_not_imported(self, tmp_path, monkeypatch):
        """_maybe_evict does nothing when the module is not in sys.modules."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path))
        _make_bundle(tmp_path, "nbl-custom-worker", "0.1.0", "nbl_custom_worker")
        _remove_from_sys_modules("nbl_custom_worker")

        _maybe_evict("nbl_custom_worker")  # not in sys.modules → silent return

    def test_stamps_bundle_path_on_first_call(self, tmp_path, monkeypatch):
        """_maybe_evict stamps __bundle_path__ on the module the first time it sees it."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path))
        _make_bundle(tmp_path, "nbl-custom-worker", "0.1.0", "nbl_custom_worker")

        fake = types.ModuleType("nbl_custom_worker")
        sys.modules["nbl_custom_worker"] = fake
        try:
            _maybe_evict("nbl_custom_worker")
            assert hasattr(fake, "__bundle_path__")
            assert "0.1.0" in fake.__bundle_path__
        finally:
            _remove_from_sys_modules("nbl_custom_worker")

    def test_does_not_evict_when_symlink_unchanged(self, tmp_path, monkeypatch):
        """_maybe_evict leaves sys.modules intact when the symlink hasn't moved."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path))
        version_dir = _make_bundle(tmp_path, "nbl-custom-worker", "0.1.0", "nbl_custom_worker")

        fake = types.ModuleType("nbl_custom_worker")
        fake.__bundle_path__ = str(version_dir)
        sys.modules["nbl_custom_worker"] = fake
        try:
            _maybe_evict("nbl_custom_worker")
            assert "nbl_custom_worker" in sys.modules
        finally:
            _remove_from_sys_modules("nbl_custom_worker")

    def test_evicts_module_tree_when_symlink_changes(self, tmp_path, monkeypatch):
        """_maybe_evict drops the full package subtree when the symlink moves to a new version."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path))

        # Start at 0.1.0
        _make_bundle(tmp_path, "nbl-custom-worker", "0.1.0", "nbl_custom_worker")
        old_path = str(tmp_path / "nbl-custom-worker" / "0.1.0")

        # Populate sys.modules with the old version tree
        fake_root = types.ModuleType("nbl_custom_worker")
        fake_root.__bundle_path__ = old_path
        fake_sub = types.ModuleType("nbl_custom_worker.runner")
        fake_unrelated = types.ModuleType("nbl_cisco_meraki.runner")
        sys.modules["nbl_custom_worker"] = fake_root
        sys.modules["nbl_custom_worker.runner"] = fake_sub
        sys.modules["nbl_cisco_meraki.runner"] = fake_unrelated

        # Upgrade symlink to 0.2.0
        _make_bundle(tmp_path, "nbl-custom-worker", "0.2.0", "nbl_custom_worker")

        try:
            _maybe_evict("nbl_custom_worker")
            # After
            assert "nbl_custom_worker" not in sys.modules
            assert "nbl_custom_worker.runner" not in sys.modules
            assert "nbl_cisco_meraki.runner" in sys.modules  # unrelated, must be untouched
        finally:
            _remove_from_sys_modules("nbl_custom_worker")
            sys.modules.pop("nbl_cisco_meraki.runner", None)

    def test_handles_hyphen_to_underscore_bundle_dir(self, tmp_path, monkeypatch):
        """_maybe_evict finds bundle dir using hyphens when module name uses underscores."""
        monkeypatch.setenv("BUNDLES_ROOT_PATH", str(tmp_path))
        # Bundle dir uses hyphens; module name uses underscores
        _make_bundle(tmp_path, "nbl-custom-worker", "0.1.0", "nbl_custom_worker")

        fake = types.ModuleType("nbl_custom_worker")
        sys.modules["nbl_custom_worker"] = fake
        try:
            _maybe_evict("nbl_custom_worker")
            # Should have stamped the path (found via hyphen dir name)
            assert hasattr(fake, "__bundle_path__")
        finally:
            _remove_from_sys_modules("nbl_custom_worker")


# ---------------------------------------------------------------------------
# install_finder
# ---------------------------------------------------------------------------

class TestInstallFinder:
    """Tests for the install_finder startup helper."""

    def setup_method(self):
        """Remove any existing PackageFinder before each test."""
        sys.meta_path[:] = [f for f in sys.meta_path if not isinstance(f, PackageFinder)]

    def teardown_method(self):
        """Clean up after each test."""
        sys.meta_path[:] = [f for f in sys.meta_path if not isinstance(f, PackageFinder)]

    def test_installs_finder_into_meta_path(self):
        """install_finder appends a PackageFinder to sys.meta_path."""
        install_finder()
        assert any(isinstance(f, PackageFinder) for f in sys.meta_path)

    def test_idempotent_does_not_install_twice(self):
        """install_finder is idempotent — calling it twice installs only one finder."""
        install_finder()
        install_finder()
        count = sum(1 for f in sys.meta_path if isinstance(f, PackageFinder))
        assert count == 1

    def test_finder_appended_last(self):
        """install_finder appends to the end of sys.meta_path so stdlib takes priority."""
        install_finder()
        assert isinstance(sys.meta_path[-1], PackageFinder)
