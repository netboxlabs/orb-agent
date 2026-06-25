#!/usr/bin/env python
# Copyright 2025 NetBox Labs Inc
"""
Worker Package Finder.

Discovers plugins installed by the PackageManager from disk.
Bundles are extracted to BUNDLES_ROOT/<name>/current/ and this
finder makes them importable without pip.
"""

import importlib.abc
import importlib.util
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

def _bundles_root():
    """Return the bundles root path, or None if BUNDLES_ROOT_PATH is not set."""
    val = os.environ.get("BUNDLES_ROOT_PATH")
    if not val:
        logger.debug("PackageFinder: BUNDLES_ROOT_PATH is not set; bundle delivery disabled")
        return None
    return Path(val)


class PackageFinder(importlib.abc.MetaPathFinder):
    """
    sys.meta_path finder that resolves modules from bundle directories.

    Appended last in sys.meta_path so it only fires after stdlib and
    pip-installed packages are exhausted.
    """

    def __init__(self):
        """Initialise the finder with an empty bundle-dir cache."""
        self._cached_bundle_dirs = []  # list[Path]
        self._cached_root_mtime = None  # float or None

    def find_spec(self, fullname: str, path, target=None):
        """Locate a module spec by scanning active bundle current/ directories."""
        # Only handle top-level imports; submodules are resolved by the standard machinery
        # via submodule_search_locations set on the top-level spec. Single-file bundle
        # modules cannot have submodules by design.
        if "." in fullname:
            return None

        for bundle_dir in self._active_bundle_dirs():
            resolved_dir = bundle_dir.resolve()
            # Package directory (fullname/__init__.py)
            candidate = resolved_dir / fullname
            if (candidate / "__init__.py").is_file():
                spec = importlib.util.spec_from_file_location(
                    fullname,
                    candidate / "__init__.py",
                    submodule_search_locations=[str(candidate)],
                )
                if spec is not None:
                    logger.debug(f"PackageFinder: resolved '{fullname}' from {resolved_dir}")
                    return spec

            # Single-file module (fullname.py)
            module_file = resolved_dir / f"{fullname}.py"
            if module_file.is_file():
                spec = importlib.util.spec_from_file_location(fullname, module_file)
                if spec is not None:
                    logger.debug(f"PackageFinder: resolved '{fullname}' from {resolved_dir}")
                    return spec

        return None

    def _active_bundle_dirs(self) -> list:
        """
        Return current/ dirs for all bundles with a valid symlink.

        Cache is invalidated when either BUNDLES_ROOT or any of its immediate
        subdirectories change mtime. This catches both new bundle directories
        being added at the root level AND current/ symlinks being created or
        swapped inside existing bundle directories (which only update the
        bundle subdirectory mtime, not the root).
        """
        bundles_root = _bundles_root()
        if bundles_root is None or not bundles_root.is_dir():
            self._cached_bundle_dirs = []
            self._cached_root_mtime = None
            return []
        try:
            # Collect mtimes of root and all immediate subdirectories.
            subdirs = sorted(b for b in bundles_root.iterdir() if b.is_dir())
            mtime = tuple(
                p.stat().st_mtime
                for p in [bundles_root] + subdirs
            )
        except OSError:
            return self._cached_bundle_dirs
        if mtime != self._cached_root_mtime:
            self._cached_bundle_dirs = [
                b / "current"
                for b in subdirs
                if (b / "current").exists()
            ]
            self._cached_root_mtime = mtime
        return self._cached_bundle_dirs


def maybe_evict(package_name: str) -> None:
    """
    Evict a package from sys.modules if its bundle symlink has changed.

    Called in PolicyRunner.setup() before load_class() so a version upgrade
    by the PackageManager takes effect without restarting the worker.

    The resolved symlink path is stamped onto the module as __bundle_path__
    here (post-import) rather than in find_spec (pre-import) so sys.modules
    is guaranteed to contain the module when we write the attribute.

    Args:
    ----
        package_name: Top-level module name (e.g. "nbl_custom_worker").

    """
    # Derive top-level module name in case a dotted path was passed
    # (e.g. "nbl_custom_worker.backend" → "nbl_custom_worker").
    top_level = package_name.split(".", 1)[0]

    # Derive the bundle directory name: module names use underscores,
    # bundle dirs may use hyphens (e.g. nbl-custom-worker). Check both.
    bundles_root = _bundles_root()
    if bundles_root is None:
        return
    candidates = [
        bundles_root / top_level,
        bundles_root / top_level.replace("_", "-"),
    ]
    current = next(
        (c / "current" for c in candidates if (c / "current").exists()), None
    )
    if current is None:
        return

    try:
        resolved = str(current.resolve())
    except OSError:
        return

    mod = sys.modules.get(top_level)
    if mod is None:
        return

    # Stamp on first sight. If the module was loaded before we started
    # stamping, its code may already be stale — evict if __file__ disagrees.
    cached = getattr(mod, "__bundle_path__", None)
    if cached is None:
        mod_file = getattr(mod, "__file__", None)
        if mod_file and not Path(mod_file).is_relative_to(Path(resolved)):
            # Module was loaded from a different (older) bundle version — evict it.
            cached = str(mod_file)
        else:
            mod.__bundle_path__ = resolved
            return

    if cached != resolved:
        to_remove = [
            k for k in sys.modules
            if k == top_level or k.startswith(f"{top_level}.")
        ]
        for key in to_remove:
            del sys.modules[key]
        logger.info(
            f"PackageFinder: evicted {len(to_remove)} module(s) for '{top_level}' "
            f"({cached!r} → {resolved!r})"
        )
    else:
        logger.debug(f"PackageFinder: '{top_level}' is current, no eviction needed")


def install_finder() -> None:
    """Install PackageFinder into sys.meta_path (idempotent)."""
    bundles_root = _bundles_root()
    if bundles_root is None:
        logger.debug("PackageFinder: BUNDLES_ROOT_PATH not set, skipping install")
        return
    if any(isinstance(f, PackageFinder) for f in sys.meta_path):
        logger.debug("PackageFinder: already installed, skipping")
        return
    sys.meta_path.append(PackageFinder())
    logger.info(f"PackageFinder: installed (bundles root: {bundles_root})")
