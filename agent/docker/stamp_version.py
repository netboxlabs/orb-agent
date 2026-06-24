#!/usr/bin/env python
"""Stamp build metadata into a backend's version.py.

Usage: stamp_version.py <version> <path/to/version.py>

Reads BUILD_COMMIT and BUILD_TRACK from the environment and the version from the
first argument, then rewrites the __version__/__commit_hash__/__track__ module
assignments in the target file. Done in Python rather than sed so that a value
containing characters significant to sed (e.g. a '/' in a local branch-name
track) cannot corrupt the substitution.
"""
import os
import re
import sys

if len(sys.argv) != 3:
    sys.exit(f"usage: {sys.argv[0]} <version> <path/to/version.py>")

version, path = sys.argv[1], sys.argv[2]
fields = {
    "__version__": version,
    "__commit_hash__": os.environ.get("BUILD_COMMIT", "unknown"),
    "__track__": os.environ.get("BUILD_TRACK", "dev"),
}

with open(path) as f:
    text = f.read()
# Fail fast if an expected assignment isn't found: a silent no-op would let the
# image ship with the 0.0.0/unknown defaults this script exists to replace.
for name, value in fields.items():
    text, replaced = re.subn(
        rf"(?m)^{name} = .*$",
        lambda m, v=value, key=name: f"{key} = {v!r}",
        text,
        count=1,
    )
    if replaced != 1:
        sys.exit(f"{path}: expected to stamp '{name}' exactly once, matched {replaced}")
with open(path, "w") as f:
    f.write(text)
