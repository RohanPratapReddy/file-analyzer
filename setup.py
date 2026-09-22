"""Build shim for the ``file-analyzer`` meta-package.

Since the src->3-wheel split, the ``file-analyzer`` name is a thin **meta-package**
that installs the *analysis profile* -- the client foundation plus the analyzer
engine -- so that ``pip install file-analyzer`` keeps working for existing users
and pulls exactly what an analysis node needs (the database-hosting server stays a
deliberate, separate ``file-analyzer-server`` install).

This meta carries no code of its own. It single-sources the platform version from
``packages/client/file_analyzer/_version.py`` (the one source of truth, shipped in
``file-analyzer-client``) by AST-parsing it at build time -- without importing
anything -- and pins its two runtime deps to that exact version so the meta and the
wheels it drags in always move in lockstep. Everything else about the build comes
from ``pyproject.toml``. Build with ``--no-isolation`` so this runs in-tree and the
sibling ``_version.py`` path resolves.
"""

import ast
from pathlib import Path

from setuptools import setup


def _read_version() -> str:
    vfile = (
        Path(__file__).resolve()
        / ".."
        / "packages"
        / "client"
        / "file_analyzer"
        / "_version.py"
    ).resolve()
    tree = ast.parse(vfile.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__version__":
                    return ast.literal_eval(node.value)
    raise RuntimeError(f"could not find __version__ in {vfile}")


_VERSION = _read_version()

setup(
    version=_VERSION,
    # Lockstep pins: the meta always drags in the matching client + engine wheels.
    install_requires=[
        f"file-analyzer-client=={_VERSION}",
        f"file-analyzer-engine=={_VERSION}",
    ],
)
