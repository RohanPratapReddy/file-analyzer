"""Build shim: single-source the version from the client wheel's _version.py.

The one source of truth for the platform version is
``packages/client/file_analyzer/_version.py`` (it ships in ``file-analyzer-client``,
which every other wheel depends on). The server wheel does not carry that file, so
setuptools' ``attr:`` dynamic directive cannot reach it. This shim AST-parses the
sibling file at build time -- without importing anything -- and hands the version
to setuptools. Everything else about the build comes from ``pyproject.toml``.
"""

import ast
from pathlib import Path

from setuptools import setup


def _read_version() -> str:
    vfile = (
        Path(__file__).resolve().parents[1] / "client" / "file_analyzer" / "_version.py"
    )
    tree = ast.parse(vfile.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__version__":
                    return ast.literal_eval(node.value)
    raise RuntimeError(f"could not find __version__ in {vfile}")


setup(version=_read_version())
