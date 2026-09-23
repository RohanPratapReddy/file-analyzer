"""Single source of truth for the file-analyzer version.

This module is deliberately tiny and import-free so that:

* ``pyproject.toml`` can read it statically via setuptools' ``attr:`` directive
  (``[tool.setuptools.dynamic] version = {attr = "file_analyzer._version.__version__"}``),
  by AST-parsing this file WITHOUT importing the package (no fleet import at
  build time);
* the MCP server (``mcp_server.py``) can recover the version by parsing this file
  directly, without triggering ``file_analyzer/__init__.py`` (which would import the whole
  analyzer fleet and slow the agent handshake);
* the SDK exposes it as ``file_analyzer.__version__`` and the CLIs expose it via
  ``--version``.

Bump this one string for a release; every other surface follows.
"""

__version__ = "1.1.1"
