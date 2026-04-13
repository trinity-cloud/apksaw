"""
Root conftest.py — pre-import shims for optional heavy dependencies.

apksaw's tool modules import from ``mcp.server.fastmcp`` and ``androguard``
at module level.  When running tests in a lightweight environment (CI,
developer machine without the full dependency tree, Python < 3.10 system
pytest), these imports fail before any test code runs.

This file installs lightweight stubs into ``sys.modules`` *before* any test
collection happens, so the actual test files can import and call tool
functions without needing a real MCP runtime or a real APK.

It also ensures ``src/`` is on ``sys.path`` so the ``apksaw`` package is
always importable regardless of whether it is installed editable or not.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Ensure src/ is importable
# ---------------------------------------------------------------------------

_src = str(Path(__file__).parent / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

# ---------------------------------------------------------------------------
# Stub out heavy / optional dependencies so tool modules import cleanly
# ---------------------------------------------------------------------------

def _stub(name: str) -> MagicMock:
    """Register a MagicMock stub under *name* in sys.modules if absent."""
    if name not in sys.modules:
        mock = MagicMock()
        sys.modules[name] = mock
    return sys.modules[name]


# MCP runtime — only needed at test time to satisfy the @mcp.tool() decorator
_mcp_stub = _stub("mcp")
_mcp_server_stub = _stub("mcp.server")
_fastmcp_stub = _stub("mcp.server.fastmcp")

# The FastMCP class must return an object whose .tool() can be used as a
# decorator that simply returns the original function unchanged.
_mcp_instance = MagicMock()
_mcp_instance.tool.return_value = lambda fn: fn  # @mcp.tool() is a no-op
_fastmcp_stub.FastMCP.return_value = _mcp_instance

# Androguard — only needed when actually loading a real APK; all tests mock it
_stub("androguard")
_stub("androguard.misc")
_stub("androguard.decompiler")
_stub("androguard.decompiler.decompiler")

# Other optional heavy deps that may not be in the test environment
for _mod in (
    "lief",
    "capstone",
    "yara",
    "frida",
    "frida_tools",
):
    _stub(_mod)

# ---------------------------------------------------------------------------
# Pre-import apksaw modules with DB patched to prevent real SQLite access
# ---------------------------------------------------------------------------
# apksaw.session calls restore_sessions() on import which hits SQLite.
# We patch the db helpers *before* the module is imported so that first import
# is clean and subsequent imports (in tests) use the already-imported module.

from unittest.mock import patch as _patch  # noqa: E402

with _patch("apksaw.db.init_db"), \
     _patch("apksaw.db.list_all_sessions", return_value=[]):
    import apksaw.session  # noqa: F401, E402
    # Pre-import server (which imports all tool modules) so they're cached
    # and ready before any test tries to patch them.
    try:
        import apksaw.server  # noqa: F401, E402
    except Exception:
        pass  # If server fails for any reason, individual tests will surface it
