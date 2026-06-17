"""Main MCP server for Android Threat Analyzer."""

from mcp.server.fastmcp import FastMCP

# Create the MCP server instance - imported by all tool modules
mcp = FastMCP(
    name="apksaw",
    instructions=(
        "Android app decompiler and security analyzer. "
        "Start by listing packages on a connected device with list_packages, "
        "or load an APK file with load_apk. "
        "Use the returned session_id for all subsequent analysis tools."
    ),
)

# Import all tool modules to register their tools with the mcp instance.
# Each module uses @mcp.tool() decorator to register tools.
from .tools import device  # noqa: F401, E402
from .tools import apk  # noqa: F401, E402
from .tools import dex  # noqa: F401, E402
from .tools import strings  # noqa: F401, E402
from .tools import xrefs  # noqa: F401, E402
from .tools import security  # noqa: F401, E402
from .tools import security_v2  # noqa: F401, E402
from .tools import certificates  # noqa: F401, E402
from .tools import native  # noqa: F401, E402
from .tools import dynamic  # noqa: F401, E402
from .tools import frida_gen  # noqa: F401, E402
from .tools import diff  # noqa: F401, E402
from .tools import patch_analysis  # noqa: F401, E402
from .tools import multidex  # noqa: F401, E402
from .tools import visualization  # noqa: F401, E402
from .tools import mapping  # noqa: F401, E402
from .tools import endpoints  # noqa: F401, E402
from .tools import yara_scan  # noqa: F401, E402
from .tools import protobuf  # noqa: F401, E402
from .tools import fuzzer  # noqa: F401, E402
from .tools import fuzzer_v2  # noqa: F401, E402
from .tools import anti_analysis  # noqa: F401, E402
from .tools import runtime  # noqa: F401, E402
from .tools import exploit_gen  # noqa: F401, E402
from .tools import secrets_probe  # noqa: F401, E402
from .tools import webview  # noqa: F401, E402
from .tools import app_links  # noqa: F401, E402

# Load plugins (must be after all built-in tool imports)
from .plugins import discover_and_load_plugins, _plugin_results  # noqa: F401, E402
_discovered = discover_and_load_plugins()
_plugin_results.update(_discovered)


def main():
    """Entry point for the MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
