"""Plugin system for apksaw. Plugins are Python packages that register
additional MCP tools with the apksaw server."""

from importlib.metadata import entry_points
from apksaw.server import mcp
from apksaw.session import get_session


class PluginContext:
    """Context object passed to plugins, providing access to apksaw internals."""

    def __init__(self):
        self.mcp = mcp
        self.get_session = get_session

    def register_tool(self, func):
        """Register a function as an MCP tool."""
        return mcp.tool()(func)


def discover_and_load_plugins():
    """Discover and load all installed apksaw plugins.

    Plugins register via entry_points in their pyproject.toml:
    [project.entry-points."apksaw.plugins"]
    my_plugin = "my_package:register"

    The register function receives a PluginContext and should use it to register tools.
    """
    loaded = []
    errors = []

    # Python 3.12+ and 3.10+ compatible
    try:
        eps = entry_points(group="apksaw.plugins")
    except TypeError:
        eps = entry_points().get("apksaw.plugins", [])

    for ep in eps:
        try:
            register_func = ep.load()
            ctx = PluginContext()
            register_func(ctx)
            loaded.append(ep.name)
        except Exception as e:
            errors.append({"plugin": ep.name, "error": str(e)})

    return {"loaded": loaded, "errors": errors}


# ---------------------------------------------------------------------------
# Module-level state — populated by discover_and_load_plugins() in server.py
# ---------------------------------------------------------------------------

_plugin_results: dict = {"loaded": [], "errors": []}


@mcp.tool()
def list_plugins() -> dict:
    """List all loaded apksaw plugins and their status.

    Returns a dict with:
    - loaded: list of successfully loaded plugin names
    - errors: list of dicts with 'plugin' and 'error' keys for any failures
    """
    return _plugin_results
