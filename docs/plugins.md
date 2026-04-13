# Plugins

apksaw supports plugins — Python packages that register additional MCP tools alongside the built-in ones. Plugins are discovered automatically at startup via Python entry points.

## How It Works

1. apksaw calls `discover_and_load_plugins()` after all built-in tools are registered.
2. It scans the `apksaw.plugins` entry point group using `importlib.metadata`.
3. For each registered entry point, it calls `register(ctx)` with a `PluginContext`.
4. The `PluginContext` provides access to the MCP server and session system.

## Writing a Plugin

### 1. Create a Python package

```
my-apksaw-plugin/
├── pyproject.toml
└── src/
    └── my_plugin/
        └── __init__.py
```

### 2. Register the entry point

In `pyproject.toml`:

```toml
[project]
name = "apksaw-my-plugin"
version = "0.1.0"
dependencies = ["apksaw"]

[project.entry-points."apksaw.plugins"]
my_plugin = "my_plugin:register"
```

### 3. Implement `register(ctx)`

```python
# src/my_plugin/__init__.py

def register(ctx):
    """Called by apksaw at startup."""

    @ctx.register_tool
    def my_custom_scan(session_id: str) -> dict:
        """Performs a custom analysis on the APK."""
        session = ctx.get_session(session_id)
        apk = session.apk  # Androguard APK object
        # ... your analysis logic ...
        return {"status": "ok", "findings": []}
```

### 4. Install the plugin

```bash
pip install -e .
# or
uv add my-apksaw-plugin
```

Restart apksaw. The new tool will appear alongside built-in tools.

## PluginContext API

| Attribute / Method | Description |
|---|---|
| `ctx.mcp` | The `FastMCP` server instance |
| `ctx.get_session(session_id)` | Retrieve a `Session` by ID |
| `ctx.register_tool(func)` | Decorator — registers `func` as an MCP tool |

## Checking Loaded Plugins

Use the built-in `list_plugins` tool:

```
list_plugins()
# → {"loaded": ["my_plugin"], "errors": []}
```

Any plugins that failed to load are reported in `errors` with the exception message.

## Example Plugin

A complete working example is in [`examples/plugin-template/`](https://github.com/trinity-cloud/apksaw/tree/main/examples/plugin-template).
