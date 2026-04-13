# Getting Started

This guide walks through your first apksaw analysis session end-to-end.

## Prerequisites

- Python 3.10+
- An MCP-compatible client (Claude Desktop, Claude Code, or any MCP host)
- ADB in your `PATH` if you want device interaction tools

## 1. Install apksaw

```bash
pip install apksaw
# or with uv
uv add apksaw
```

## 2. Configure your MCP client

Add apksaw to your MCP client's configuration. For **Claude Desktop**, edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "apksaw": {
      "command": "apksaw"
    }
  }
}
```

Restart Claude Desktop. You should see apksaw tools available in the tools panel.

## 3. Run your first analysis

### From a connected device

```
list_packages()
# Lists all installed packages on the connected Android device

pull_apk(package_name="com.example.app")
# Pulls the APK from the device to a local workspace
# Returns session_id for further analysis
```

### From a local APK file

```
load_apk(apk_path="/path/to/app.apk")
# Returns: {"session_id": "abc123", "package_name": "...", "sha256": "..."}
```

## 4. Analyze the APK

Use the `session_id` returned above with any analysis tool:

```
get_permissions(session_id="abc123")
get_manifest(session_id="abc123")
scan_all(session_id="abc123")
extract_secrets(session_id="abc123")
```

## 5. Next steps

- Read the [Tools](tools/device.md) reference for the full list of available tools.
- Set up [Plugins](plugins.md) to extend apksaw with custom analysis.
- See [Architecture](architecture.md) to understand how sessions and tool modules work.
