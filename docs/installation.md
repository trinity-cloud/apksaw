# Installation

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | 3.12 recommended |
| ADB | any | Required for device tools only |
| Android device or emulator | API 21+ | For live device interaction |

ADB must be on your `PATH`:

```bash
which adb   # should print a path
adb devices # should list connected devices
```

## Install apksaw

### pip

```bash
pip install apksaw
```

### uv (recommended)

```bash
uv add apksaw
# or globally
uv tool install apksaw
```

### From source

```bash
git clone https://github.com/trinity-cloud/apksaw
cd apksaw
uv sync
```

## Verify the installation

```bash
apksaw --version
# or
python -m apksaw --version
```

## MCP Configuration

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "apksaw": {
      "command": "apksaw"
    }
  }
}
```

### Claude Code (CLI)

```bash
claude mcp add apksaw -- apksaw
```

### Custom MCP host

apksaw speaks the MCP stdio transport. Launch it with:

```bash
apksaw
```

and pipe JSON-RPC messages over stdin/stdout per the MCP specification.

## Optional dependencies

Some features require additional system tools:

| Feature | Requirement |
|---|---|
| Native library disassembly | Capstone (installed automatically) |
| ELF parsing | LIEF (installed automatically) |
| Frida instrumentation | `frida-tools` (`pip install frida-tools`) |
| APK repacking | `apktool` and `zipalign` in PATH |

## Workspace storage

By default, apksaw stores session data and extracted APKs in:

```
~/.apksaw/workspaces/
~/.apksaw/apksaw.db
```

Set `DROIDSCOPE_WORKSPACES_DIR` to override.
