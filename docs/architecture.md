# Architecture

## Overview

apksaw is a [Model Context Protocol](https://modelcontextprotocol.io/) server. An MCP server exposes capabilities (tools, resources, prompts) to an LLM host over a structured JSON-RPC protocol. The host — Claude Desktop, Claude Code, or any MCP-compatible agent — invokes tools by name with typed parameters and receives structured results.

```
LLM Host (Claude Desktop / Claude Code)
    │  MCP stdio transport (JSON-RPC)
    ▼
apksaw MCP Server  (FastMCP / mcp.server.fastmcp)
    │
    ├── Tool modules (device, apk, dex, strings, …)
    ├── Session store (in-memory + SQLite)
    └── Plugin loader (entry_points)
```

## MCP Protocol

apksaw uses the **stdio transport**: the process reads JSON-RPC requests from stdin and writes responses to stdout. This makes it easy to integrate with any MCP host — no networking required.

The server is built with [FastMCP](https://github.com/jlowin/fastmcp), which handles protocol framing, tool schema generation from Python type hints, and error serialization.

## Session Model

Every analysis begins with `load_apk` or `pull_apk`, which returns a `session_id`. All other tools accept this ID to retrieve the associated state.

```
load_apk("/path/to/app.apk")
→ Session(session_id="abc123", apk_path=..., sha256=..., package_name=...)
```

Sessions are stored in two places:

1. **In-memory dict** (`_sessions`) — fast lookup, lost on process exit.
2. **SQLite** (`~/.apksaw/apksaw.db`) — persists across restarts. On startup, `restore_sessions()` rehydrates the in-memory dict from the database.

Androguard objects (`APK`, `DEX`, `Analysis`) are **lazy-loaded**: they are not parsed until a tool actually needs them, so `load_apk` is fast even for large APKs.

## Tool Modules

Each source file under `src/apksaw/tools/` registers a group of related tools:

| Module | Tools |
|---|---|
| `device.py` | `device_info`, `list_packages`, `pull_apk`, `install_apk`, `uninstall_app`, `start_activity`, `send_broadcast`, `force_stop`, `clear_app_data`, `screenshot`, `monitor_logcat` |
| `apk.py` | `load_apk`, `app_info`, `get_manifest`, `get_permissions`, `get_components`, `list_files`, `get_signing_info` |
| `dex.py` | `list_classes`, `list_methods`, `get_class_info`, `decompile_class`, `decompile_method` |
| `strings.py` | `search_strings`, `extract_urls`, `extract_interesting_strings` |
| `xrefs.py` | `get_xrefs_to`, `get_xrefs_from`, `find_method_usage`, `get_call_graph`, `find_api_calls`, `search_code` |
| `security.py` | `scan_all`, `scan_manifest_security`, `scan_network_security`, `scan_code_injection`, `scan_crypto_issues`, `scan_data_storage`, `extract_secrets` |
| `certificates.py` | `get_signing_info`, `check_certificate_security` |
| `native.py` | `list_native_libs`, `analyze_native_lib`, `search_native_strings`, `check_native_security`, `disassemble_function` |
| `dynamic.py` | `get_runtime_info`, `prepare_frida_apk`, `take_screenshot` |

Tools import `mcp` from `server.py` and use the `@mcp.tool()` decorator. The decorator reads the function's type hints and docstring to generate the MCP tool schema automatically.

## Analysis Backends

| Backend | Purpose |
|---|---|
| [Androguard](https://github.com/androguard/androguard) | DEX/APK parsing, Dalvik bytecode analysis, cross-references |
| [LIEF](https://lief.re/) | ELF binary parsing for native libraries |
| [Capstone](https://www.capstone-engine.org/) | ARM/ARM64/x86 disassembly |
| ADB | Live device interaction |
| Frida | Dynamic instrumentation (optional) |

## Plugin System

After loading built-in tool modules, `server.py` calls `discover_and_load_plugins()`, which scans Python entry points in the `apksaw.plugins` group and invokes each plugin's `register(ctx)` function. See [Plugins](plugins.md) for details.
