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
2. **SQLite** (`~/.apksaw/db/index.db`) — persists across restarts. On startup, `restore_sessions()` rehydrates the in-memory dict from the database.

Androguard objects (`APK`, `DEX`, `Analysis`) are **lazy-loaded**: they are not parsed until a tool actually needs them, so `load_apk` is fast even for large APKs.

## Tool Modules

Each source file under `src/apksaw/tools/` registers a group of related tools:

| Module | Tools |
|---|---|
| `device.py` | `device_info`, `list_packages`, `app_info`, `pull_apk`, `screenshot` |
| `dynamic.py` | `monitor_logcat`, `start_activity`, `send_broadcast`, `get_runtime_info`, `force_stop`, `clear_app_data`, `install_apk`, `uninstall_app`, `take_screenshot`, `prepare_frida_apk` |
| `runtime.py` | `repackage_with_gadget`, `run_frida_script`, `capture_runtime_secrets` |
| `apk.py` | `load_apk`, `get_manifest`, `get_permissions`, `get_components`, `list_files` |
| `dex.py` | `list_classes`, `get_class_info`, `list_methods`, `decompile_method`, `decompile_class`, `decompile_apk_full` |
| `strings.py` | `search_strings`, `extract_urls`, `extract_secrets`, `search_code`, `extract_interesting_strings` |
| `xrefs.py` | `get_xrefs_to`, `get_xrefs_from`, `get_call_graph`, `find_method_usage`, `find_api_calls` |
| `security.py` | `scan_manifest_security`, `scan_crypto_issues`, `scan_network_security`, `scan_code_injection`, `scan_data_storage`, `scan_all` |
| `security_v2.py` | `scan_crypto_issues_v2`, `scan_network_security_v2`, `scan_code_injection_v2`, `scan_all_v2` |
| `certificates.py` | `get_signing_info`, `check_certificate_security` |
| `native.py` | `list_native_libs`, `analyze_native_lib`, `search_native_strings`, `check_native_security`, `disassemble_function` |
| `diff.py` | `diff_apks`, `diff_manifest`, `diff_classes`, `diff_strings`, `diff_security` |
| `patch_analysis.py` | `analyze_security_patches`, `find_patched_methods`, `find_vulnerability_window` |
| `fuzzer.py` | `fuzz_exported_components`, `fuzz_deep_links`, `fuzz_content_providers` |
| `fuzzer_v2.py` | `fuzz_exported_components_v2`, `fuzz_deep_links_v2`, `automine_blind_sqli` |
| `exploit_gen.py` | `poc_old_version`, `generate_component_poc`, `generate_webview_exploit`, `generate_provider_poc`, `generate_deeplink_poc`, `generate_intent_redirection_poc` |
| `frida_gen.py` | `generate_frida_hook`, `generate_ssl_bypass`, `generate_token_dumper`, `generate_crypto_hooks` |
| `anti_analysis.py` | `detect_anti_analysis`, `generate_bypass_script` |
| `endpoints.py` | `extract_api_endpoints`, `find_auth_interceptors` |
| `protobuf.py` | `extract_protobuf_schemas`, `find_grpc_services`, `export_proto_file` |
| `yara_scan.py` | `scan_yara`, `list_yara_rules` |
| `mapping.py` | `load_mapping`, `deobfuscate_name`, `detect_obfuscation` |
| `multidex.py` | `list_dex_files`, `analyze_dex_boundaries`, `get_dex_class_map` |
| `visualization.py` | `export_call_graph` |

Tools import `mcp` from `server.py` and use the `@mcp.tool()` decorator. The decorator reads the function's type hints and docstring to generate the MCP tool schema automatically.

## Analysis Backends

| Backend | Purpose |
|---|---|
| [Androguard](https://github.com/androguard/androguard) | DEX/APK parsing, Dalvik bytecode analysis, cross-references |
| [LIEF](https://lief.re/) | ELF binary parsing for native libraries |
| [Capstone](https://www.capstone-engine.org/) | ARM/ARM64/x86 disassembly |
| ADB | Live device interaction |
| Frida | Dynamic instrumentation (optional) |
| apktool / Android build tools | Gadget injection, APK repackaging, zipalign, and signing |

## Plugin System

After loading built-in tool modules, `server.py` calls `discover_and_load_plugins()`, which scans Python entry points in the `apksaw.plugins` group and invokes each plugin's `register(ctx)` function. See [Plugins](plugins.md) for details.
