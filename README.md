<p align="center">
  <h1 align="center">apksaw</h1>
  <p align="center"><strong>AI-agent Android reverse engineering toolkit</strong></p>
  <p align="center">74 tools. One MCP server. Plug into Claude Code and talk to APKs.</p>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#tools">Tools</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#case-studies">Case Studies</a> &bull;
  <a href="#examples">Examples</a>
</p>

---

**apksaw** is an MCP server that gives AI agents the hands to touch Android bytecode. It's a force multiplier, not a replacement for security expertise.

An AI agent can't read binary DEX files. apksaw solves that. It translates APKs into structured, queryable data — decompiled Java, cross-reference graphs, parsed manifests, string pools, native symbols — so the agent can reason about Android apps the same way a human analyst uses Ghidra or jadx.

```
> Pull the app from my phone, decompile it, and find hardcoded API keys.
```

The tools find candidates. The agent verifies them. In real-world testing, automated scanners produced a **65% false positive rate** — every finding had to be manually verified by decompiling the surrounding code and tracing data flow. apksaw makes that verification fast. It doesn't make it unnecessary.

> **apksaw is the microscope, not the pathologist.**

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/trinity-cloud/apksaw.git
cd apksaw
uv sync

# Add to Claude Code
claude mcp add apksaw -- uv run --directory /path/to/apksaw apksaw

# Or copy .mcp.json to your project root
```

Restart Claude Code. All 74 tools appear automatically.

## How It Works

```
You (natural language)
  |
  v
Claude Code
  |
  v
apksaw MCP Server (stdio)
  |
  +--> Androguard -----> DEX parsing, decompilation, cross-references
  +--> LIEF ------------> Native .so ELF analysis
  +--> Capstone --------> ARM/ARM64 disassembly
  +--> JADX ------------> Java decompilation (auto-downloaded)
  +--> ADB -------------> Device interaction, APK extraction
```

The agent calls tools, reads the structured JSON results, reasons about them, and chains further tool calls. You describe what you want in plain English. The agent decides which tools to call, in what order, and how to interpret the results.

## Tools

### Device (5 tools)
| Tool | Description |
|---|---|
| `device_info` | Model, Android version, SDK level, serial |
| `list_packages` | List installed apps (third-party, system, all) |
| `app_info` | Detailed package info via `dumpsys` |
| `pull_apk` | Extract APK from device (handles split APKs) |
| `screenshot` | Capture device screen |

### APK Analysis (5 tools)
| Tool | Description |
|---|---|
| `load_apk` | Load APK for analysis, returns session ID |
| `get_manifest` | Full parsed AndroidManifest as structured JSON |
| `get_permissions` | Requested, declared, and dangerous permissions |
| `get_components` | Activities, services, receivers, providers with export status |
| `list_files` | All files in the APK with sizes |

### DEX / Decompilation (5 tools)
| Tool | Description |
|---|---|
| `list_classes` | Browse classes with filtering and pagination |
| `get_class_info` | Fields, methods, superclass, interfaces |
| `list_methods` | Search methods by class or name pattern |
| `decompile_method` | Decompile a single method to Java (falls back to smali) |
| `decompile_class` | Decompile an entire class |

### String Analysis (5 tools)
| Tool | Description |
|---|---|
| `search_strings` | Regex search across the DEX string pool |
| `extract_urls` | All URLs categorized (HTTPS, HTTP, content://, file://) |
| `extract_secrets` | API keys, tokens, credentials via pattern matching |
| `search_code` | Search through disassembled bytecode instructions |
| `extract_interesting_strings` | Auto-filter boilerplate, surface the good stuff |

### Cross-References (5 tools)
| Tool | Description |
|---|---|
| `get_xrefs_to` | What does this method/class call? |
| `get_xrefs_from` | Who calls this method/class? |
| `get_call_graph` | Build a call graph (BFS, configurable depth) |
| `find_method_usage` | Find all callers of a specific API |
| `find_api_calls` | Regex search across all method invocations |

### Security Scanning (6 tools)
| Tool | Description |
|---|---|
| `scan_manifest_security` | Debuggable, backup, exported components, cleartext |
| `scan_crypto_issues` | ECB mode, hardcoded keys, weak hashes, static IVs |
| `scan_network_security` | HTTP URLs, TrustManager bypasses, missing pinning |
| `scan_code_injection` | WebView JS interfaces, SQL injection, Runtime.exec |
| `scan_data_storage` | World-readable files, external storage, logcat leaks |
| `scan_all` | Run all scanners, combined report with severity counts |

### Certificate Analysis (2 tools)
| Tool | Description |
|---|---|
| `get_signing_info` | Signing schemes, certificate details, fingerprints |
| `check_certificate_security` | Debug certs, weak keys, Janus vulnerability check |

### Native Analysis (5 tools)
| Tool | Description |
|---|---|
| `list_native_libs` | All .so files grouped by architecture |
| `analyze_native_lib` | Exports, imports, JNI functions, suspicious symbols |
| `disassemble_function` | ARM/ARM64/x86 disassembly via Capstone |
| `search_native_strings` | Extract and classify strings from .so sections |
| `check_native_security` | Stack canary, NX, RELRO, PIE, Fortify checks |

### Dynamic Analysis (10 tools)
| Tool | Description |
|---|---|
| `monitor_logcat` | Filtered logcat capture for a package |
| `start_activity` | Launch activities with custom intents |
| `send_broadcast` | Send broadcast intents |
| `get_runtime_info` | Process, memory, battery, network stats |
| `force_stop` | Force stop an app |
| `clear_app_data` | Clear app data |
| `install_apk` | Install APK to device |
| `uninstall_app` | Uninstall app |
| `take_screenshot` | Screenshot to local file |
| `prepare_frida_apk` | Frida gadget injection guide and commands |

## Examples

### Pull and scan an app in one shot
```
> Pull the Spotify app from my phone and run a full security scan.
```

### Hunt for hardcoded secrets
```
> Load the APK at ./target.apk and search for API keys, Firebase URLs,
  and any strings that look like credentials.
```

### Trace a suspicious API call
```
> Find all calls to Runtime.exec() in this APK. For each caller,
  decompile the method and determine if the command is hardcoded
  or comes from user input.
```

### Deep dive into a specific class
```
> List all classes in the com.example.auth package.
  Decompile the LoginManager class and check if it stores
  credentials in SharedPreferences.
```

### Analyze native code
```
> List the native libraries in this APK. Analyze libcrypto.so -
  show me the exported functions, check for stack canaries,
  and disassemble any function with "encrypt" in the name.
```

## Case Studies

apksaw has been used in real security research engagements. These case studies document the process, findings, and — importantly — the false positives.

### [Hinge (co.hinge.app)](docs/case-studies/hinge-audit.md)

Match Group's dating app handling sensitive PII (location, religion, ethnicity, sexual orientation). apksaw's scanner produced 20 findings. After manual verification, **13 were false positives**. The 7 confirmed findings included an exploitable Braze SDK key (proven to leak 160 internal user attributes via live API call), an unrestricted Google Geocoding key, and deep link UI redress (proven via ADB with screenshots).

**Key takeaway:** The scanner found the candidates. The agent — by decompiling code, tracing data flow, and testing API keys with `curl` — separated signal from noise.

### [Kimi AI (com.moonshot.kimichat)](docs/case-studies/kimi-audit.md)

Moonshot AI's chat assistant distributed globally via Google Play. apksaw's scanner flagged 36 findings including a "critical WebView exploit chain." The agent's investigation revealed the WebView flag was actually set to `false` (scanner didn't check the boolean argument), while uncovering findings the scanner missed entirely: a disabled MCP server with no authentication shipping in the production binary, a hardcoded AES key for JS decryption, and 12 third-party SDKs collecting device identifiers globally.

**Key takeaway:** The most important finding — that the "critical" WebView exploit was a false positive — came from the agent reading decompiled code, not from the scanner. Tools find method calls. Analysts read arguments.

## Architecture

```
src/apksaw/
  server.py            # FastMCP server (stdio transport)
  config.py            # Paths and constants
  session.py           # APK analysis session management
  tools/
    device.py          # ADB device interaction
    apk.py             # APK manifest and metadata
    dex.py             # DEX bytecode analysis and decompilation
    strings.py         # String extraction and pattern matching
    xrefs.py           # Cross-reference and call graph analysis
    security.py        # Automated vulnerability scanning
    certificates.py    # APK signing and certificate analysis
    native.py          # ELF/SO native library analysis
    dynamic.py         # Runtime analysis and Frida preparation
  utils/
    adb.py             # ADB command wrapper
    bootstrap.py       # Auto-download JADX and apktool
    jadx.py            # JADX decompiler wrapper
```

## Requirements

- Python 3.10+
- ADB installed and on `$PATH`
- Java 11+ (for JADX/apktool)
- A connected Android device or an APK file

JADX and apktool are **downloaded automatically** on first use to `~/.apksaw/tools/`.

## Philosophy

apksaw is built on three principles:

1. **Tools, not conclusions.** apksaw decompiles, extracts, and searches. It does not decide whether a finding is exploitable. That judgment belongs to the analyst — human or AI.

2. **Structured output for machines.** Every tool returns JSON with consistent schemas. This isn't for human readability — it's so AI agents can parse results, chain tool calls, and build multi-step investigations without brittle text parsing.

3. **Honest about limitations.** The built-in security scanner has a high false positive rate on real-world apps. The v2 scanner with taint analysis reduces this, but eliminating false positives entirely requires reading code — which is why apksaw exists as a toolkit, not a report generator.

## License

MIT
