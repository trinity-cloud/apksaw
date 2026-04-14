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
  +--> YARA ------------> Pattern-based malware/secret detection
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

### DEX / Decompilation (6 tools)
| Tool | Description |
|---|---|
| `list_classes` | Browse classes with filtering and pagination |
| `get_class_info` | Fields, methods, superclass, interfaces |
| `list_methods` | Search methods by class or name pattern |
| `decompile_method` | Decompile a method to Java (Androguard or JADX backend) |
| `decompile_class` | Decompile an entire class |
| `decompile_apk_full` | Run JADX on the full APK (cached for instant subsequent lookups) |

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

### Security Scanning (10 tools)
| Tool | Description |
|---|---|
| `scan_manifest_security` | Debuggable, backup, exported components, cleartext |
| `scan_crypto_issues` | ECB mode, hardcoded keys, weak hashes, static IVs |
| `scan_network_security` | HTTP URLs, TrustManager bypasses, missing pinning |
| `scan_code_injection` | WebView JS interfaces, SQL injection, Runtime.exec |
| `scan_data_storage` | World-readable files, external storage, logcat leaks |
| `scan_all` | Run all scanners, combined report with severity counts |
| `scan_crypto_issues_v2` | Enhanced: argument inspection + confidence levels |
| `scan_network_security_v2` | Enhanced: TrustManager body verification |
| `scan_code_injection_v2` | Enhanced: reachability from exported components |
| `scan_all_v2` | Run all v2 scanners with confidence breakdown |

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

### APK Diffing (5 tools)
| Tool | Description |
|---|---|
| `diff_apks` | High-level comparison of two APK versions |
| `diff_manifest` | Permission, component, and attribute changes |
| `diff_classes` | Added/removed/modified/renamed classes (obfuscation-resistant) |
| `diff_strings` | New URLs, endpoints, and secrets between versions |
| `diff_security` | Security posture changes (new vulns, fixes) |

### Frida Script Generator (4 tools)
| Tool | Description |
|---|---|
| `generate_frida_hook` | Generate targeted hooks (log args, return, trace) |
| `generate_ssl_bypass` | SSL pinning bypass for the specific app's implementation |
| `generate_token_dumper` | Hook auth interceptors to capture Bearer tokens |
| `generate_crypto_hooks` | Hook all crypto operations (Cipher, SecretKeySpec, MessageDigest) |

### API Endpoint Discovery (2 tools)
| Tool | Description |
|---|---|
| `extract_api_endpoints` | Find REST URLs, Retrofit annotations, OkHttp base URLs |
| `find_auth_interceptors` | Find OkHttp interceptors that add auth headers |

### YARA Scanning (2 tools)
| Tool | Description |
|---|---|
| `scan_yara` | Scan APK with 50 built-in rules (credentials, crypto, obfuscation, suspicious) |
| `list_yara_rules` | List all available YARA rule sets |

### Call Graph Visualization (1 tool)
| Tool | Description |
|---|---|
| `export_call_graph` | Export call graphs as Mermaid, DOT, or JSON with security-sensitive coloring |

### ProGuard / R8 Mapping (3 tools)
| Tool | Description |
|---|---|
| `load_mapping` | Load a ProGuard/R8 mapping.txt for deobfuscation |
| `deobfuscate_name` | Look up obfuscated class or method names |
| `detect_obfuscation` | Detect obfuscator type and level (R8, ProGuard, DexGuard) |

### Multi-DEX Analysis (3 tools)
| Tool | Description |
|---|---|
| `list_dex_files` | List all DEX files with class/method counts |
| `analyze_dex_boundaries` | Cross-DEX references, isolated DEX detection |
| `get_dex_class_map` | Which classes live in which DEX file |

### Plugin System (1 tool)
| Tool | Description |
|---|---|
| `list_plugins` | List loaded apksaw plugins and their status |

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

### Compare two versions
```
> Load both v1.0 and v2.0 of the app. Diff the manifests, show me
  any new permissions, and check if they removed certificate pinning.
```

### Generate Frida hooks
```
> Generate a Frida script that hooks all crypto operations in this app
  and logs the keys, IVs, and plaintext.
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
  server.py              # FastMCP server (stdio transport)
  config.py              # Paths and constants
  session.py             # APK session management (in-memory + SQLite persistence)
  db.py                  # SQLite persistence layer
  plugins.py             # Plugin discovery and loading
  tools/
    device.py            # ADB device interaction
    apk.py               # APK manifest and metadata
    dex.py               # DEX analysis and decompilation (Androguard + JADX)
    strings.py           # String extraction and pattern matching
    xrefs.py             # Cross-reference and call graph analysis
    security.py          # Automated vulnerability scanning (v1)
    security_v2.py       # Enhanced scanning with taint-lite analysis
    certificates.py      # APK signing and certificate analysis
    native.py            # ELF/SO native library analysis
    dynamic.py           # Runtime analysis and Frida preparation
    diff.py              # APK version comparison
    frida_gen.py         # Frida script generation
    endpoints.py         # API endpoint discovery
    yara_scan.py         # YARA rule scanning
    visualization.py     # Call graph export (Mermaid, DOT, JSON)
    mapping.py           # ProGuard/R8 mapping support
    multidex.py          # Multi-DEX analysis
  utils/
    adb.py               # ADB command wrapper
    common.py            # Shared helpers (name conversion)
    taint_lite.py        # Lightweight taint analysis for scanner v2
    bootstrap.py         # Auto-download JADX and apktool
    jadx.py              # JADX decompiler wrapper
  rules/
    credentials.yar      # API key and secret detection (14 rules)
    crypto.yar           # Cryptographic weakness detection (10 rules)
    obfuscation.yar      # Packer and obfuscator detection (11 rules)
    suspicious.yar       # Suspicious behavior detection (15 rules)
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
