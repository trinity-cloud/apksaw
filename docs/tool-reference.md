# Tool Reference

apksaw exposes **113 MCP tools**. You rarely call them by name — your coding agent picks the right ones from your natural-language request. This page is the full inventory for when you want to know exactly what's available, or wire a tool into a script.

Tools fall into two categories:

- **Automation tools** *do the work* — one call, structured conclusion (scan, fuzz, diff, generate a PoC).
- **Infrastructure tools** *give the agent hands* — structured data the agent reads and reasons about (decompiled Java, cross-references, parsed manifests).

For the module-by-module source layout, see [Architecture](architecture.md).

## Automation — tools that do the work

These tools produce results, not just data. One tool call, structured output.

| Tool | What it does |
|---|---|
| `fuzz_exported_components` | Tests every exported activity/receiver/service with malformed intents (SQLi, path traversal, XSS, null bytes, oversized strings). Monitors logcat for crashes and ANRs. |
| `fuzz_deep_links` | 13 malformed URI variants per registered deep link scheme. Automated crash detection. |
| `fuzz_content_providers` | SQL injection and path traversal against exported ContentProviders. Detects data exposure. |
| `fuzz_exported_components_v2` | Builds payload suites from the extras each exported component actually reads via bytecode analysis. Dry-run by default, ADB execution behind `confirm=True`. |
| `fuzz_deep_links_v2` | Builds URI suites from manifest `<data>` filters plus harvested `getQueryParameter` keys. |
| `automine_blind_sqli` | Mines ContentProvider schemas and emits boolean, UNION, error, and SQLite time-oracle payloads using app-specific table/column names. |
| `scan_all` | Runs 5 security scanners (manifest, crypto, network, injection, storage) and returns a combined severity report. |
| `scan_all_v2` | Enhanced scanners with taint analysis — checks argument values, verifies TrustManager bodies, traces reachability from exported components. Adds confidence levels. |
| `scan_yara` | 50 built-in YARA rules across 4 categories (credentials, crypto, obfuscation, suspicious behavior). |
| `extract_secrets` | Pattern-matched extraction of API keys, tokens, Firebase URLs, PEM keys, Bearer tokens, high-entropy strings. |
| `extract_api_endpoints` | Finds REST URLs, Retrofit annotations, OkHttp base URLs. Maps the full API surface. |
| `analyze_security_patches` | Compares two APK versions and identifies security-relevant fixes: unexported components, added pinning, removed dangerous APIs. |
| `find_vulnerability_window` | Reverse-engineers what vulnerability was patched. Generates PoC commands for the old version. |
| `poc_old_version` | Replays patch-diff PoCs against the old APK, optionally executing them on device with logcat and screenshot evidence. |
| `generate_component_poc` | Generates and optionally runs exported activity/service/receiver probes with realistic extras. |
| `generate_webview_exploit` | Builds JavaScript and Frida payloads for discovered `@JavascriptInterface` bridges. |
| `generate_provider_poc` | Builds SQL injection and path traversal probes for exported ContentProviders. |
| `generate_deeplink_poc` | Builds deep-link payload suites keyed to manifest filters and query-parameter usage. |
| `generate_intent_redirection_poc` | Finds caller-controlled `startActivity` sinks and builds LaunchAnyWhere-style probes. |
| `repackage_with_gadget` | Injects Frida gadget into an APK for non-rooted runtime analysis, with dry-run planning and explicit confirmation. |
| `run_frida_script` | Attaches to a gadget-instrumented app and returns structured Frida message evidence. |
| `capture_runtime_secrets` | One-call runtime capture for Bearer tokens, crypto keys, WebView bridges, and related secrets. |
| `extract_protobuf_schemas` | Reconstructs `.proto` definitions from generated Java classes. Maps all gRPC services and RPC methods. |
| `generate_ssl_bypass` | Analyzes the specific pinning implementation and generates a targeted Frida bypass script. |
| `generate_token_dumper` | Finds auth interceptors in the APK and generates Frida hooks to capture Bearer tokens. |
| `generate_crypto_hooks` | Generates Frida hooks for all Cipher, SecretKeySpec, and MessageDigest operations. |
| `detect_anti_analysis` | Detects root, emulator, debugger, Frida, tamper, hook-detection, and SSL-pinning defenses with confidence tiers. |
| `generate_bypass_script` | Generates targeted Frida bypass scripts for detected anti-analysis categories. |
| `detect_obfuscation` | Analyzes class naming patterns to identify obfuscator (R8, ProGuard, DexGuard) and confidence level. |
| `check_native_security` | Checks stack canary, NX, RELRO, PIE, Fortify on native `.so` libraries. |
| `find_rop_gadgets` | Capstone sweep of a native lib's `.text` for ROP gadget candidates, classified by mnemonic shape. Candidate generator (reliable on arm64/x86; best-effort on arm32), not a full ROPgadget/ropper replacement. |
| `generate_jni_hook` | Demangles `Java_*` JNI exports from a `.so` and writes a Frida JS script that hooks each one, logging args/returns via `send()`. |
| `execute_native_hook` | Runs a generated Frida hook script against the target app and captures `send()` payloads. Dry-run by default; live execution behind `confirm=True` + ADB device + Frida. |

## Secret verification
| Tool | What it does |
|---|---|
| `probe_secret` | Dispatcher that routes a discovered secret to the appropriate per-type probe. |
| `probe_google_api_key` | Classifies a Google API key as valid/invalid/restricted via a passive Geocoding API call. |
| `probe_firebase_rtdb` | Classifies a Firebase RTDB as world-readable/auth-required/not-found via passive shallow query. |
| `probe_firebase_storage` | Classifies a Firebase Storage bucket; active mode (confirm-gated) lists up to N objects. |
| `probe_aws_key` | Verifies an AWS key via sts:GetCallerIdentity; optional botocore; active enumerates policies. |

## WebView / App Links
| Tool | What it does |
|---|---|
| `scan_webview_surface` | Scans WebSettings setters (setAllowFileAccess, setJavaScriptEnabled, etc.) — resolves boolean args, drops proven-safe sites. |
| `verify_app_links` | Verifies Android App Links posture: fetches `/.well-known/assetlinks.json` per autoVerify host, classifies ok/mismatch/missing/unreachable. |

## PoC generators (Tier 2)
| Tool | What it does |
|---|---|
| `generate_pending_intent_poc` | Detects mutable PendingIntent + implicit Intent sites (FLAG_MUTABLE via const/high16 resolution) and generates hijack PoC. |
| `generate_task_hijack_poc` | Scans manifest for singleTask/singleInstance/non-default taskAffinity and emits StrandHogg-class attacker snippet. |
| `generate_uri_grant_poc` | Detects content:// URI pass-through / grant-flag sites and emits coercion intent PoC. |

## Native (Tier 2)
| Tool | What it does |
|---|---|
| `map_jni_registrations` | Recovers dynamically-registered JNI methods (RegisterNatives in JNI_OnLoad) via Capstone + .rodata scan. Feeds generate_jni_hook. |

## Infrastructure — tools that give the agent hands

These tools provide structured data that the agent interprets and reasons about.

**Device interaction:**
`device_info` | `list_packages` | `pull_apk` | `app_info` | `screenshot` | `install_apk` | `uninstall_app` | `force_stop` | `clear_app_data` | `monitor_logcat` | `start_activity` | `send_broadcast` | `get_runtime_info` | `take_screenshot`

**APK analysis:**
`load_apk` | `get_manifest` | `get_permissions` | `get_components` | `list_files` | `get_signing_info` | `check_certificate_security`

**Code navigation:**
`list_classes` | `get_class_info` | `list_methods` | `decompile_method` | `decompile_class` | `decompile_apk_full` | `search_strings` | `extract_urls` | `extract_interesting_strings` | `search_code`

**Cross-references:**
`get_xrefs_to` | `get_xrefs_from` | `get_call_graph` | `find_method_usage` | `find_api_calls` | `export_call_graph`

**Diffing:**
`diff_apks` | `diff_manifest` | `diff_classes` | `diff_strings` | `diff_security` | `analyze_security_patches` | `find_patched_methods` | `find_vulnerability_window`

**Native analysis:**
`list_native_libs` | `analyze_native_lib` | `disassemble_function` | `search_native_strings` | `check_native_security` | `find_rop_gadgets` | `generate_jni_hook` | `execute_native_hook`

**Runtime execution:**
`repackage_with_gadget` | `run_frida_script` | `capture_runtime_secrets` | `prepare_frida_apk`

**PoC execution:**
`poc_old_version` | `generate_component_poc` | `generate_webview_exploit` | `generate_provider_poc` | `generate_deeplink_poc` | `generate_intent_redirection_poc`

**Fuzzing:**
`fuzz_exported_components` | `fuzz_deep_links` | `fuzz_content_providers` | `fuzz_exported_components_v2` | `fuzz_deep_links_v2` | `automine_blind_sqli`

**Anti-analysis:**
`detect_anti_analysis` | `generate_bypass_script`

**Multi-DEX:**
`list_dex_files` | `analyze_dex_boundaries` | `get_dex_class_map`

**Mapping:**
`load_mapping` | `deobfuscate_name` | `detect_obfuscation`

**Other:**
`extract_protobuf_schemas` | `find_grpc_services` | `export_proto_file` | `extract_api_endpoints` | `find_auth_interceptors` | `generate_frida_hook` | `generate_ssl_bypass` | `generate_token_dumper` | `generate_crypto_hooks` | `scan_yara` | `list_yara_rules` | `list_plugins` | Individual scanners (`scan_manifest_security` | `scan_crypto_issues` | `scan_network_security` | `scan_code_injection` | `scan_data_storage` | `scan_crypto_issues_v2` | `scan_network_security_v2` | `scan_code_injection_v2` | `scan_all_v2`)
