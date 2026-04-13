# apksaw

**apksaw** is an MCP (Model Context Protocol) server that exposes Android APK decompilation and security analysis as structured tools. It lets an LLM-powered agent analyze Android applications using the same workflow a human security researcher would — without writing scripts or memorizing tool flags.

## Key Features

- **48 built-in tools** covering device interaction, APK inspection, Dalvik decompilation, string extraction, cross-reference analysis, security scanning, certificate verification, native library analysis, and dynamic instrumentation.
- **Session model** — load an APK once, reference it by `session_id` across all subsequent tools.
- **Persistent sessions** — sessions survive server restarts via SQLite; Androguard objects reload lazily on demand.
- **Plugin system** — extend apksaw with custom tools by publishing a Python package that registers via entry points.
- **Backends** — [Androguard](https://github.com/androguard/androguard) for Dalvik analysis, [LIEF](https://lief.re/) for native ELF parsing, [Capstone](https://www.capstone-engine.org/) for disassembly.

## Quick Example

```
# In your MCP client (e.g., Claude Desktop)

list_packages()
# → ["com.example.app", "com.bank.mobile", ...]

load_apk("/path/to/app.apk")
# → {"session_id": "a1b2c3d4e5f6", "package_name": "com.example.app", ...}

get_manifest(session_id="a1b2c3d4e5f6")
# → full AndroidManifest.xml as structured dict

scan_all(session_id="a1b2c3d4e5f6")
# → consolidated security findings across all scanners
```

## Use Cases

- Automated security audits of third-party Android apps
- Bug bounty reconnaissance
- Malware triage and IOC extraction
- CI/CD integration for mobile app security gates
