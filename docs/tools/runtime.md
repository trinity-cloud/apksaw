# Runtime Execution Tools

Tools that actually **execute** dynamic analysis on a non-rooted device — closing
the gap between static detection (which finds vulnerabilities) and live evidence
capture (which proves exploitation). These are the execute counterparts to the
script-*generator* tools in `frida_gen` and the plan-only `prepare_frida_apk` in
the dynamic module.

All three tools follow the session-first pattern (`session_id` as the first
argument) and return structured `{"status": ..., "data": ...}` dicts.

## Target posture

apksaw's runtime tools are designed for a **non-rooted** target (e.g. a Pixel 10a
with USB debugging enabled). Because `frida-server` cannot be pushed to a
non-rooted device, the workflow is:

1. Inject `frida-gadget` into the APK by repackaging it (`repackage_with_gadget`).
2. Install the gadget-injected APK on the device.
3. Attach the Frida client over an `adb forward`'d port (`run_frida_script` /
   `capture_runtime_secrets`).

The gadget listens in `listen` mode on port 27042 and waits for a Frida client
to attach — so no root, no `frida-server`, and no persistent background process
is required.

## `repackage_with_gadget`

Inject `frida-gadget`, patch smali, repackage, sign, and install — the full
gadget-injection pipeline in one call. This is the **execute** counterpart to
`prepare_frida_apk` (which only describes the process without running it).

```
# Dry run — returns the plan and tool-check, no side effects
repackage_with_gadget(session_id="abc123")
→ {
    "status": "requires_consent",
    "consent_required": true,
    "message": "Set confirm=True to actually repackage and install.",
    "data": {
      "apk_path": "/path/to/app.apk",
      "package_name": "com.example.app",
      "abis": ["arm64-v8a"],
      "tool_check": {
        "apktool": {"available": true, "command": "apktool"},
        "zipalign": {"available": true, "path": "/usr/bin/zipalign"},
        "apksigner": {"available": true, "path": "/usr/bin/apksigner"},
        "frida_gadget_so": {"available": false, "path": "...", "note": "Download from ..."},
        "frida_tools_python": {"available": true, "version": "16.x"}
      },
      "steps": ["apktool d → decompile", "copy libfrida-gadget.so → lib/<abi>/", ...]
    }
  }

# Confirm — runs the full pipeline
repackage_with_gadget(session_id="abc123", confirm=True)
→ {
    "status": "ok",
    "data": {
      "out_apk": "/.../com.example.app_frida_signed.apk",
      "abis_installed": ["arm64-v8a"],
      "smali_patch": {"patched_file": "...", "method_kind": "clinit"},
      "execution_log": ["[1/8] Decompiling...", ...],
      "next_action": "Launch the app once on device ..."
    }
  }
```

**Safety:** `confirm=True` modifies the APK, replaces its signature, and installs
it on the device. Only run against apps you are authorised to analyse. The
repackaged APK must be uninstalled before the original can be reinstalled.

**Pipeline (8 steps):** apktool decode → copy gadget `.so` per ABI → write gadget
config → patch smali (`System.loadLibrary("frida-gadget")`) → apktool build →
zipalign → apksigner sign → adb install.

**Smali patching strategy:** the tool tries, in order: (1) inject into an existing
`<clinit>`; (2) synthesise a new `<clinit>` after the last `.super` line; (3)
inject into `onCreate`. It searches `smali/`, `smali_classes2/`, `smali_classes3/`,
`smali_classes4/` (multidex-aware) and backs up the original to `*.apksaw.bak`.

**Prerequisites:** `apktool`, `zipalign`, `apksigner` in PATH; a `libfrida-gadget.so`
under `~/.apksaw/tools/frida-gadget/` (download from the
[Frida releases page](https://github.com/frida/frida/releases)); `keytool` on PATH
(a debug keystore is auto-created if absent); a connected ADB device.

## `run_frida_script`

Execute an arbitrary Frida JavaScript hook on the gadget-injected target and
return captured `send()` messages. Use this to drive a script you generated with
the `generate_*` tools (e.g. `generate_ssl_bypass`).

```
run_frida_script(
    session_id="abc123",
    script="/path/to/ssl_bypass.js",   # .js file path OR inline JS string
    target="spawn",                     # "spawn" (launch) or "attach" (already running)
    duration_s=60,                      # clamped to [1, 600]
    redact_secrets=True                 # mask Bearer/JWT/Google keys in output
)
→ {
    "status": "ok",
    "data": {
      "messages": [{"payload": {...}, "ts": 1700000000.0}, ...],
      "exceptions": [],
      "duration_s": 60,
      "script_path": "/.../user_inline.js",
      "message_count": 12
    }
  }
```

**Script resolution:** if `script` is a path to an existing `.js` file it is read
verbatim; otherwise it is treated as inline JS and written to the session
workspace as `frida_scripts/user_inline.js` for traceability.

The tool launches the app (for `spawn`), opens an `adb forward` from a free host
port to the gadget's 27042, attaches the Frida client, loads the script, and
collects `send`/`error` messages for `duration_s` seconds before detaching and
tearing down the forward.

## `capture_runtime_secrets`

The **one-call** answer to the "I found the vulnerability statically, now show me
the live secret" gap (e.g. the Hinge case study where the scanner found an empty
`CertificatePinner` but couldn't capture the live Bearer token). Composes four
Java-hook families into a single Frida script, launches the app, and returns all
intercepted secrets as structured findings.

```
capture_runtime_secrets(
    session_id="abc123",
    duration_s=45,
    capture_bearers=True,      # OkHttp Request$Builder.build + HttpURLConnection
    capture_keys=True,         # SecretKeySpec + IvParameterSpec + Cipher + KeyStore
    capture_webview=True,      # WebView.addJavascriptInterface / loadUrl / evaluateJavascript
    capture_identifiers=True,  # TelephonyManager + Settings$Secure (android_id)
    drive_action="launcher",   # "launcher" | "existing" | "am ..." literal
    redact_secrets=True
)
→ {
    "status": "ok",
    "data": {
      "secrets": [
        {"type": "bearer", "endpoint": "https://api.example.com/v1/me", "value": "Bearer eyJ...[REDACTED]"},
        {"type": "crypto_key", "algorithm": "AES", "key_hex": "deadbeef...", "length": 32},
        {"type": "keystore_password", "value": "***"},
        {"type": "device_identifier", "kind": "imei", "value": "..."}
      ],
      "webview": [
        {"type": "webview_url", "url": "https://app.example.com/dashboard"},
        {"type": "js_bridge", "name": "AndroidBridge", "class_name": "com.example.Bridge"}
      ],
      "endpoints": ["https://api.example.com/v1/me", "https://app.example.com/dashboard"],
      "summary": {"bearer": 1, "crypto_key": 1, "keystore_password": 1, "webview_url": 1, "js_bridge": 1},
      "script_path": "/.../capture_runtime_secrets.js",
      "duration_s": 45
    }
  }
```

**Finding types** (`_classify_payload`):

| `type`              | Source hook                                            |
|---------------------|--------------------------------------------------------|
| `bearer`            | OkHttp `Request$Builder.build` / `HttpURLConnection`   |
| `cookie`            | same as bearer, header name contains "cookie"          |
| `api_key_header`    | same as bearer, header name contains "api" + "key"     |
| `crypto_key`        | `SecretKeySpec`, `Cipher.init`                         |
| `crypto_iv`         | `IvParameterSpec`                                      |
| `keystore_password` | `KeyStore.load(InputStream, char[])`                   |
| `webview_url`       | `WebView.loadUrl`                                      |
| `webview_js`        | `WebView.evaluateJavascript`                           |
| `js_bridge`         | `WebView.addJavascriptInterface`                       |
| `device_identifier` | `TelephonyManager.getDeviceId/getSubscriberId`, `Settings$Secure` |
| `unknown`           | anything else                                          |

**Redaction:** with `redact_secrets=True` (default), `Bearer`/JWT/Google API key
values are masked in the returned payload so secrets never land verbatim in chat
logs. Set to `False` only when you need the raw value as evidence.

## Relationship to the other modules

| Module       | Role                                                        |
|--------------|-------------------------------------------------------------|
| `frida_gen`  | **Generates** Frida scripts as `.js` text files (static)    |
| `dynamic`    | **Describes** the gadget-injection workflow (plan only)     |
| **`runtime`**| **Executes** — injects, attaches, and returns live evidence |

The typical end-to-end flow is: static scan → `generate_ssl_bypass` (or
`capture_runtime_secrets`) → `repackage_with_gadget(confirm=True)` →
`run_frida_script` / `capture_runtime_secrets`.
