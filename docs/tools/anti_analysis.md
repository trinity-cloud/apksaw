# Anti-Analysis Detector + Bypass Generator

Two static tools that scan an APK for anti-reverse-engineering defences
and produce targeted Frida JS payloads to neutralise them.  Both tools
run **entirely against the Androguard Analysis object** — no device, no
ADB, no consent gate required.

## Target posture

Static pre-execution intelligence.  Before you put the APK on a device,
these tools tell you what protections the app deploys and give you a
Frida script that can disable them when you do go live with `runtime.py`.

Seven detection categories, each backed by a signature table of regexes
run against the dex string pool, class list, and method-call sites:

| Category               | What it detects                                                     |
|------------------------|---------------------------------------------------------------------|
| `root_detection`       | `su` binaries, Magisk, Superuser.apk, RootBeer library              |
| `emulator_detection`   | goldfish/qemu/vbox/genymotion/ranchu kernel strings                 |
| `debugger_detection`   | `Debug.isDebuggerConnected()` / `waitingForDebugger()` call-sites   |
| `frida_detection`      | `frida-server`, `frida-gadget`, port 27042/27043 strings            |
| `tamper_detection`     | signature checks (`getPackageInfo`, `checkSignatures`)              |
| `hook_detection`       | Xposed / Substrate framework references                             |
| `ssl_pinning`          | OkHttp `CertificatePinner`, `X509TrustManager`, network config      |

Every finding carries a **confidence tier** (low / medium / high) and a
`bypass_technique` hint that `generate_bypass_script` consumes.

## Tool inventory

| Tool                       | Args                             | Returns                                        |
|----------------------------|----------------------------------|------------------------------------------------|
| `detect_anti_analysis`     | `session_id`                     | `{findings: [...], summary: {root:N, ...}}`     |
| `generate_bypass_script`   | `session_id`, `technique="all"`  | `{script, file_path, usage, detected_categories, limitations}` |

### detect_anti_analysis

Walks the dex string pool, class list, and method-call sites for
defence signatures.  When no markers are found the tool returns an
**honest empty list** — no crash, no false positive.

```
detect_anti_analysis(session_id="abc123")
→ {
    "status": "ok",
    "data": {
      "findings": [
        {"category": "root_detection",
         "indicator": "rootbeer_library",
         "match": "Lcom/scottyab/rootbeer/RootBeer;",
         "source": "class_analysis",
         "confidence": "high",
         "bypass_technique": "root_hide"}
      ],
      "summary": {"root": 1, "emulator": 0, "debugger": 0,
                  "frida": 0, "tamper": 0, "hook": 0, "ssl_pinning": 0}
    }
  }
```

### generate_bypass_script

Consumes the detection findings and emits a Frida JS payload with
per-category `try { ... } catch (e) { ... }` wrappers and
`console.log('[apksaw] ...')` markers.  Written to
`<workspace>/frida_scripts/anti_analysis_bypass.js`.

The `technique` parameter selects the bypass scope:

| Value               | Behaviour                                          |
|---------------------|----------------------------------------------------|
| `"all"` (default)   | Include every category, regardless of detection    |
| `"universal"`       | Include only detected categories (or all if none)  |
| `"root_detection"`  | Single-category root bypass only                   |
| `"emulator_detection"` | Single-category emulator spoof only             |
| …                   | (same for `debugger`, `frida`, `tamper`, `hook`, `ssl_pinning`) |

```
generate_bypass_script(session_id="abc123", technique="all")
→ {
    "status": "ok",
    "data": {
      "script": "Java.perform(function() { ... });",
      "file_path": "/tmp/apksaw_ws/frida_scripts/anti_analysis_bypass.js",
      "usage": "frida -U -l ... -f com.example --no-pause",
      "detected_categories": ["root_detection"],
      "limitations": []
    }
  }
```

## Confidence tiering

| Tier    | Trigger                                                    |
|---------|------------------------------------------------------------|
| `low`   | String-pool match only (e.g. "su" found in a URL)          |
| `medium`| Method-call site found (e.g. `Debug.isDebuggerConnected`)  |
| `high`  | Full detector class imported (e.g. `RootBeer` in dex)      |

When the same indicator appears from multiple sources, the **highest**
confidence wins.

## Frida JS snippets — what each bypass does

| Category            | Hook targets                                                    |
|---------------------|-----------------------------------------------------------------|
| `root_detection`    | `RootBeer.isRooted()` → `false`, `Runtime.exec("su")` → `null`, `File.exists()` for su/magisk paths → `false` |
| `emulator_detection`| `Build.FINGERPRINT`, `Build.MODEL`, `Build.BRAND`, `Build.MANUFACTURER` → Pixel 10a real-device values |
| `frida_detection`   | `Process` class hook (port 27042/27043 is un-blockable at Java layer; documented limitation) |
| `debugger_detection`| `Debug.isDebuggerConnected()` → `false`                        |
| `tamper_detection`  | `ApplicationPackageManager` hook (honest: server-verified signatures cannot be fully bypassed) |
| `hook_detection`    | Xposed / Substrate disable (note: apps may use native checks)   |
| `ssl_pinning`       | Conscrypt `TrustManagerImpl.verifyChain()` → no-op; for targeted OkHttp bypass use `generate_ssl_bypass` |

## SafetyNet / Play Integrity — honest fallback

Server-verified attestation (SafetyNet, Play Integrity API) **cannot** be
forged from the client side.  When `generate_bypass_script` includes the
`tamper_detection` category, a limitation entry is added to
`data.limitations` explaining this constraint.  Users never receive a
false-confidence bypass.

## Integration with other tools

* After running `detect_anti_analysis`, feed the `bypass_technique` hints
  into `generate_bypass_script` for a targeted payload.
* For SSL pinning, the module re-implements a generic Conscrypt bypass;
  for OkHttp-specific pinning use `frida_gen.generate_ssl_bypass` which
  performs deeper `CertificatePinner` class inspection.
* Execute the generated script with `runtime.run_frida_script` when you
  are ready to go live on a device.
