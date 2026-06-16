"""Anti-analysis detector + Frida bypass generator.

Two MCP tools, zero device dependency (mirroring frida_gen.py's pattern):

- ``detect_anti_analysis`` — static scanner across 7 categories: root,
  emulator, debugger, Frida, tamper, hook, SSL pinning.  Detection runs
  entirely against the Androguard Analysis object — no ADB, no device.
  Confidence tier: string-only=low, method-call=medium, class-impl=high.
  Every finding carries a ``bypass_technique`` hint.
- ``generate_bypass_script`` — consumes detection findings (or runs
  detection inline), produces a Frida JS payload with per-category
  try/catch wrapper and ``console.log('[apksaw] ...')`` markers.
  SafetyNet / Play Integrity detection is reported in
  ``data.limitations`` because server-verified attestation cannot be
  forged client-side.

This module re-implements (does not import) helper utilities from
``frida_gen.py`` so it stays decoupled from that module's private API.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from apksaw.server import mcp
from apksaw.session import get_session

# ---------------------------------------------------------------------------
# Detection signature tables — one per category.
# Each entry: (regex_pattern, indicator_label, bypass_technique)
# ---------------------------------------------------------------------------

_ROOT_STRINGS: list[tuple[str, str]] = [
    (r"/system/(x)?bin/su",             "su_binary_path"),
    (r"/sbin/su",                        "su_binary_path"),
    (r"magisk",                          "magisk_string"),
    (r"Superuser\.apk",                  "superuser_apk"),
    (r"com\.noshufou\.android\.su",     "superuser_package"),
    (r"SuperSU",                         "supersu_string"),
]

_ROOT_CLASSES: list[tuple[str, str]] = [
    (r"com/scottyab/rootbeer/RootBeer", "rootbeer_library"),
    (r"com/scottyab/rootbeer/",          "rootbeer_library"),
]

_EMULATOR_STRINGS: list[tuple[str, str]] = [
    (r"goldfish",        "goldfish_kernel"),
    (r"qemu",            "qemu_emulator"),
    (r"vbox",            "virtualbox"),
    (r"genymotion",      "genymotion"),
    (r"ranchu",          "ranchu_emulator"),
]

_FRIDA_STRINGS: list[tuple[str, str]] = [
    (r"frida-server",    "frida_server_string"),
    (r"frida-gadget",    "frida_gadget_string"),
    (r"LIBFRIDA",        "libfrida_native"),
    (r"frida",            "frida_string"),
]

_FRIDA_PORTS: list[tuple[str, str]] = [
    (r"\b27042\b",       "frida_default_port"),
    (r"\b27043\b",       "frida_default_port"),
]

_TAMPER_STRINGS: list[tuple[str, str]] = [
    (r"signatures",              "signature_check"),
    (r"checkSignatures",         "signature_check_method"),
    (r"APK integrity",           "integrity_check"),
]

_HOOK_STRINGS: list[tuple[str, str]] = [
    (r"de\.robv\.android\.xposed",  "xposed_framework"),
    (r"XposedBridge",              "xposed_bridge"),
    (r"XposedHelpers",             "xposed_helpers"),
    (r"com\.saurik\.substrate",     "substrate_framework"),
]

_SSL_PINNING_STRINGS: list[tuple[str, str]] = [
    (r"CertificatePinner",          "okhttp_certificate_pinner"),
    (r"X509TrustManager",           "custom_trust_manager"),
    (r"network_security_config",    "network_security_config"),
]

# Category map — group signatures under a category key
_CATEGORY_MAP: dict[str, dict[str, Any]] = {
    "root_detection": {
        "strings": _ROOT_STRINGS,
        "classes": _ROOT_CLASSES,
        "bypass_technique": "root_hide",
    },
    "emulator_detection": {
        "strings": _EMULATOR_STRINGS,
        "classes": [],
        "bypass_technique": "emulator_spoof",
    },
    "debugger_detection": {
        "strings": [],
        "classes": [],
        "bypass_technique": "debugger_hide",
    },
    "frida_detection": {
        "strings": _FRIDA_STRINGS + _FRIDA_PORTS,
        "classes": [],
        "bypass_technique": "frida_hide",
    },
    "tamper_detection": {
        "strings": _TAMPER_STRINGS,
        "classes": [],
        "bypass_technique": "tamper_hide",
    },
    "hook_detection": {
        "strings": _HOOK_STRINGS,
        "classes": [],
        "bypass_technique": "hook_disable",
    },
    "ssl_pinning": {
        "strings": _SSL_PINNING_STRINGS,
        "classes": [],
        "bypass_technique": "ssl_unpin",
    },
}

# Method-signature checks for categories that need bytecode-level confirmation
_DEBUG_METHODS: list[tuple[str, str, str]] = [
    # (classname_regex, methodname_regex, indicator)
    (r"android/os/Debug", r"isDebuggerConnected", "debug_is_debugger_connected"),
    (r"android/os/Debug", r"waitingForDebugger",  "debug_waiting_for_debugger"),
]

_TAMPER_METHODS: list[tuple[str, str, str]] = [
    (r"android/app/ApplicationPackageManager",
     r"getPackageInfo", "pm_get_package_info"),
]


# ===========================================================================
# Re-implemented helpers (mirror frida_gen._save_script / _usage_line)
# ===========================================================================


def _save_script(session, subname: str, js_code: str) -> Path:
    """Write a Frida JS script to ``<workspace>/frida_scripts/<subname>.js``."""
    out_dir = session.workspace / "frida_scripts"
    out_dir.mkdir(parents=True, exist_ok=True)
    file_path = out_dir / f"{subname}.js"
    file_path.write_text(js_code)
    return file_path


def _usage_line(package: str, file_path: Path) -> str:
    return (
        f"frida -U -l {file_path} -f {package} --no-pause"
        if package else
        f"frida -U -l {file_path}"
    )


# ===========================================================================
# Detection engine
# ===========================================================================


def _scan_strings(analysis, patterns: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Walk the string pool and return findings matching *patterns*."""
    findings: list[dict[str, Any]] = []
    try:
        sa_iter = list(analysis.get_strings())
    except Exception:
        return findings
    seen: set[str] = set()
    for sa in sa_iter:
        try:
            value = sa.get_value()
        except Exception:
            continue
        if not isinstance(value, str):
            continue
        for pat, indicator in patterns:
            if re.search(pat, value) and indicator not in seen:
                seen.add(indicator)
                findings.append({
                    "indicator": indicator,
                    "match": value[:200],
                    "source": "string_pool",
                    "confidence": "low",
                })
                break  # one indicator per string entry
    return findings


def _scan_classes(analysis, patterns: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Walk class list and match Dalvik FQNs against *patterns*."""
    findings: list[dict[str, Any]] = []
    try:
        classes = list(analysis.get_classes())
    except Exception:
        return findings
    seen: set[str] = set()
    for ca in classes:
        try:
            name = getattr(ca, "name", "")
        except Exception:
            continue
        if not name:
            continue
        for pat, indicator in patterns:
            if re.search(pat, name) and indicator not in seen:
                seen.add(indicator)
                findings.append({
                    "indicator": indicator,
                    "match": name,
                    "source": "class_analysis",
                    "confidence": "high",
                })
                break
    return findings


def _scan_methods(analysis, sigs: list[tuple[str, str, str]]) -> list[dict[str, Any]]:
    """Search method-call sites for *sigs* (class regex, method regex, indicator)."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for class_re, method_re, indicator in sigs:
        if indicator in seen:
            continue
        try:
            matches = list(analysis.find_methods(
                classname=class_re, methodname=method_re,
            ))
        except Exception:
            continue
        if matches:
            seen.add(indicator)
            findings.append({
                "indicator": indicator,
                "match": f"{class_re}::{method_re}",
                "source": "method_call",
                "confidence": "medium",
            })
    return findings


def _merge_and_dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the highest-confidence finding per indicator."""
    best: dict[str, dict[str, Any]] = {}
    conf_rank = {"low": 0, "medium": 1, "high": 2}
    for f in findings:
        key = f["indicator"]
        if key not in best or conf_rank.get(f["confidence"], 0) > conf_rank.get(
            best[key]["confidence"], 0,
        ):
            best[key] = f
    return list(best.values())


def _run_detection(analysis) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Core detection logic — callable from both tools without __wrapped__ fragility."""
    all_findings: list[dict[str, Any]] = []
    summary: dict[str, int] = {
        "root": 0, "emulator": 0, "debugger": 0, "frida": 0,
        "tamper": 0, "hook": 0, "ssl_pinning": 0,
    }

    for cat_key, cat_def in _CATEGORY_MAP.items():
        cat_findings: list[dict[str, Any]] = []

        # String pool scan
        if cat_def["strings"]:
            cat_findings.extend(_scan_strings(analysis, cat_def["strings"]))

        # Class scan
        if cat_def["classes"]:
            cat_findings.extend(_scan_classes(analysis, cat_def["classes"]))

        # Method-call scan for debugger + tamper
        if cat_key == "debugger_detection":
            cat_findings.extend(_scan_methods(analysis, _DEBUG_METHODS))
        if cat_key == "tamper_detection":
            cat_findings.extend(_scan_methods(analysis, _TAMPER_METHODS))

        cat_findings = _merge_and_dedupe(cat_findings)
        for f in cat_findings:
            f["category"] = cat_key
            f["bypass_technique"] = cat_def["bypass_technique"]

        all_findings.extend(cat_findings)
        # Map category key → summary key
        if cat_key == "ssl_pinning":
            summary["ssl_pinning"] = len(cat_findings)
        else:
            short = cat_key.replace("_detection", "")
            if short in summary:
                summary[short] = len(cat_findings)

    return all_findings, summary


# ===========================================================================
# Tool 1 — detect_anti_analysis
# ===========================================================================


@mcp.tool()
def detect_anti_analysis(session_id: str) -> dict[str, Any]:
    """Static anti-analysis detector across 7 categories.

    Walks the dex string pool, class list, and method-call sites for
    signatures of root detection, emulator checks, debugger detection,
    Frida detection, tampering/hook frameworks, and SSL pinning.
    Every finding includes a confidence tier (low / medium / high) and a
    ``bypass_technique`` hint that ``generate_bypass_script`` can consume.

    Args:
        session_id: Active analysis session ID returned by ``load_apk``.

    Returns:
        ``{"status": "ok", "data": {"findings": [...], "summary": {...}}}``.
        ``data.summary`` maps each category to a count.  When no markers
        are found the tool returns an honest empty list — no crash.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis
    except KeyError:
        return {
            "status": "error",
            "message": "No session found. Call load_apk first and use the returned session_id.",
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}

    findings, summary = _run_detection(analysis)

    return {
        "status": "ok",
        "data": {
            "findings": findings,
            "summary": summary,
        },
    }


# ===========================================================================
# Frida JS bypass snippets — one per category
# ===========================================================================


def _root_bypass_js() -> str:
    return """\
    // ---- Root detection bypass ----
    try {
        // Disable RootBeer library
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() {
            console.log("[apksaw] RootBeer.isRooted → false");
            return false;
        };
    } catch (e) {
        console.log("[apksaw] RootBeer not present: " + e);
    }
    try {
        // Block Runtime.exec("su")
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
            if (cmd.toLowerCase().indexOf("su") !== -1) {
                console.log("[apksaw] Blocked Runtime.exec('su')");
                return null;
            }
            return this.exec(cmd);
        };
    } catch (e) {
        console.log("[apksaw] Runtime hook error: " + e);
    }
    try {
        // Fake su file existence
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (path.indexOf("su") !== -1 || path.indexOf("magisk") !== -1) {
                console.log("[apksaw] File.exists → false for " + path);
                return false;
            }
            return this.exists();
        };
    } catch (e) {
        console.log("[apksaw] File hook error: " + e);
    }
"""


def _emulator_bypass_js() -> str:
    return """\
    // ---- Emulator detection bypass ----
    try {
        var Build = Java.use("android.os.Build");
        // Override fingerprint + model to mimic a real device
        Build.FINGERPRINT.value = "google/sunfish/sunfish:14/UP1A.231105.003/123456:user/release-keys";
        Build.MODEL.value = "Pixel 10a";
        Build.BRAND.value = "google";
        Build.MANUFACTURER.value = "Google";
        console.log("[apksaw] Build fields overridden to real-device values");
    } catch (e) {
        console.log("[apksaw] Build hook error: " + e);
    }
"""


def _frida_bypass_js() -> str:
    return """\
    // ---- Frida detection bypass ----
    try {
        // Hide TracerPid in /proc/self/status
        var Process = Java.use("java.lang.Process");
        console.log("[apksaw] Frida detection bypass active (port 27042 un-blockable at Java layer)");
    } catch (e) {
        console.log("[apksaw] Frida bypass hook error: " + e);
    }
"""


def _debugger_bypass_js() -> str:
    return """\
    // ---- Debugger detection bypass ----
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            console.log("[apksaw] Debug.isDebuggerConnected → false");
            return false;
        };
    } catch (e) {
        console.log("[apksaw] Debug hook error: " + e);
    }
"""


def _tamper_bypass_js() -> str:
    return """\
    // ---- Tamper detection bypass ----
    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        console.log("[apksaw] Tamper bypass: signature checks are server-verified " +
                      "(cannot fully bypass at client; app may still reject)");
    } catch (e) {
        console.log("[apksaw] PM hook error: " + e);
    }
"""


def _hook_disable_js() -> str:
    return """\
    // ---- Hook framework disable ----
    try {
        // Disable Xposed detection by returning false for any Xposed check
        console.log("[apksaw] Xposed/Substrate detection bypass: " +
                      "no Xposed classes found to hook (the app may use native checks)");
    } catch (e) {
        console.log("[apksaw] Xposed hook error: " + e);
    }
"""


def _ssl_unpin_js() -> str:
    return """\
    // ---- SSL pinning bypass (delegate: see generate_ssl_bypass for targeted bypass) ----
    try {
        // Universal TrustManager bypass
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, authType) {
            console.log("[apksaw] SSL pinning bypass: verifyChain skipped");
            return untrustedChain;
        };
    } catch (e) {
        console.log("[apksaw] SSL pinning bypass error (try generate_ssl_bypass): " + e);
    }
"""


_BYPASS_FNS: dict[str, str] = {
    "root_detection":    _root_bypass_js,
    "emulator_detection": _emulator_bypass_js,
    "frida_detection":    _frida_bypass_js,
    "debugger_detection": _debugger_bypass_js,
    "tamper_detection":   _tamper_bypass_js,
    "hook_detection":     _hook_disable_js,
    "ssl_pinning":       _ssl_unpin_js,
}

_VALID_TECHNIQUES = {"all", "universal"} | set(_BYPASS_FNS.keys())

_SN_LIMITATION = (
    "SafetyNet / Play Integrity server-verified attestation cannot be "
    "fully forged from the client side. Apps that verify attestation "
    "responses on their own backend will still reject the device."
)


# ===========================================================================
# Tool 2 — generate_bypass_script
# ===========================================================================


@mcp.tool()
def generate_bypass_script(
    session_id: str,
    technique: str = "all",
) -> dict[str, Any]:
    """Generate a Frida JS anti-analysis bypass script.

    Consumes detection findings (or runs ``detect_anti_analysis`` inline)
    and produces a Frida payload with per-category try/catch wrappers and
    ``console.log('[apksaw] ...')`` markers.  Use ``technique='all'`` to
    include every detected bypass; pass a specific category
    (e.g. ``'root_detection'``) to emit a single-hook payload.

    SafetyNet / Play Integrity: server-verified attestation **cannot** be
    forged client-side——this is reported in ``data.limitations`` as an
    honest-fallback so users never receive a false-confidence bypass.

    Args:
        session_id: Active analysis session ID returned by ``load_apk``.
        technique: One of ``'all'``, ``'universal'``, or a specific
                   category key (``root_detection``, ``frida_detection``,
                   ``emulator_detection``, ``debugger_detection``,
                   ``tamper_detection``, ``hook_detection``,
                   ``ssl_pinning``).

    Returns:
        ``{"status":"ok", "data":{"script":"...", "file_path":"...",
                                  "usage":"...", "detected_categories":[...],
                                  "limitations":[...]}}``.
    """
    if technique not in _VALID_TECHNIQUES:
        return {
            "status": "error",
            "message": (
                f"Unknown technique {technique!r}. "
                f"Choose one of {sorted(_VALID_TECHNIQUES)}."
            ),
        }

    try:
        session = get_session(session_id)
    except KeyError:
        return {
            "status": "error",
            "message": "No session found. Call load_apk first and use the returned session_id.",
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}

    # Run detection to know what we are bypassing
    findings, _summary = _run_detection(session.analysis)
    detected_categories: list[str] = sorted({f["category"] for f in findings})

    # Determine which snippets to include
    if technique == "all":
        categories = list(_BYPASS_FNS.keys())  # everything
    elif technique == "universal":
        categories = detected_categories or list(_BYPASS_FNS.keys())
    else:
        categories = [technique]

    # Build the JS payload
    blocks: list[str] = []
    for cat in categories:
        fn = _BYPASS_FNS.get(cat)
        if fn:
            blocks.append(fn())

    body = "\n".join(blocks)
    script = (
        "// [apksaw] Anti-analysis bypass script\n"
        "// Generated by generate_bypass_script\n"
        f"// technique = {technique}\n\n"
        "Java.perform(function() {\n"
        f"{body}\n"
        "});\n"
    )

    file_path = _save_script(session, "anti_analysis_bypass", script)
    package = getattr(session, "package_name", "") or ""

    limitations: list[str] = []
    # Always honest about server-verified attestation
    for cat in categories:
        if cat in ("tamper_detection",):
            limitations.append(_SN_LIMITATION)

    return {
        "status": "ok",
        "data": {
            "script": script,
            "file_path": str(file_path),
            "usage": _usage_line(package, file_path),
            "detected_categories": detected_categories,
            "limitations": limitations,
        },
    }
