"""Intent fuzzer tools for Android APK security testing.

Sends malformed intents to exported components and monitors logcat for
crashes, ANRs, and uncaught exceptions.  Three entry-points are exposed:

- ``fuzz_exported_components`` — fuzz every exported activity/service/receiver
- ``fuzz_deep_links``          — fuzz all registered URI schemes
- ``fuzz_content_providers``   — test exported providers for SQL injection /
                                 path traversal via adb shell content commands
"""

from __future__ import annotations

import re
import time
from typing import Any

from apksaw.server import mcp
from apksaw.session import get_session
from apksaw.utils.adb import check_device_connected, run_adb

# Android manifest XML namespace
_ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Logcat crash / error patterns we watch for
_CRASH_PATTERNS: list[tuple[str, str]] = [
    (r"FATAL EXCEPTION",                        "crash"),
    (r"Process.*has died",                      "crash"),
    (r"Force finishing activity",               "crash"),
    (r"java\.lang\.NullPointerException",       "exception"),
    (r"java\.lang\.ClassCastException",         "exception"),
    (r"java\.lang\.IllegalArgumentException",   "exception"),
    (r"java\.lang\.IllegalStateException",      "exception"),
    (r"java\.lang\.RuntimeException",           "exception"),
    (r"java\.lang\.SecurityException",          "security_exception"),
    (r"android\.os\.NetworkOnMainThreadException", "exception"),
    (r"ANR in ",                                "anr"),
    (r"Application Not Responding",             "anr"),
]

# Severity map: result type -> severity label
_SEVERITY_MAP: dict[str, str] = {
    "crash":              "critical",
    "anr":                "high",
    "exception":          "high",
    "security_exception": "medium",
    "no_crash":           "info",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _attr(element, name: str, default: Any = None) -> Any:
    """Get an android: namespaced attribute from an lxml element."""
    return element.get(f"{{{_ANDROID_NS}}}{name}", default)


def _require_device() -> None:
    """Raise RuntimeError if no ADB device is connected."""
    if not check_device_connected():
        raise RuntimeError(
            "No ADB device connected. "
            "Connect a device, enable USB debugging, and authorise this computer."
        )


def _clear_logcat() -> None:
    """Clear the on-device logcat ring buffer."""
    try:
        run_adb("logcat", "-c", timeout=10)
    except RuntimeError:
        pass  # Non-fatal — best effort


def _capture_logcat(lines: int = 500) -> str:
    """Dump recent logcat lines and return raw text."""
    try:
        return run_adb("shell", "logcat", "-d", "-t", str(lines), timeout=20)
    except RuntimeError:
        return ""


def _check_logcat_for_crash(logcat_text: str, package_name: str) -> tuple[str, str]:
    """Scan logcat text for crash indicators related to *package_name*.

    Returns a (result_type, crash_snippet) tuple where result_type is one of
    ``"crash"``, ``"anr"``, ``"exception"``, ``"security_exception"``, or
    ``"no_crash"``.  The snippet is the matched line (up to 500 chars).
    """
    # Only look at lines that mention the package or are crash-level
    relevant_lines: list[str] = []
    for line in logcat_text.splitlines():
        if package_name in line or re.search(
            r"FATAL EXCEPTION|ANR in |Force finishing", line
        ):
            relevant_lines.append(line)

    combined = "\n".join(relevant_lines)

    for pattern, result_type in _CRASH_PATTERNS:
        m = re.search(pattern, combined, re.IGNORECASE)
        if m:
            # Return the line containing the match as the snippet
            for line in relevant_lines:
                if re.search(pattern, line, re.IGNORECASE):
                    return result_type, line[:500]
            return result_type, m.group(0)[:500]

    return "no_crash", ""


def _take_screenshot_b64(label: str) -> dict | None:
    """Capture a screenshot and return a summary dict (no base64 in results)."""
    try:
        run_adb("shell", "screencap", "-p", f"/sdcard/fuzz_{label}.png", timeout=15)
        return {"saved_on_device": f"/sdcard/fuzz_{label}.png"}
    except RuntimeError:
        return None


def _parse_manifest_components(session_id: str) -> dict:
    """Extract exported activities, services, receivers, and providers from the APK.

    Returns a dict with keys ``"activities"``, ``"services"``,
    ``"receivers"``, ``"providers"`` — each a list of component dicts
    from :func:`_parse_component`.
    """
    session = get_session(session_id)
    apk = session.apk
    manifest_elem = apk.get_android_manifest_xml()

    target_sdk_raw = apk.get_target_sdk_version()
    try:
        target_sdk = int(target_sdk_raw) if target_sdk_raw else 0
    except (ValueError, TypeError):
        target_sdk = 0

    app_elem = manifest_elem.find("application")
    if app_elem is None:
        return {"activities": [], "services": [], "receivers": [], "providers": []}

    def parse_tag(tag: str) -> list[dict]:
        return [_parse_component(e, tag, target_sdk) for e in app_elem.findall(tag)]

    activities = parse_tag("activity") + parse_tag("activity-alias")
    services   = parse_tag("service")
    receivers  = parse_tag("receiver")
    providers  = parse_tag("provider")

    return {
        "activities": [c for c in activities if c["exported"]],
        "services":   [c for c in services   if c["exported"]],
        "receivers":  [c for c in receivers  if c["exported"]],
        "providers":  [c for c in providers  if c["exported"]],
    }


def _parse_component(elem, tag: str, target_sdk: int) -> dict:
    """Extract structured info from an activity/service/receiver/provider element."""
    name = _attr(elem, "name", "")
    exported_raw = _attr(elem, "exported")
    permission = _attr(elem, "permission")

    intent_filters = [_parse_intent_filter(f) for f in elem.findall("intent-filter")]

    if exported_raw is not None:
        exported = exported_raw.lower() in ("true", "1")
    else:
        exported = bool(intent_filters) and target_sdk < 31

    component: dict[str, Any] = {
        "name": name,
        "exported": exported,
        "permission": permission,
        "intent_filters": intent_filters,
    }

    if tag == "provider":
        component["authorities"] = _attr(elem, "authorities")
        component["read_permission"] = _attr(elem, "readPermission")
        component["write_permission"] = _attr(elem, "writePermission")
        component["grant_uri_permissions"] = _attr(elem, "grantUriPermissions", "false")

    return component


def _parse_intent_filter(filter_elem) -> dict:
    """Parse a single <intent-filter> element into a structured dict."""
    actions = [_attr(a, "name", "") for a in filter_elem.findall("action")]
    categories = [_attr(c, "name", "") for c in filter_elem.findall("category")]
    data_list: list[dict] = []
    for d in filter_elem.findall("data"):
        entry: dict[str, str] = {}
        for attr_name in ("scheme", "host", "port", "path", "pathPrefix",
                          "pathPattern", "mimeType"):
            val = _attr(d, attr_name)
            if val is not None:
                entry[attr_name] = val
        if entry:
            data_list.append(entry)
    return {"actions": actions, "categories": categories, "data": data_list}


def _build_activity_tests(pkg: str, component_name: str,
                           intent_filters: list[dict]) -> list[dict]:
    """Return the list of test cases for a single activity component."""
    cn = f"{pkg}/{component_name}"

    # Gather URI schemes from intent-filter data elements
    schemes: list[str] = []
    hosts: list[str] = []
    for f in intent_filters:
        for d in f.get("data", []):
            if "scheme" in d:
                schemes.append(d["scheme"])
            if "host" in d:
                hosts.append(d["host"])

    base_scheme = schemes[0] if schemes else None
    base_host   = hosts[0]   if hosts   else "host"

    tests: list[dict] = [
        {
            "name": "empty_intent",
            "cmd":  ["shell", "am", "start", "-n", cn],
        },
        {
            "name": "null_data_uri",
            "cmd":  ["shell", "am", "start", "-n", cn, "-d", ""],
        },
        {
            "name": "malformed_uri",
            "cmd":  ["shell", "am", "start", "-n", cn, "-d", "://invalid"],
        },
        {
            "name": "oversized_string_extra",
            "cmd":  ["shell", "am", "start", "-n", cn, "--es", "key", "A" * 5000],
        },
        {
            "name": "wrong_type_extra",
            "cmd":  ["shell", "am", "start", "-n", cn, "--ei", "string_key", "99999"],
        },
        {
            "name": "javascript_uri",
            "cmd":  ["shell", "am", "start", "-n", cn, "-d", "javascript:alert(1)"],
        },
        {
            "name": "action_no_data",
            "cmd":  ["shell", "am", "start", "-n", cn, "-a", "android.intent.action.VIEW"],
        },
    ]

    # Deep-link variants only when a scheme is present
    if base_scheme:
        base_uri = f"{base_scheme}://{base_host}"
        tests += [
            {
                "name": "sql_injection_uri",
                "cmd":  ["shell", "am", "start", "-n", cn, "-d",
                         f"{base_uri}/' OR '1'='1"],
            },
            {
                "name": "path_traversal_uri",
                "cmd":  ["shell", "am", "start", "-n", cn, "-d",
                         f"{base_uri}/../../etc/passwd"],
            },
            {
                "name": "xss_uri",
                "cmd":  ["shell", "am", "start", "-n", cn, "-d",
                         f"{base_uri}/<script>alert(1)</script>"],
            },
            {
                "name": "long_path_uri",
                "cmd":  ["shell", "am", "start", "-n", cn, "-d",
                         f"{base_uri}/" + "A" * 2000],
            },
            {
                "name": "null_byte_uri",
                "cmd":  ["shell", "am", "start", "-n", cn, "-d",
                         f"{base_uri}/test%00evil"],
            },
            {
                "name": "crlf_injection_uri",
                "cmd":  ["shell", "am", "start", "-n", cn, "-d",
                         f"{base_uri}/path%0d%0aInjected-Header:value"],
            },
        ]

    return tests


def _build_receiver_tests(pkg: str, component_name: str,
                           intent_filters: list[dict]) -> list[dict]:
    """Return broadcast test cases for a single receiver component."""
    cn = f"{pkg}/{component_name}"

    # Collect declared actions for this receiver
    actions: list[str] = []
    for f in intent_filters:
        actions.extend(f.get("actions", []))

    primary_action = actions[0] if actions else "android.intent.action.MAIN"

    tests: list[dict] = [
        {
            "name": "empty_broadcast",
            "cmd":  ["shell", "am", "broadcast", "-n", cn, "-a", primary_action],
        },
        {
            "name": "broadcast_oversized_extra",
            "cmd":  ["shell", "am", "broadcast", "-n", cn, "-a", primary_action,
                     "--es", "data", "X" * 5000],
        },
        {
            "name": "broadcast_wrong_type",
            "cmd":  ["shell", "am", "broadcast", "-n", cn, "-a", primary_action,
                     "--ei", "string_field", "99999"],
        },
        {
            "name": "broadcast_no_action",
            "cmd":  ["shell", "am", "broadcast", "-n", cn],
        },
        {
            "name": "broadcast_malformed_uri",
            "cmd":  ["shell", "am", "broadcast", "-n", cn, "-a", primary_action,
                     "-d", "://invalid"],
        },
    ]

    # Additional broadcasts for each declared action
    for action in actions[1:4]:  # Cap at 3 extra actions
        tests.append({
            "name": f"broadcast_action_{action.split('.')[-1]}",
            "cmd":  ["shell", "am", "broadcast", "-n", cn, "-a", action],
        })

    return tests


def _build_service_tests(pkg: str, component_name: str,
                          intent_filters: list[dict]) -> list[dict]:
    """Return start-service test cases for a single service component."""
    cn = f"{pkg}/{component_name}"

    actions: list[str] = []
    for f in intent_filters:
        actions.extend(f.get("actions", []))
    primary_action = actions[0] if actions else "android.intent.action.MAIN"

    return [
        {
            "name": "start_service_empty",
            "cmd":  ["shell", "am", "startservice", "-n", cn],
        },
        {
            "name": "start_service_with_action",
            "cmd":  ["shell", "am", "startservice", "-n", cn, "-a", primary_action],
        },
        {
            "name": "start_service_oversized_extra",
            "cmd":  ["shell", "am", "startservice", "-n", cn,
                     "--es", "key", "S" * 5000],
        },
        {
            "name": "start_service_malformed_uri",
            "cmd":  ["shell", "am", "startservice", "-n", cn,
                     "-d", "://invalid"],
        },
    ]


def _run_test(
    pkg: str,
    component: str,
    component_type: str,
    test: dict,
    timeout_per_test: int,
    take_screenshots: bool,
    test_index: int,
) -> dict:
    """Execute one fuzz test and return a result dict."""
    intent_cmd_str = "adb " + " ".join(test["cmd"])

    try:
        _clear_logcat()
        run_adb(*test["cmd"], timeout=max(timeout_per_test + 5, 15))
    except RuntimeError:
        # am commands can exit non-zero even on success (e.g. activity not found)
        pass

    time.sleep(timeout_per_test)

    logcat_text = _capture_logcat()
    result_type, crash_snippet = _check_logcat_for_crash(logcat_text, pkg)

    screenshot_info = None
    if take_screenshots:
        label = f"{test_index:04d}_{test['name'][:20]}"
        screenshot_info = _take_screenshot_b64(label)

    return {
        "component":      component,
        "component_type": component_type,
        "test":           test["name"],
        "intent_command": intent_cmd_str,
        "result":         result_type,
        "crash_log":      crash_snippet,
        "severity":       _SEVERITY_MAP.get(result_type, "info"),
        "screenshot":     screenshot_info,
    }


# ---------------------------------------------------------------------------
# Tool 1 — fuzz_exported_components
# ---------------------------------------------------------------------------

@mcp.tool()
def fuzz_exported_components(
    session_id: str,
    package_name: str,
    timeout_per_test: int = 5,
    take_screenshots: bool = False,
) -> dict:
    """Fuzz all exported components with malformed intents and detect crashes.

    For each exported activity, service, and receiver found in the APK manifest:
    1. Sends a series of test intents with various malformed inputs.
    2. Monitors logcat for crashes, ANRs, and uncaught exceptions after each.
    3. Records which inputs cause failures and their severity.

    Args:
        session_id: Session with loaded APK (used for manifest parsing).
        package_name: Package name of the installed app on the connected device.
        timeout_per_test: Seconds to wait after each intent for crash detection.
        take_screenshots: Capture a screenshot after each activity launch.

    Returns:
        dict with ``status``, ``data`` containing ``total_tests``, ``crashes``,
        ``anrs``, ``exceptions``, ``results`` list, ``vulnerable_components``,
        and ``screenshots``.
    """
    try:
        _require_device()

        components = _parse_manifest_components(session_id)

        all_results: list[dict] = []
        test_index = 0

        for component in components["activities"]:
            cname = component["name"]
            tests = _build_activity_tests(
                package_name, cname, component.get("intent_filters", [])
            )
            for test in tests:
                result = _run_test(
                    package_name, cname, "activity",
                    test, timeout_per_test, take_screenshots, test_index
                )
                all_results.append(result)
                test_index += 1

        for component in components["services"]:
            cname = component["name"]
            tests = _build_service_tests(
                package_name, cname, component.get("intent_filters", [])
            )
            for test in tests:
                result = _run_test(
                    package_name, cname, "service",
                    test, timeout_per_test, take_screenshots, test_index
                )
                all_results.append(result)
                test_index += 1

        for component in components["receivers"]:
            cname = component["name"]
            tests = _build_receiver_tests(
                package_name, cname, component.get("intent_filters", [])
            )
            for test in tests:
                result = _run_test(
                    package_name, cname, "receiver",
                    test, timeout_per_test, take_screenshots, test_index
                )
                all_results.append(result)
                test_index += 1

        # Aggregate counters
        crashes    = sum(1 for r in all_results if r["result"] == "crash")
        anrs       = sum(1 for r in all_results if r["result"] == "anr")
        exceptions = sum(1 for r in all_results if r["result"] in ("exception", "security_exception"))
        screenshots = [
            r["screenshot"] for r in all_results
            if r.get("screenshot") is not None
        ]

        vulnerable: list[str] = list({
            r["component"]
            for r in all_results
            if r["result"] != "no_crash"
        })

        return {
            "status": "ok",
            "data": {
                "total_tests":           len(all_results),
                "crashes":               crashes,
                "anrs":                  anrs,
                "exceptions":            exceptions,
                "results":               all_results,
                "vulnerable_components": vulnerable,
                "screenshots":           screenshots,
                "component_counts": {
                    "activities": len(components["activities"]),
                    "services":   len(components["services"]),
                    "receivers":  len(components["receivers"]),
                },
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": (
                "Ensure a device is connected (adb devices), "
                "USB debugging is authorised, and the app is installed."
            ),
        }
    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Fuzzer error: {exc}",
        }


# ---------------------------------------------------------------------------
# Tool 2 — fuzz_deep_links
# ---------------------------------------------------------------------------

def _extract_uri_schemes(components: dict) -> list[tuple[str, str]]:
    """Return deduplicated (scheme, host) pairs from all exported components."""
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for ctype in ("activities", "services", "receivers"):
        for comp in components.get(ctype, []):
            for f in comp.get("intent_filters", []):
                for d in f.get("data", []):
                    scheme = d.get("scheme", "")
                    host   = d.get("host",   "")
                    if scheme and scheme not in ("http", "https"):
                        key = (scheme, host or "host")
                        if key not in seen:
                            seen.add(key)
                            pairs.append(key)

    return pairs


def _build_deep_link_tests(scheme: str, host: str) -> list[dict]:
    """Build malformed URI test payloads for a single (scheme, host) pair."""
    base = f"{scheme}://{host}"
    return [
        {"name": "normal_path",       "uri": f"{base}/normal"},
        {"name": "long_path",         "uri": f"{base}/" + "A" * 5000},
        {"name": "path_traversal",    "uri": f"{base}/../../../etc/passwd"},
        {"name": "null_byte",         "uri": f"{base}/test%00evil"},
        {"name": "sql_in_query",      "uri": f"{base}/path?id=1' OR '1'='1"},
        {"name": "crlf_injection",    "uri": f"{base}/path%0d%0aInjected-Header:value"},
        {"name": "js_fragment",       "uri": f"{base}/path#<script>alert(1)</script>"},
        {"name": "empty_path",        "uri": f"{scheme}://"},
        {"name": "long_query",        "uri": f"{base}/path?" + "key=value&" * 500},
        {"name": "xss_path",          "uri": f"{base}/<script>alert(1)</script>"},
        {"name": "unicode_overflow",  "uri": f"{base}/" + "%ED%A0%80" * 50},
        {"name": "double_slash",      "uri": f"{scheme}:////etc/passwd"},
        {"name": "percent_encoded_slash", "uri": f"{base}/%2e%2e/%2e%2e/etc/passwd"},
    ]


@mcp.tool()
def fuzz_deep_links(
    session_id: str,
    package_name: str,
    timeout_per_test: int = 5,
) -> dict:
    """Fuzz all registered deep link URI schemes with malformed inputs.

    Extracts all custom URI schemes from the manifest's intent filters, then
    tests each (scheme, host) combination with malformed paths, query
    parameters, and fragments via ``am start -d``.  Monitors logcat for
    crashes after each test.

    Args:
        session_id: Session with a loaded APK.
        package_name: Package name of the installed app on the connected device.
        timeout_per_test: Seconds to wait after each intent for crash detection.

    Returns:
        dict with ``status`` and ``data`` containing per-URI test results
        and crash summaries.
    """
    try:
        _require_device()

        components = _parse_manifest_components(session_id)
        uri_pairs  = _extract_uri_schemes(components)

        if not uri_pairs:
            return {
                "status": "ok",
                "data": {
                    "total_tests":           0,
                    "crashes":               0,
                    "results":               [],
                    "vulnerable_components": [],
                    "message": "No custom deep-link URI schemes found in the manifest.",
                },
            }

        all_results: list[dict] = []
        test_index  = 0

        for scheme, host in uri_pairs:
            tests = _build_deep_link_tests(scheme, host)
            for test in tests:
                uri     = test["uri"]
                cmd     = ["shell", "am", "start",
                           "-a", "android.intent.action.VIEW",
                           "-d", uri]
                cmd_str = "adb " + " ".join(cmd)

                try:
                    _clear_logcat()
                    run_adb(*cmd, timeout=max(timeout_per_test + 5, 15))
                except RuntimeError:
                    pass

                time.sleep(timeout_per_test)
                logcat_text = _capture_logcat()
                result_type, crash_snippet = _check_logcat_for_crash(
                    logcat_text, package_name
                )

                all_results.append({
                    "scheme":         scheme,
                    "host":           host,
                    "test":           test["name"],
                    "uri":            uri,
                    "intent_command": cmd_str,
                    "result":         result_type,
                    "crash_log":      crash_snippet,
                    "severity":       _SEVERITY_MAP.get(result_type, "info"),
                })
                test_index += 1

        crashes  = sum(1 for r in all_results if r["result"] == "crash")
        anrs     = sum(1 for r in all_results if r["result"] == "anr")
        exceptions = sum(1 for r in all_results if r["result"] in (
            "exception", "security_exception"
        ))

        vulnerable_schemes = list({
            f"{r['scheme']}://{r['host']}"
            for r in all_results
            if r["result"] != "no_crash"
        })

        return {
            "status": "ok",
            "data": {
                "total_tests":      len(all_results),
                "crashes":          crashes,
                "anrs":             anrs,
                "exceptions":       exceptions,
                "uri_pairs_tested": [f"{s}://{h}" for s, h in uri_pairs],
                "results":          all_results,
                "vulnerable_schemes": vulnerable_schemes,
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": (
                "Ensure a device is connected (adb devices), "
                "USB debugging is authorised, and the app is installed."
            ),
        }
    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Deep-link fuzzer error: {exc}",
        }


# ---------------------------------------------------------------------------
# Tool 3 — fuzz_content_providers
# ---------------------------------------------------------------------------

def _build_provider_tests(authority: str) -> list[dict]:
    """Build content query/insert/update/delete test cases for one authority."""
    base = f"content://{authority}"
    tests: list[dict] = [
        # Basic read access
        {
            "name":    "basic_query",
            "op":      "query",
            "cmd":     ["shell", "content", "query", "--uri", f"{base}/"],
        },
        # SQL injection via --where
        {
            "name":    "sql_injection_where",
            "op":      "query",
            "cmd":     ["shell", "content", "query", "--uri", f"{base}/",
                        "--where", "1=1"],
        },
        {
            "name":    "sql_injection_where_tautology",
            "op":      "query",
            "cmd":     ["shell", "content", "query", "--uri", f"{base}/",
                        "--where", "1=1 OR 1=1"],
        },
        # SQL injection via projection (column list)
        {
            "name":    "sql_injection_projection",
            "op":      "query",
            "cmd":     ["shell", "content", "query", "--uri", f"{base}/",
                        "--projection", "* FROM sqlite_master--"],
        },
        # Path traversal in URI
        {
            "name":    "path_traversal",
            "op":      "query",
            "cmd":     ["shell", "content", "query", "--uri",
                        f"{base}/../../etc/passwd"],
        },
        {
            "name":    "path_traversal_encoded",
            "op":      "query",
            "cmd":     ["shell", "content", "query", "--uri",
                        f"{base}/%2e%2e/%2e%2e/etc/passwd"],
        },
        # Null segment
        {
            "name":    "null_path_segment",
            "op":      "query",
            "cmd":     ["shell", "content", "query", "--uri",
                        f"{base}/null"],
        },
        # Insert with SQL injection values
        {
            "name":    "insert_sql_injection",
            "op":      "insert",
            "cmd":     ["shell", "content", "insert", "--uri", f"{base}/",
                        "--bind", "col:s:' OR '1'='1"],
        },
        # Update without a WHERE (mass update attempt)
        {
            "name":    "update_no_where",
            "op":      "update",
            "cmd":     ["shell", "content", "update", "--uri", f"{base}/",
                        "--bind", "col:s:hacked"],
        },
        # Delete with SQL injection
        {
            "name":    "delete_sql_injection",
            "op":      "delete",
            "cmd":     ["shell", "content", "delete", "--uri", f"{base}/",
                        "--where", "1=1"],
        },
        # Oversized URI
        {
            "name":    "oversized_uri",
            "op":      "query",
            "cmd":     ["shell", "content", "query", "--uri",
                        f"{base}/" + "A" * 2000],
        },
    ]
    return tests


@mcp.tool()
def fuzz_content_providers(session_id: str, package_name: str) -> dict:
    """Test exported content providers for SQL injection and path traversal.

    Uses ``adb shell content query/insert/update/delete`` to test each
    exported content provider's URIs with malformed inputs, SQL injection
    payloads, and path traversal sequences.

    Args:
        session_id: Session with a loaded APK.
        package_name: Package name of the installed app on the connected device.

    Returns:
        dict with ``status`` and ``data`` containing per-provider test results,
        any errors/responses, and a list of potentially vulnerable providers.
    """
    try:
        _require_device()

        components = _parse_manifest_components(session_id)
        providers  = components.get("providers", [])

        if not providers:
            return {
                "status": "ok",
                "data": {
                    "total_tests":           0,
                    "results":               [],
                    "vulnerable_components": [],
                    "message": "No exported content providers found in the manifest.",
                },
            }

        all_results: list[dict] = []

        for provider in providers:
            authorities_raw = provider.get("authorities", "") or ""
            # Multiple authorities can be semicolon-separated
            authority_list = [a.strip() for a in authorities_raw.split(";") if a.strip()]

            if not authority_list:
                continue

            for authority in authority_list:
                tests = _build_provider_tests(authority)

                for test in tests:
                    cmd     = test["cmd"]
                    cmd_str = "adb " + " ".join(cmd)
                    output  = ""
                    error   = ""

                    _clear_logcat()
                    try:
                        output = run_adb(*cmd, timeout=20)
                    except RuntimeError as exc:
                        error = str(exc)

                    # Brief pause then check logcat
                    time.sleep(2)
                    logcat_text = _capture_logcat()
                    result_type, crash_snippet = _check_logcat_for_crash(
                        logcat_text, package_name
                    )

                    # Heuristic: if output contains rows or exception, mark accordingly
                    has_data  = bool(output) and "Row:" in output
                    has_error = bool(error)

                    # Elevate result if we got actual data back (access succeeded)
                    if has_data and result_type == "no_crash":
                        result_type = "data_exposed"
                        _SEVERITY_MAP["data_exposed"] = "high"

                    all_results.append({
                        "provider":       provider["name"],
                        "authority":      authority,
                        "test":           test["name"],
                        "operation":      test["op"],
                        "command":        cmd_str,
                        "result":         result_type,
                        "crash_log":      crash_snippet,
                        "response":       output[:500] if output else "",
                        "error":          error[:500] if error else "",
                        "data_returned":  has_data,
                        "severity":       _SEVERITY_MAP.get(result_type, "info"),
                    })

        crashes    = sum(1 for r in all_results if r["result"] == "crash")
        exceptions = sum(1 for r in all_results if r["result"] in (
            "exception", "security_exception"
        ))
        data_exposed = sum(1 for r in all_results if r.get("data_returned"))

        vulnerable: list[str] = list({
            r["provider"]
            for r in all_results
            if r["result"] not in ("no_crash",)
        })

        return {
            "status": "ok",
            "data": {
                "total_tests":           len(all_results),
                "crashes":               crashes,
                "exceptions":            exceptions,
                "data_exposed_count":    data_exposed,
                "providers_tested":      len(providers),
                "results":               all_results,
                "vulnerable_components": vulnerable,
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": (
                "Ensure a device is connected (adb devices), "
                "USB debugging is authorised, and the app is installed."
            ),
        }
    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Content provider fuzzer error: {exc}",
        }
