"""Security-focused patch differ — identifies fixed vulnerabilities between APK versions.

Three tools are exposed:

- ``analyze_security_patches``  — broad scan of all security-relevant changes
- ``find_patched_methods``       — method-level diff with security annotations
- ``find_vulnerability_window``  — reverse-patch analysis: turn each patch into
                                   the implied vulnerability in the *old* version,
                                   and emit PoC ADB / Frida commands for it
"""

from __future__ import annotations

import difflib
import re
import xml.etree.ElementTree as ET
from typing import Any

from apksaw.server import mcp
from apksaw.session import get_session

# ---------------------------------------------------------------------------
# Android namespace constant (shared with diff.py)
# ---------------------------------------------------------------------------

_ANDROID_NS = "http://schemas.android.com/apk/res/android"


# ---------------------------------------------------------------------------
# Dangerous API signatures we track for removal
# Format: (class_regex, method_regex, human_label)
# ---------------------------------------------------------------------------

_DANGEROUS_APIS: list[tuple[str, str, str]] = [
    (r"Ljava/lang/Runtime;",                   r"exec",                           "Runtime.exec()"),
    (r"Landroid/webkit/WebView;",              r"addJavascriptInterface",          "WebView.addJavascriptInterface()"),
    (r"Landroid/webkit/WebSettings;",          r"setAllowUniversalAccessFromFileURLs", "WebSettings.setAllowUniversalAccessFromFileURLs()"),
    (r"Landroid/webkit/WebSettings;",          r"setAllowFileAccessFromFileURLs",  "WebSettings.setAllowFileAccessFromFileURLs()"),
    (r"Landroid/webkit/WebSettings;",          r"setJavaScriptEnabled",            "WebSettings.setJavaScriptEnabled()"),
    (r"Landroid/webkit/WebView;",              r"loadUrl",                         "WebView.loadUrl()"),
    (r"Landroid/database/sqlite/SQLiteDatabase;", r"rawQuery",                     "SQLiteDatabase.rawQuery()"),
    (r"Landroid/database/sqlite/SQLiteDatabase;", r"execSQL",                      "SQLiteDatabase.execSQL()"),
    (r"Ldalvik/system/DexClassLoader;",        r"<init>",                          "DexClassLoader (dynamic code loading)"),
    (r"Ldalvik/system/PathClassLoader;",       r"<init>",                          "PathClassLoader (dynamic code loading)"),
    (r"Ljava/lang/reflect/Method;",            r"invoke",                          "Reflection.Method.invoke()"),
    (r"Landroid/content/SharedPreferences\$Editor;", r"putString",                 "SharedPreferences.putString() (potential sensitive data)"),
    (r"Ljavax/net/ssl/HttpsURLConnection;",    r"setHostnameVerifier",             "HttpsURLConnection.setHostnameVerifier()"),
    (r"Ljavax/net/ssl/SSLContext;",            r"init",                            "SSLContext.init() (custom TrustManager)"),
]

# ---------------------------------------------------------------------------
# Input-validation patterns in decompiled source (Java pseudocode / smali)
# ---------------------------------------------------------------------------

_VALIDATION_PATTERNS: list[tuple[str, str, str]] = [
    (r"==\s*null|!=\s*null|Objects\.requireNonNull|requireNonNull",
     "null_check", "Null check"),
    (r"TextUtils\.isEmpty|isEmpty\(\)|isBlank\(\)",
     "empty_check", "Empty/blank check"),
    (r"\.length\(\)\s*[><]=?\s*\d+|\.length\s*[><]=?\s*\d+",
     "length_check", "Length bounds check"),
    (r"Pattern\.compile|\.matches\(|\.find\(\)|Regex\(",
     "regex_validation", "Regex input validation"),
    (r"\binstanceof\b",
     "type_check", "Type check (instanceof)"),
    (r"getScheme\(\)|getHost\(\)|getAuthority\(\)|Uri\.parse",
     "uri_validation", "URI/scheme validation"),
    (r"startsWith\(|endsWith\(|contains\(",
     "string_prefix_check", "String prefix/suffix/contains check"),
    (r"Preconditions\.|checkArgument\(|checkNotNull\(|checkState\(",
     "guava_precondition", "Guava Precondition check"),
    (r"@NonNull|@NotNull|@Nullable",
     "annotation_check", "Nullability annotation enforcement"),
]

# ---------------------------------------------------------------------------
# Exception handling patterns around security-sensitive operations
# ---------------------------------------------------------------------------

_SECURITY_EXCEPTION_TARGETS: list[tuple[str, str]] = [
    (r"checkServerTrusted",   "X509TrustManager.checkServerTrusted"),
    (r"verify\s*\(",          "HostnameVerifier.verify"),
    (r"Cipher\.getInstance",  "Cipher.getInstance"),
    (r"SecretKeySpec",        "SecretKeySpec construction"),
    (r"KeyStore",             "KeyStore access"),
    (r"SSLContext",           "SSLContext init"),
    (r"CertificateFactory",   "CertificateFactory"),
]


# ---------------------------------------------------------------------------
# Shared low-level helpers
# ---------------------------------------------------------------------------


def _attr(element, name: str, default: Any = None) -> Any:
    return element.get(f"{{{_ANDROID_NS}}}{name}", default)


def _dalvik_to_java(name: str) -> str:
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def _java_to_dalvik(name: str) -> str:
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"


def _normalize_class_name(name: str) -> str:
    name = name.strip()
    if name.startswith("L") and name.endswith(";"):
        return name
    return _java_to_dalvik(name)


def _get_components(apk) -> dict[str, dict]:
    """Return {tag::name -> component_attrs} for all manifest components."""
    manifest_elem = apk.get_android_manifest_xml()
    target_sdk_raw = apk.get_target_sdk_version()
    try:
        target_sdk = int(target_sdk_raw) if target_sdk_raw else 0
    except (ValueError, TypeError):
        target_sdk = 0

    app_elem = manifest_elem.find("application")
    if app_elem is None:
        return {}

    components: dict[str, dict] = {}
    tags = ("activity", "activity-alias", "service", "receiver", "provider")
    for tag in tags:
        for elem in app_elem.findall(tag):
            name = _attr(elem, "name", "")
            if not name:
                continue

            exported_raw = _attr(elem, "exported")
            has_filters = bool(elem.findall("intent-filter"))
            if exported_raw is not None:
                exported = exported_raw.lower() in ("true", "1")
            else:
                exported = has_filters and target_sdk < 31

            permission = _attr(elem, "permission")
            read_permission = _attr(elem, "readPermission")
            write_permission = _attr(elem, "writePermission")
            grant_uri = bool(elem.findall("grant-uri-permission"))

            filters = []
            for f in elem.findall("intent-filter"):
                actions = [_attr(a, "name", "") for a in f.findall("action")]
                data_schemes = [
                    _attr(d, "scheme", "")
                    for d in f.findall("data")
                    if _attr(d, "scheme")
                ]
                filters.append({"actions": actions, "schemes": data_schemes})

            components[f"{tag}::{name}"] = {
                "tag": tag,
                "name": name,
                "exported": exported,
                "permission": permission,
                "read_permission": read_permission,
                "write_permission": write_permission,
                "intent_filters": filters,
                "grant_uri_permissions": grant_uri,
            }

    return components


def _get_permissions(apk) -> set[str]:
    perms = set(apk.get_permissions())
    manifest_elem = apk.get_android_manifest_xml()
    for p in manifest_elem.findall("uses-permission-sdk-23"):
        name = _attr(p, "name")
        if name:
            perms.add(name)
    return perms


def _get_nsc_info(apk) -> dict:
    """Parse network_security_config.xml and return a structured summary."""
    result: dict = {
        "found": False,
        "cleartext_permitted": None,
        "domains": [],
        "pin_sets": [],
        "trust_anchors": [],
        "user_certs_trusted": None,
    }

    # Locate the NSC resource — filename varies (nsc.xml, network_security_config.xml…)
    # Try the canonical filename first, then iterate all res/xml/ files
    candidate_files: list[str] = ["res/xml/network_security_config.xml"]
    try:
        for f in apk.get_files():
            if f.startswith("res/xml/") and f not in candidate_files:
                candidate_files.append(f)
    except Exception:
        pass

    nsc_raw: bytes | None = None
    for candidate in candidate_files:
        try:
            nsc_raw = apk.get_file(candidate)
            if nsc_raw:
                break
        except Exception:
            continue

    if not nsc_raw:
        return result

    # AXMLPrinter output from androguard may already be decoded XML; try to parse
    try:
        if isinstance(nsc_raw, bytes):
            # It may be binary AXML — try direct parse and fall back gracefully
            try:
                root = ET.fromstring(nsc_raw.decode("utf-8", errors="replace"))
            except ET.ParseError:
                # Binary AXML — use the androguard AXMLPrinter if available
                try:
                    from androguard.core.bytecodes.axml import AXMLPrinter
                    printer = AXMLPrinter(nsc_raw)
                    root = ET.fromstring(printer.get_xml())
                except Exception:
                    return result
        else:
            root = ET.fromstring(nsc_raw)
    except Exception:
        return result

    result["found"] = True

    # Global cleartext
    base_config = root.find("base-config")
    if base_config is not None:
        ct = base_config.get("cleartextTrafficPermitted", "").lower()
        result["cleartext_permitted"] = ct in ("true", "1") if ct else None
        # User CA trust
        for trust_anchors_elem in base_config.findall("trust-anchors"):
            for cert_elem in trust_anchors_elem.findall("certificates"):
                src = cert_elem.get("src", "")
                result["trust_anchors"].append(src)
                if src == "user":
                    result["user_certs_trusted"] = True

    if result["user_certs_trusted"] is None:
        result["user_certs_trusted"] = False

    # Domain-specific configs
    for ds in root.findall("domain-config"):
        domains_in_block = [
            d.text.strip() for d in ds.findall("domain") if d.text
        ]
        pin_set = ds.find("pin-set")
        pins: list[str] = []
        if pin_set is not None:
            for pin in pin_set.findall("pin"):
                digest = pin.get("digest", "sha256")
                value = (pin.text or "").strip()
                pins.append(f"{digest}/{value}")

        result["domains"].append({
            "domains": domains_in_block,
            "pins": pins,
            "cleartext": ds.get("cleartextTrafficPermitted"),
        })
        result["pin_sets"].extend(pins)

    return result


def _collect_api_callsites(analysis, class_re: str, method_re: str) -> set[str]:
    """Return set of 'ClassName->methodName' caller locations for an API."""
    locations: set[str] = set()
    try:
        for ma in analysis.find_methods(classname=class_re, methodname=method_re):
            for _, caller, _ in ma.get_xref_from():
                if not caller.is_external():
                    locations.add(f"{caller.class_name}->{caller.name}")
    except Exception:
        pass
    return locations


def _method_bytecode_fingerprint(method_analysis) -> int:
    """Hash all Dalvik instruction names+outputs for a method (cheap change detector)."""
    try:
        em = method_analysis.get_method()
        code = em.get_code()
        if code is None:
            return 0
        parts = []
        for instr in code.get_bc().get_instructions():
            parts.append(f"{instr.get_name()}:{instr.get_output()}")
        return hash("\n".join(parts))
    except Exception:
        return 0


def _decompile_method_source(session, class_analysis, method_analysis) -> str:
    """Decompile a method to readable source; fall back to smali strings."""
    try:
        from androguard.decompiler.decompiler import DecompilerDAD
        dec = DecompilerDAD(session.dex_list, session.analysis)
        src = dec.get_source_method(method_analysis.get_method())
        if src and src.strip():
            return src
    except Exception:
        pass

    # Smali disassembly fallback — just collect instruction strings
    try:
        em = method_analysis.get_method()
        code = em.get_code()
        if code is None:
            return "# (abstract or native)"
        lines = [
            f"    {instr.get_name():30s} {instr.get_output()}"
            for instr in code.get_bc().get_instructions()
        ]
        return "\n".join(lines)
    except Exception as exc:
        return f"# decompile error: {exc}"


def _source_has_try_catch(source: str) -> bool:
    """Check if decompiled source or smali contains exception handling."""
    try_catch_re = re.compile(
        r"\btry\b|\bcatch\b|:try_start_|:catch_|move-exception|:catchall_",
        re.IGNORECASE,
    )
    return bool(try_catch_re.search(source))


def _extract_security_annotations(source_old: str, source_new: str) -> list[dict]:
    """Compare two method sources and return security-relevant diff annotations."""
    old_lines = source_old.splitlines()
    new_lines = source_new.splitlines()

    added_lines = [
        line.lstrip()
        for line in difflib.unified_diff(old_lines, new_lines, lineterm="")
        if line.startswith("+") and not line.startswith("+++")
    ]
    removed_lines = [
        line.lstrip()
        for line in difflib.unified_diff(old_lines, new_lines, lineterm="")
        if line.startswith("-") and not line.startswith("---")
    ]

    annotations: list[dict] = []

    # Input validation added
    for pattern, kind, label in _VALIDATION_PATTERNS:
        compiled = re.compile(pattern, re.IGNORECASE)
        new_hits = [line for line in added_lines if compiled.search(line)]
        if new_hits:
            annotations.append({
                "type": "input_validation_added",
                "kind": kind,
                "label": label,
                "examples": new_hits[:3],
                "severity": "medium",
            })

    # Exception handling added around security operations
    new_has_try = any(
        re.search(r"\btry\b|:try_start_", line, re.IGNORECASE) for line in added_lines
    )
    old_has_try = _source_has_try_catch(source_old)
    if new_has_try and not old_has_try:
        for target_re, target_label in _SECURITY_EXCEPTION_TARGETS:
            if re.search(target_re, source_new, re.IGNORECASE):
                annotations.append({
                    "type": "exception_handling_added",
                    "label": f"try-catch added around {target_label}",
                    "severity": "medium",
                })

    # Dangerous API removed
    for _class_re, _method_re, api_label in _DANGEROUS_APIS:
        # Approximate: look for the method name substring in removed lines
        short_name = _method_re.replace("\\", "").replace("(", "").replace(")", "")
        if any(short_name in line for line in removed_lines):
            annotations.append({
                "type": "dangerous_api_removed",
                "api": api_label,
                "severity": "high",
            })

    return annotations


def _is_obfuscated_class_name(dalvik_name: str) -> bool:
    """Return True if a Dalvik class name looks like a single-letter obfuscated name."""
    # Strip L...;
    if dalvik_name.startswith("L") and dalvik_name.endswith(";"):
        inner = dalvik_name[1:-1]
    else:
        inner = dalvik_name
    # Last component after final /
    short = inner.rsplit("/", 1)[-1]
    # Remove $ inner-class suffix
    short = short.split("$")[0]
    return len(short) <= 2


def _obfuscation_ratio(analysis) -> float:
    """Fraction of non-external classes with obfuscated names."""
    total = 0
    obfuscated = 0
    for ca in analysis.get_classes():
        if ca.is_external():
            continue
        total += 1
        if _is_obfuscated_class_name(ca.name):
            obfuscated += 1
    if total == 0:
        return 0.0
    return obfuscated / total


# ---------------------------------------------------------------------------
# PoC command generators
# ---------------------------------------------------------------------------

def _poc_for_exported_component(package: str, tag: str, comp_name: str) -> list[str]:
    """Generate ADB PoC commands to probe an exposed component."""
    cmds: list[str] = []
    if tag in ("activity", "activity-alias"):
        cmds.append(
            f"adb shell am start -n {package}/{comp_name}"
        )
        cmds.append(
            f"# To pass extras: adb shell am start -n {package}/{comp_name} "
            f"--es extra_key extra_value"
        )
    elif tag == "service":
        cmds.append(
            f"adb shell am startservice -n {package}/{comp_name}"
        )
    elif tag == "receiver":
        cmds.append(
            f"adb shell am broadcast -a android.intent.action.MAIN -n {package}/{comp_name}"
        )
    elif tag == "provider":
        cmds.append(
            f"adb shell content query --uri content://{package}/data"
        )
        cmds.append(
            f"# Try read: adb shell content read --uri content://{package}/data"
        )
    return cmds


def _poc_for_mitm(domain: str) -> list[str]:
    """Generate Frida / proxy PoC for a domain lacking cert pinning in old APK."""
    return [
        f"# Route device through Burp/mitmproxy, then test: https://{domain}",
        "# Use Frida SSL bypass script: frida -U -f <package> -l ssl_bypass.js",
        "# Or: adb shell settings put global http_proxy <your_ip>:8080",
        f"# curl -k https://{domain}  # verify traffic is visible in proxy",
    ]


def _poc_for_dangerous_api(api_label: str, package: str, component: str) -> list[str]:
    """Generic PoC hint for a dangerous API removed in the new version."""
    if "Runtime.exec" in api_label:
        return [
            "# Old APK exposed Runtime.exec — reach it via exported component:",
            f"adb shell am start -n {package}/{component} --es cmd 'id'",
        ]
    if "addJavascriptInterface" in api_label:
        return [
            "# Old APK has addJavascriptInterface — load attacker HTML in WebView:",
            f"adb shell am start -n {package}/{component} "
            f"--es url 'file:///sdcard/attack.html'",
            "# attack.html: <script>jsInterface.execCommand('id')</script>",
        ]
    if "loadUrl" in api_label:
        return [
            "# Old APK may allow arbitrary loadUrl — attempt file:// or javascript: URI:",
            f"adb shell am start -n {package}/{component} "
            f"--es url 'javascript:alert(document.cookie)'",
        ]
    if "rawQuery" in api_label or "execSQL" in api_label:
        return [
            "# Old APK may have SQL injection — fuzz the query parameter:",
            f"adb shell am start -n {package}/{component} --es query \"' OR '1'='1",
        ]
    return [f"# {api_label} removed — reach the caller via exported components if any"]


# ---------------------------------------------------------------------------
# Tool 1 — analyze_security_patches
# ---------------------------------------------------------------------------


@mcp.tool()
def analyze_security_patches(session_id_old: str, session_id_new: str) -> dict:
    """Analyze differences between two APK versions to identify security patches.

    Looks for patterns that indicate a vulnerability was fixed in the newer version:
    - New input validation added (the old version lacked it)
    - Components changed from exported to non-exported
    - New permission checks added to components
    - TLS/certificate pinning added or strengthened
    - New exception handling around security-sensitive APIs
    - Removed dangerous API calls (exec, loadUrl, addJavascriptInterface)
    - New obfuscation or integrity checks added

    Args:
        session_id_old: Session ID for the older APK version (from load_apk).
        session_id_new: Session ID for the newer APK version (from load_apk).

    Returns:
        A dict with status "ok" and data containing a list of security_patches,
        any regressions found as new_vulnerabilities, and a severity summary.
    """
    try:
        old_session = get_session(session_id_old)
        new_session = get_session(session_id_new)
        old_apk = old_session.apk
        new_apk = new_session.apk
        old_analysis = old_session.analysis
        new_analysis = new_session.analysis

        patches: list[dict] = []
        regressions: list[dict] = []

        # ------------------------------------------------------------------
        # 1. Component export changes
        # ------------------------------------------------------------------
        old_comps = _get_components(old_apk)
        new_comps = _get_components(new_apk)

        for key in set(old_comps) & set(new_comps):
            old_c = old_comps[key]
            new_c = new_comps[key]
            tag = old_c["tag"]
            comp_name = old_c["name"]

            was_exported = old_c["exported"]
            now_exported = new_c["exported"]
            old_perm = old_c.get("permission")
            new_perm = new_c.get("permission")

            # Component went from exported-no-perm to unexported
            if was_exported and not old_perm and not now_exported:
                patches.append({
                    "type": "component_unexported",
                    "component": comp_name,
                    "tag": tag,
                    "old_value": "exported=true, no permission",
                    "new_value": "exported=false",
                    "severity": "high",
                    "implication": (
                        f"Old version had exposed {tag} '{comp_name}' with no access "
                        f"control — likely exploitable without any permissions."
                    ),
                })

            # Component stayed exported but gained a permission guard
            elif was_exported and not old_perm and now_exported and new_perm:
                patches.append({
                    "type": "component_permission_added",
                    "component": comp_name,
                    "tag": tag,
                    "old_value": "exported=true, permission=none",
                    "new_value": f"exported=true, permission={new_perm}",
                    "severity": "high",
                    "implication": (
                        f"Old version allowed any app to interact with '{comp_name}'. "
                        f"Permission '{new_perm}' was added to restrict access."
                    ),
                })

            # Regression: component became exported
            elif not was_exported and now_exported:
                regressions.append({
                    "type": "component_newly_exported",
                    "component": comp_name,
                    "tag": tag,
                    "old_value": "exported=false (or implicit false)",
                    "new_value": f"exported=true, permission={new_perm or 'none'}",
                    "severity": "high",
                    "implication": (
                        f"New version exposes '{comp_name}' — this may be an attack surface "
                        f"regression."
                    ),
                })

            # Grant-URI permissions added (provider)
            if tag == "provider":
                old_grant = old_c.get("grant_uri_permissions", False)
                new_grant = new_c.get("grant_uri_permissions", False)
                if old_grant and not new_grant:
                    patches.append({
                        "type": "provider_grant_uri_removed",
                        "component": comp_name,
                        "tag": tag,
                        "old_value": "grantUriPermissions=true",
                        "new_value": "grantUriPermissions removed/false",
                        "severity": "medium",
                        "implication": (
                            "Old version allowed temporary URI grants to this provider — "
                            "potential data leakage path via grant was closed."
                        ),
                    })

        # Newly added components that are exported — potential regression
        for key in set(new_comps) - set(old_comps):
            new_c = new_comps[key]
            if new_c["exported"] and not new_c.get("permission"):
                regressions.append({
                    "type": "new_exported_component",
                    "component": new_c["name"],
                    "tag": new_c["tag"],
                    "old_value": "did not exist",
                    "new_value": "exported=true, permission=none",
                    "severity": "medium",
                    "implication": (
                        f"Newly added {new_c['tag']} '{new_c['name']}' is exported "
                        f"without permission — may be an unintended exposure."
                    ),
                })

        # ------------------------------------------------------------------
        # 2. Permission additions (distinguish security vs feature)
        # ------------------------------------------------------------------
        old_perms = _get_permissions(old_apk)
        new_perms = _get_permissions(new_apk)
        added_perms = new_perms - old_perms
        removed_perms = old_perms - new_perms

        # Feature permissions (new capabilities — not a fix)
        _FEATURE_PERMS = {
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.BODY_SENSORS",
            "android.permission.ACTIVITY_RECOGNITION",
        }

        for perm in sorted(added_perms):
            if perm in _FEATURE_PERMS:
                continue  # Skip — new feature, not security fix
            if perm.startswith("android.permission.") or "." in perm:
                severity = "low"
                # Custom signature permissions are more likely a security fix
                if not perm.startswith("android.permission."):
                    severity = "medium"
                patches.append({
                    "type": "permission_added",
                    "permission": perm,
                    "old_value": "not declared",
                    "new_value": "declared in new APK",
                    "severity": severity,
                    "implication": (
                        f"New permission '{perm}' added. "
                        f"If it's a custom signature permission used to guard components, "
                        f"the old version had unguarded access."
                    ),
                })

        for perm in sorted(removed_perms):
            # Dangerous permission removed — could be a security hardening
            _DANGEROUS_PERMS = {
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.READ_PHONE_STATE",
                "android.permission.PROCESS_OUTGOING_CALLS",
                "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG",
            }
            if perm in _DANGEROUS_PERMS:
                patches.append({
                    "type": "dangerous_permission_removed",
                    "permission": perm,
                    "old_value": "declared — app had broad access",
                    "new_value": "removed in new APK",
                    "severity": "medium",
                    "implication": (
                        f"Old version requested dangerous permission '{perm}'. "
                        f"Removal reduces the app's attack surface and data collection scope."
                    ),
                })

        # ------------------------------------------------------------------
        # 3. TLS / NSC hardening
        # ------------------------------------------------------------------
        old_nsc = _get_nsc_info(old_apk)
        new_nsc = _get_nsc_info(new_apk)

        # NSC file added
        if not old_nsc["found"] and new_nsc["found"]:
            patches.append({
                "type": "nsc_added",
                "detail": "Network Security Config added",
                "old_value": "no network_security_config.xml",
                "new_value": "network_security_config.xml present",
                "severity": "medium",
                "implication": (
                    "Old version had no NSC — all traffic used platform defaults "
                    "(cleartext permitted on older API levels, user CAs trusted)."
                ),
            })

        # Certificate pinning added
        old_pins = set(old_nsc.get("pin_sets", []))
        new_pins = set(new_nsc.get("pin_sets", []))
        added_pins = new_pins - old_pins

        if added_pins:
            # Collect domains for which pins were added
            pinned_domains: list[str] = []
            for domain_block in new_nsc.get("domains", []):
                if any(p in new_pins - old_pins for p in domain_block.get("pins", [])):
                    pinned_domains.extend(domain_block.get("domains", []))

            patches.append({
                "type": "tls_pinning_added",
                "detail": f"Certificate pinning added for: {', '.join(pinned_domains) or 'unknown domains'}",
                "old_value": "no pins" if not old_pins else f"pins: {sorted(old_pins)}",
                "new_value": f"pin-set with {sorted(added_pins)}",
                "severity": "high",
                "implication": (
                    "Old version was vulnerable to MITM attacks on the pinned domain(s). "
                    "Frida or a rogue CA could intercept all HTTPS traffic."
                ),
                "affected_domains": pinned_domains,
            })

        # Cleartext changed from allowed to disallowed
        old_ct = old_nsc.get("cleartext_permitted")
        new_ct = new_nsc.get("cleartext_permitted")
        if old_ct is True and new_ct is False:
            patches.append({
                "type": "cleartext_traffic_disabled",
                "detail": "cleartextTrafficPermitted changed from true to false",
                "old_value": "cleartextTrafficPermitted=true",
                "new_value": "cleartextTrafficPermitted=false",
                "severity": "high",
                "implication": (
                    "Old version allowed HTTP (unencrypted) traffic — "
                    "data was transmittable in cleartext, exposing it to network eavesdropping."
                ),
            })

        # User CA trust removed
        old_user_ca = old_nsc.get("user_certs_trusted", False)
        new_user_ca = new_nsc.get("user_certs_trusted", False)
        if old_user_ca and not new_user_ca:
            patches.append({
                "type": "user_ca_trust_removed",
                "detail": "User-installed CA trust removed from trust anchors",
                "old_value": "trust-anchors includes user certificates",
                "new_value": "trust-anchors does not include user certificates",
                "severity": "high",
                "implication": (
                    "Old version trusted user-installed CAs — an attacker could install "
                    "a rogue CA cert and intercept all HTTPS traffic without Frida."
                ),
            })

        # NSC cleartext on manifest-level (usesCleartextTraffic)
        old_manifest_ct = _attr(
            old_apk.get_android_manifest_xml().find("application") or ET.Element("x"),
            "usesCleartextTraffic",
        )
        new_manifest_ct = _attr(
            new_apk.get_android_manifest_xml().find("application") or ET.Element("x"),
            "usesCleartextTraffic",
        )
        if old_manifest_ct in ("true", "1") and new_manifest_ct in ("false", "0", None):
            patches.append({
                "type": "cleartext_traffic_flag_disabled",
                "detail": "android:usesCleartextTraffic changed from true to false/removed",
                "old_value": "usesCleartextTraffic=true",
                "new_value": f"usesCleartextTraffic={new_manifest_ct or 'not set (default false)'}",
                "severity": "high",
                "implication": (
                    "Old version had cleartext traffic explicitly enabled at the application level."
                ),
            })

        # Debuggable flag removed
        old_manifest_debug = _attr(
            old_apk.get_android_manifest_xml().find("application") or ET.Element("x"),
            "debuggable",
        )
        new_manifest_debug = _attr(
            new_apk.get_android_manifest_xml().find("application") or ET.Element("x"),
            "debuggable",
        )
        if old_manifest_debug in ("true", "1") and new_manifest_debug not in ("true", "1"):
            patches.append({
                "type": "debuggable_disabled",
                "detail": "android:debuggable changed from true to false/removed",
                "old_value": "debuggable=true",
                "new_value": f"debuggable={new_manifest_debug or 'not set (default false)'}",
                "severity": "high",
                "implication": (
                    "Old version was debuggable — any app on the device could attach "
                    "a debugger, extract memory, and bypass security controls."
                ),
            })

        # Backup flag removed
        old_backup = _attr(
            old_apk.get_android_manifest_xml().find("application") or ET.Element("x"),
            "allowBackup",
        )
        new_backup = _attr(
            new_apk.get_android_manifest_xml().find("application") or ET.Element("x"),
            "allowBackup",
        )
        if old_backup in ("true", "1") and new_backup in ("false", "0"):
            patches.append({
                "type": "backup_disabled",
                "detail": "android:allowBackup changed from true to false",
                "old_value": "allowBackup=true",
                "new_value": "allowBackup=false",
                "severity": "medium",
                "implication": (
                    "Old version allowed ADB backup of app data — "
                    "`adb backup -f backup.ab <package>` could extract private data."
                ),
            })

        # ------------------------------------------------------------------
        # 4. Dangerous API removal
        # ------------------------------------------------------------------
        for class_re, method_re, api_label in _DANGEROUS_APIS:
            old_sites = _collect_api_callsites(old_analysis, class_re, method_re)
            new_sites = _collect_api_callsites(new_analysis, class_re, method_re)
            removed_sites = old_sites - new_sites
            added_sites = new_sites - old_sites

            if removed_sites:
                patches.append({
                    "type": "dangerous_api_removed",
                    "api": api_label,
                    "old_value": f"{len(old_sites)} call site(s): {sorted(removed_sites)[:5]}",
                    "new_value": (
                        f"{len(new_sites)} call site(s) remaining"
                        if new_sites else "all call sites removed"
                    ),
                    "severity": "high",
                    "implication": (
                        f"Old version called {api_label} from {len(old_sites)} location(s). "
                        f"{len(removed_sites)} call site(s) were removed — "
                        f"likely closing a code injection or data exfiltration vector."
                    ),
                    "removed_callsites": sorted(removed_sites)[:10],
                })

            if added_sites and not removed_sites:
                # Purely new dangerous API — potential regression
                regressions.append({
                    "type": "dangerous_api_added",
                    "api": api_label,
                    "old_value": "not present",
                    "new_value": f"{len(added_sites)} call site(s): {sorted(added_sites)[:5]}",
                    "severity": "high",
                    "implication": (
                        f"New version introduces {api_label} at {len(added_sites)} location(s) "
                        f"not present in the old APK — potential regression."
                    ),
                })

        # ------------------------------------------------------------------
        # 5. Obfuscation change detection
        # ------------------------------------------------------------------
        old_ratio = _obfuscation_ratio(old_analysis)
        new_ratio = _obfuscation_ratio(new_analysis)
        ratio_delta = new_ratio - old_ratio

        if ratio_delta > 0.15:
            patches.append({
                "type": "obfuscation_increased",
                "detail": (
                    f"Obfuscated class ratio increased from "
                    f"{old_ratio:.1%} to {new_ratio:.1%}"
                ),
                "old_value": f"{old_ratio:.1%} obfuscated names",
                "new_value": f"{new_ratio:.1%} obfuscated names",
                "severity": "low",
                "implication": (
                    "New version applies significantly more aggressive obfuscation. "
                    "This may also mask other security changes, making reverse engineering harder."
                ),
            })
        elif ratio_delta < -0.15:
            regressions.append({
                "type": "obfuscation_decreased",
                "detail": (
                    f"Obfuscated class ratio decreased from "
                    f"{old_ratio:.1%} to {new_ratio:.1%}"
                ),
                "old_value": f"{old_ratio:.1%} obfuscated names",
                "new_value": f"{new_ratio:.1%} obfuscated names",
                "severity": "low",
                "implication": (
                    "New version has less obfuscation — class and method names more readable, "
                    "making it easier to reverse-engineer security logic."
                ),
            })

        # ------------------------------------------------------------------
        # Summary
        # ------------------------------------------------------------------
        def _count_sev(items: list[dict], sev: str) -> int:
            return sum(1 for p in items if p.get("severity") == sev)

        summary = {
            "total_patches": len(patches),
            "high_severity_patches": _count_sev(patches, "high"),
            "medium_severity_patches": _count_sev(patches, "medium"),
            "low_severity_patches": _count_sev(patches, "low"),
            "regressions": len(regressions),
        }

        return {
            "status": "ok",
            "data": {
                "old_version": {
                    "package": old_apk.get_package(),
                    "version_name": old_apk.get_androidversion_name(),
                    "version_code": old_apk.get_androidversion_code(),
                },
                "new_version": {
                    "package": new_apk.get_package(),
                    "version_name": new_apk.get_androidversion_name(),
                    "version_code": new_apk.get_androidversion_code(),
                },
                "security_patches": patches,
                "new_vulnerabilities": regressions,
                "summary": summary,
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk for both APKs first to create valid sessions.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"analyze_security_patches failed: {exc}",
            "suggestion": "Ensure both sessions are valid and APKs were loaded successfully.",
        }


# ---------------------------------------------------------------------------
# Tool 2 — find_patched_methods
# ---------------------------------------------------------------------------


@mcp.tool()
def find_patched_methods(
    session_id_old: str,
    session_id_new: str,
    class_name: str = "",
) -> dict:
    """Find methods that were modified between versions and analyze what changed.

    For each modified method, shows the old and new decompiled code side by side
    and highlights security-relevant differences.

    Args:
        session_id_old: Session ID for the older APK version (from load_apk).
        session_id_new: Session ID for the newer APK version (from load_apk).
        class_name:     Optional Java or Dalvik class name to restrict comparison.
                        When empty, all classes present in both versions are compared.
                        Large APKs may produce many results — prefer providing a
                        class_name or package prefix for focused analysis.

    Returns:
        A dict with status "ok" and data containing a list of patched_methods,
        each with old_source, new_source, a unified diff, and security_annotations.
    """
    try:
        old_session = get_session(session_id_old)
        new_session = get_session(session_id_new)
        old_analysis = old_session.analysis
        new_analysis = new_session.analysis

        # ------------------------------------------------------------------
        # Build class maps
        # ------------------------------------------------------------------
        filter_dalvik: str = ""
        if class_name:
            filter_dalvik = _normalize_class_name(class_name)

        def _build_method_map(analysis) -> dict[str, dict]:
            """Return {dalvik_class_name -> {method_key -> (fingerprint, method_analysis)}}."""
            result: dict[str, dict] = {}
            for ca in analysis.get_classes():
                if ca.is_external():
                    continue
                cname = ca.name
                if filter_dalvik and cname != filter_dalvik:
                    continue
                methods: dict[str, Any] = {}
                for ma in ca.get_methods():
                    key = f"{ma.name}{ma.descriptor}"
                    fp = _method_bytecode_fingerprint(ma)
                    methods[key] = (fp, ma, ca)
                if methods:
                    result[cname] = methods
            return result

        old_map = _build_method_map(old_analysis)
        new_map = _build_method_map(new_analysis)

        patched_methods: list[dict] = []
        compared_classes = set(old_map.keys()) & set(new_map.keys())

        for class_dalvik in sorted(compared_classes):
            old_methods = old_map[class_dalvik]
            new_methods = new_map[class_dalvik]

            for method_key in sorted(set(old_methods.keys()) & set(new_methods.keys())):
                old_fp, old_ma, old_ca = old_methods[method_key]
                new_fp, new_ma, new_ca = new_methods[method_key]

                if old_fp == new_fp:
                    continue  # Unchanged — skip

                # Decompile both sides
                old_src = _decompile_method_source(old_session, old_ca, old_ma)
                new_src = _decompile_method_source(new_session, new_ca, new_ma)

                # Unified diff
                old_lines = old_src.splitlines(keepends=True)
                new_lines = new_src.splitlines(keepends=True)
                diff_lines = list(
                    difflib.unified_diff(
                        old_lines,
                        new_lines,
                        fromfile=f"old/{_dalvik_to_java(class_dalvik)}.{method_key}",
                        tofile=f"new/{_dalvik_to_java(class_dalvik)}.{method_key}",
                        n=3,
                    )
                )
                unified_diff = "".join(diff_lines)

                # Security annotations
                annotations = _extract_security_annotations(old_src, new_src)

                # Parse method name + descriptor from method_key for output
                # method_key = methodName + descriptor e.g. "onCreate(Landroid/os/Bundle;)V"
                method_name_only = old_ma.name
                descriptor = old_ma.descriptor

                entry: dict = {
                    "class": _dalvik_to_java(class_dalvik),
                    "method": method_name_only,
                    "descriptor": descriptor,
                    "security_relevant": len(annotations) > 0,
                    "security_annotations": annotations,
                    "old_source": old_src,
                    "new_source": new_src,
                    "unified_diff": unified_diff,
                }
                patched_methods.append(entry)

        # Sort: security-relevant first, then alphabetically
        patched_methods.sort(key=lambda e: (not e["security_relevant"], e["class"], e["method"]))

        security_relevant_count = sum(1 for e in patched_methods if e["security_relevant"])

        return {
            "status": "ok",
            "data": {
                "class_filter": _dalvik_to_java(filter_dalvik) if filter_dalvik else None,
                "total_modified_methods": len(patched_methods),
                "security_relevant_count": security_relevant_count,
                "patched_methods": patched_methods,
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk for both APKs first to create valid sessions.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"find_patched_methods failed: {exc}",
            "suggestion": "Ensure both sessions are valid and APKs were loaded successfully.",
        }


# ---------------------------------------------------------------------------
# Tool 3 — find_vulnerability_window
# ---------------------------------------------------------------------------


@mcp.tool()
def find_vulnerability_window(session_id_old: str, session_id_new: str) -> dict:
    """Identify the exact vulnerability that was patched by analyzing what
    security checks exist in the new version but are absent in the old version.

    This is reverse patch analysis — if the new version adds a null check
    before loadUrl(), the old version has an unchecked loadUrl() vulnerability.

    For every security-relevant change found by analyze_security_patches, this
    tool constructs the implied vulnerability in the old version and generates
    PoC ADB/Frida commands to exploit it.

    Args:
        session_id_old: Session ID for the older (vulnerable) APK version.
        session_id_new: Session ID for the newer (patched) APK version.

    Returns:
        A dict with status "ok" and data containing a list of vulnerabilities,
        each with a description, severity, cve_type classification, and poc_commands.
    """
    try:
        old_session = get_session(session_id_old)
        get_session(session_id_new)  # validate the new session exists
        old_apk = old_session.apk

        package_name = old_apk.get_package()

        # Run the full patch analysis to get all changes
        patch_result = analyze_security_patches(session_id_old, session_id_new)
        if patch_result.get("status") != "ok":
            return patch_result

        patches = patch_result["data"].get("security_patches", [])
        regressions = patch_result["data"].get("new_vulnerabilities", [])

        # Find the first exported component for PoC fallback
        old_comps = _get_components(old_apk)
        exported_components = [
            c for c in old_comps.values()
            if c["exported"] and c["tag"] in ("activity", "service", "receiver")
        ]
        default_component = (
            exported_components[0]["name"] if exported_components else f"{package_name}.MainActivity"
        )

        vulnerabilities: list[dict] = []

        for patch in patches:
            ptype = patch.get("type", "")
            severity = patch.get("severity", "medium")

            # ----------------------------------------------------------------
            # Exposed component vulnerability
            # ----------------------------------------------------------------
            if ptype in ("component_unexported", "component_permission_added"):
                comp_name = patch.get("component", default_component)
                tag = patch.get("tag", "activity")
                poc_cmds = _poc_for_exported_component(package_name, tag, comp_name)
                vuln_type = "Exposed Component (Improper Access Control)"
                cve_class = "CWE-926: Improper Export of Android Application Components"
                description = (
                    f"The {tag} '{comp_name}' was exported without any permission guard "
                    f"in the old version. Any installed application (or ADB) could start "
                    f"it directly, bypassing authentication and authorization controls. "
                    f"Patch fixed by: {patch.get('new_value', 'see patch detail')}."
                )

                vulnerabilities.append({
                    "patch_type": ptype,
                    "vulnerability_type": vuln_type,
                    "cwe": cve_class,
                    "severity": severity,
                    "component": comp_name,
                    "description": description,
                    "old_version_behavior": patch.get("old_value"),
                    "new_version_behavior": patch.get("new_value"),
                    "poc_commands": poc_cmds,
                    "exploitation_notes": (
                        "No special permissions required. "
                        "Install any APK on the device and call am start / startActivity()."
                    ),
                })

            # ----------------------------------------------------------------
            # MITM / TLS pinning vulnerability
            # ----------------------------------------------------------------
            elif ptype in ("tls_pinning_added", "user_ca_trust_removed"):
                affected_domains: list[str] = patch.get("affected_domains", [])
                if not affected_domains:
                    # Try to extract from detail field
                    detail = patch.get("detail", "")
                    m = re.search(r"for:\s*(.+)$", detail)
                    affected_domains = [m.group(1)] if m else ["api." + (package_name.split(".")[-2] if "." in package_name else "example.com")]

                for domain in affected_domains[:3]:  # Cap at 3 for brevity
                    poc_cmds = _poc_for_mitm(domain)
                    vulnerabilities.append({
                        "patch_type": ptype,
                        "vulnerability_type": "MITM / TLS Certificate Not Pinned",
                        "cwe": "CWE-295: Improper Certificate Validation",
                        "severity": severity,
                        "component": f"HTTPS traffic to {domain}",
                        "description": (
                            f"Old version did not pin certificates for '{domain}'. "
                            f"An attacker with a trusted or user-installed CA could perform "
                            f"a Man-in-the-Middle attack and decrypt all HTTPS traffic. "
                            f"Patch fixed by: {patch.get('new_value', 'pinning added')}."
                        ),
                        "old_version_behavior": patch.get("old_value"),
                        "new_version_behavior": patch.get("new_value"),
                        "poc_commands": poc_cmds,
                        "exploitation_notes": (
                            "Set up mitmproxy or Burp Suite. "
                            "On pre-patched APK: install proxy CA, route traffic. "
                            "On post-patched APK: requires Frida SSL bypass."
                        ),
                    })

            # ----------------------------------------------------------------
            # Cleartext traffic vulnerability
            # ----------------------------------------------------------------
            elif ptype in ("cleartext_traffic_disabled", "cleartext_traffic_flag_disabled"):
                vulnerabilities.append({
                    "patch_type": ptype,
                    "vulnerability_type": "Cleartext HTTP Traffic Allowed",
                    "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
                    "severity": severity,
                    "component": "Network layer",
                    "description": (
                        "Old version explicitly permitted cleartext (HTTP) traffic. "
                        "Any data sent over HTTP can be intercepted without a rogue CA — "
                        "a passive network monitor (Wireshark, tcpdump) suffices."
                    ),
                    "old_version_behavior": patch.get("old_value"),
                    "new_version_behavior": patch.get("new_value"),
                    "poc_commands": [
                        "# Capture with tcpdump on the same network:",
                        "sudo tcpdump -i any -w capture.pcap host <device_ip>",
                        "# Or on device (root):",
                        "adb shell tcpdump -i wlan0 -w /sdcard/capture.pcap",
                        "# Then open in Wireshark and filter: http",
                    ],
                    "exploitation_notes": (
                        "No certificate manipulation required. "
                        "A network-adjacent attacker can passively capture plaintext traffic."
                    ),
                })

            # ----------------------------------------------------------------
            # Debuggable vulnerability
            # ----------------------------------------------------------------
            elif ptype == "debuggable_disabled":
                vulnerabilities.append({
                    "patch_type": ptype,
                    "vulnerability_type": "Debuggable Application",
                    "cwe": "CWE-215: Insertion of Sensitive Information Into Debugging Code",
                    "severity": severity,
                    "component": "Application (debuggable=true)",
                    "description": (
                        "Old version had android:debuggable=true. "
                        "Any app or ADB can attach a JDWP debugger, "
                        "step through code, extract secrets from memory, "
                        "and bypass runtime security checks."
                    ),
                    "old_version_behavior": "debuggable=true",
                    "new_version_behavior": "debuggable=false",
                    "poc_commands": [
                        f"adb shell run-as {package_name} ls -la",
                        "adb jdwp  # find PID",
                        "adb forward tcp:8700 jdwp:<pid>",
                        "jdb -attach localhost:8700",
                        "# Or: Android Studio debugger attach to process",
                    ],
                    "exploitation_notes": (
                        "Works via ADB without root. "
                        "`adb shell run-as` lets you read the app's private data directory."
                    ),
                })

            # ----------------------------------------------------------------
            # Backup vulnerability
            # ----------------------------------------------------------------
            elif ptype == "backup_disabled":
                vulnerabilities.append({
                    "patch_type": ptype,
                    "vulnerability_type": "ADB Backup Allowed",
                    "cwe": "CWE-530: Exposure of Backup File to an Unauthorized Control Sphere",
                    "severity": severity,
                    "component": "Application data",
                    "description": (
                        "Old version had android:allowBackup=true. "
                        "An attacker with USB access can extract the entire app data "
                        "directory using `adb backup`, including databases, tokens, and keys."
                    ),
                    "old_version_behavior": "allowBackup=true",
                    "new_version_behavior": "allowBackup=false",
                    "poc_commands": [
                        f"adb backup -noapk -f {package_name}_backup.ab {package_name}",
                        "# Extract: dd if=backup.ab bs=24 skip=1 | python -c \"import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))\" | tar xvf -",
                        f"# Or use Android Backup Extractor: java -jar abe.jar unpack {package_name}_backup.ab backup.tar",
                    ],
                    "exploitation_notes": (
                        "Requires USB access and ADB enabled. "
                        "No root needed. The phone must be unlocked and ADB authorized."
                    ),
                })

            # ----------------------------------------------------------------
            # Dangerous API vulnerability
            # ----------------------------------------------------------------
            elif ptype == "dangerous_api_removed":
                api_label = patch.get("api", "dangerous API")
                removed_callsites = patch.get("removed_callsites", [])

                # Find the best exported component to reach the vulnerable code from
                poc_comp = default_component
                for site in removed_callsites:
                    class_part = site.split("->")[0] if "->" in site else site
                    for comp in exported_components:
                        if comp["name"].split(".")[-1] in class_part:
                            poc_comp = comp["name"]
                            break

                poc_cmds = _poc_for_dangerous_api(api_label, package_name, poc_comp)

                # Map API to CWE
                api_cwe_map = {
                    "Runtime.exec": "CWE-78: OS Command Injection",
                    "addJavascriptInterface": "CWE-749: Exposed Dangerous Method or Function",
                    "setAllowUniversalAccessFromFileURLs": "CWE-200: Exposure of Sensitive Information",
                    "rawQuery": "CWE-89: SQL Injection",
                    "execSQL": "CWE-89: SQL Injection",
                    "DexClassLoader": "CWE-470: Use of Externally-Controlled Input to Select Classes",
                    "loadUrl": "CWE-601: URL Redirection to Untrusted Site",
                }
                cwe = "CWE-749: Exposed Dangerous Method or Function"
                for key, val in api_cwe_map.items():
                    if key in api_label:
                        cwe = val
                        break

                vulnerabilities.append({
                    "patch_type": ptype,
                    "vulnerability_type": f"Dangerous API: {api_label}",
                    "cwe": cwe,
                    "severity": severity,
                    "component": f"{len(removed_callsites)} method(s): {removed_callsites[:3]}",
                    "description": (
                        f"Old version called {api_label} from {len(removed_callsites)} location(s). "
                        f"If user-controlled data could reach these call sites, it enabled "
                        f"the corresponding attack. The new version removed these call sites."
                    ),
                    "old_version_behavior": patch.get("old_value"),
                    "new_version_behavior": patch.get("new_value"),
                    "poc_commands": poc_cmds,
                    "exploitation_notes": (
                        "Check if any exported component accepts Intent extras that flow "
                        "into the removed API without sanitization. "
                        "Use find_patched_methods to see the exact code change."
                    ),
                })

            # ----------------------------------------------------------------
            # Dangerous permission removed
            # ----------------------------------------------------------------
            elif ptype == "dangerous_permission_removed":
                perm = patch.get("permission", "unknown")
                vulnerabilities.append({
                    "patch_type": ptype,
                    "vulnerability_type": "Overly Broad Permission Scope",
                    "cwe": "CWE-732: Incorrect Permission Assignment for Critical Resource",
                    "severity": severity,
                    "component": f"Permission: {perm}",
                    "description": (
                        f"Old version declared '{perm}' which granted the app broad access "
                        f"to sensitive data. The permission was removed in the new version, "
                        f"reducing the blast radius of any compromise."
                    ),
                    "old_version_behavior": patch.get("old_value"),
                    "new_version_behavior": patch.get("new_value"),
                    "poc_commands": [
                        "# Verify the old APK has the permission:",
                        f"aapt dump permissions <old_apk>.apk | grep '{perm}'",
                        f"# At runtime, the old APK can access: {perm}",
                    ],
                    "exploitation_notes": (
                        "Compromise of the old app version would grant the attacker "
                        f"access to resources protected by '{perm}'."
                    ),
                })

            # ----------------------------------------------------------------
            # NSC added
            # ----------------------------------------------------------------
            elif ptype == "nsc_added":
                vulnerabilities.append({
                    "patch_type": ptype,
                    "vulnerability_type": "No Network Security Configuration",
                    "cwe": "CWE-295: Improper Certificate Validation",
                    "severity": severity,
                    "component": "Network Security Config",
                    "description": (
                        "Old version had no network_security_config.xml. "
                        "On API < 24 this means cleartext traffic was permitted; "
                        "on all API levels user-installed CAs were trusted by default, "
                        "enabling MITM with a rogue CA without requiring Frida."
                    ),
                    "old_version_behavior": patch.get("old_value"),
                    "new_version_behavior": patch.get("new_value"),
                    "poc_commands": [
                        "# Install rogue CA on test device:",
                        "adb push attacker_ca.crt /sdcard/",
                        "# Settings > Security > Install from storage",
                        "# Then route through mitmproxy — all HTTPS traffic decrypted",
                        "mitmproxy --mode transparent",
                    ],
                    "exploitation_notes": (
                        "Works on non-rooted devices. "
                        "No Frida or code instrumentation needed on the old APK."
                    ),
                })

        # ------------------------------------------------------------------
        # Reverse analysis from method-level patches
        # ------------------------------------------------------------------
        # Run find_patched_methods for security-relevant method changes
        method_result = find_patched_methods(session_id_old, session_id_new)
        if method_result.get("status") == "ok":
            for entry in method_result["data"].get("patched_methods", []):
                if not entry.get("security_relevant"):
                    continue
                for annotation in entry.get("security_annotations", []):
                    ann_type = annotation.get("type", "")
                    ann_label = annotation.get("label", "")
                    ann_kind = annotation.get("kind", "")
                    examples = annotation.get("examples", [])

                    class_name_java = entry.get("class", "unknown")
                    method_name = entry.get("method", "unknown")
                    descriptor = entry.get("descriptor", "")
                    location = f"{class_name_java}.{method_name}{descriptor}"

                    if ann_type == "input_validation_added":
                        vuln_desc = (
                            f"Method '{method_name}' in '{class_name_java}' was modified to add "
                            f"{ann_label}. The old version lacked this check. "
                            f"Examples of added code: {examples[:2]}"
                        )
                        cwe = "CWE-20: Improper Input Validation"
                        if ann_kind == "null_check":
                            cwe = "CWE-476: NULL Pointer Dereference"
                        elif ann_kind == "regex_validation":
                            cwe = "CWE-20: Improper Input Validation"
                        elif ann_kind == "uri_validation":
                            cwe = "CWE-601: URL Redirection to Untrusted Site"

                        vulnerabilities.append({
                            "patch_type": "input_validation_added",
                            "vulnerability_type": f"Missing Input Validation ({ann_label})",
                            "cwe": cwe,
                            "severity": annotation.get("severity", "medium"),
                            "component": location,
                            "description": vuln_desc,
                            "old_version_behavior": f"No {ann_label} before sensitive operation",
                            "new_version_behavior": f"{ann_label} added",
                            "poc_commands": [
                                f"# Call {method_name} with invalid/null input via exported component:",
                                f"adb shell am start -n {package_name}/{default_component} --es param ''",
                                "# Or send null-valued Intent extra and observe crash in old APK",
                                f"# Use find_patched_methods to see the exact diff for {location}",
                            ],
                            "exploitation_notes": (
                                "Confirm the method is reachable from an exported component "
                                "or a broadcast receiver. Trace the taint path from Intent extras "
                                f"to {method_name} using get_xrefs_to."
                            ),
                        })

                    elif ann_type == "dangerous_api_removed":
                        api = annotation.get("api", "dangerous API")
                        vulnerabilities.append({
                            "patch_type": "dangerous_api_removed_in_method",
                            "vulnerability_type": f"Dangerous API in patched method: {api}",
                            "cwe": "CWE-749: Exposed Dangerous Method or Function",
                            "severity": annotation.get("severity", "high"),
                            "component": location,
                            "description": (
                                f"Method '{method_name}' in '{class_name_java}' "
                                f"previously called {api}, which was removed in the new version. "
                                f"If this method was reachable with attacker-controlled input, "
                                f"the call could be exploited."
                            ),
                            "old_version_behavior": f"Called {api}",
                            "new_version_behavior": f"{api} removed",
                            "poc_commands": _poc_for_dangerous_api(api, package_name, default_component),
                            "exploitation_notes": (
                                f"Use get_xrefs_to on '{class_name_java}' '{method_name}' "
                                f"to determine if an exported component can reach this method."
                            ),
                        })

                    elif ann_type == "exception_handling_added":
                        vulnerabilities.append({
                            "patch_type": "exception_handling_added",
                            "vulnerability_type": "Unhandled Exception Around Security Operation",
                            "cwe": "CWE-390: Detection of Error Condition Without Action",
                            "severity": annotation.get("severity", "medium"),
                            "component": location,
                            "description": (
                                f"Method '{method_name}' in '{class_name_java}' had no "
                                f"exception handling for security-sensitive code. "
                                f"{annotation.get('label', 'try-catch')} was added. "
                                f"The old version may crash or silently fail in an insecure state "
                                f"when errors occur."
                            ),
                            "old_version_behavior": "No exception handling around security operation",
                            "new_version_behavior": "try-catch added",
                            "poc_commands": [
                                "# Trigger the exception path in the old APK:",
                                f"# Provide malformed input to {method_name} and observe behavior",
                                f"adb shell am start -n {package_name}/{default_component} --es bad_input 'AAAA' * 1000",
                            ],
                            "exploitation_notes": (
                                "Exception-based bypasses: if the security check throws and is "
                                "not caught, some paths proceed without enforcement. "
                                "Fuzz the method's inputs in the old APK."
                            ),
                        })

        # Sort by severity
        _sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        vulnerabilities.sort(key=lambda v: _sev_order.get(v.get("severity", "info"), 3))

        return {
            "status": "ok",
            "data": {
                "package": package_name,
                "old_version": old_apk.get_androidversion_name(),
                "analysis_note": (
                    "These vulnerabilities describe the security state of the OLD (pre-patch) APK. "
                    "Use the PoC commands against the old APK version only. "
                    "Always obtain authorization before testing."
                ),
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "regressions_in_new_version": regressions,
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk for both APKs first to create valid sessions.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"find_vulnerability_window failed: {exc}",
            "suggestion": "Ensure both sessions are valid and APKs were loaded successfully.",
        }
