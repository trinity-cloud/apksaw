"""APK diffing tools for comparing two versions of an Android application."""

import re
from typing import Any

from apksaw.server import mcp
from apksaw.session import get_session

# Android manifest XML namespace
_ANDROID_NS = "http://schemas.android.com/apk/res/android"

# URL/endpoint detection patterns (compiled once at import time)
_RE_HTTP_URL = re.compile(r"^https?://", re.IGNORECASE)
_RE_API_ENDPOINT = re.compile(
    r"^https?://[^/]+/(?:api|v\d+|graphql|rest|rpc|grpc)[/\w\-]*",
    re.IGNORECASE,
)
_SECRETS_PATTERNS = [
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                          # Google API key
    re.compile(r"AKIA[0-9A-Z]{16}"),                                  # AWS key
    re.compile(r"[Aa]pi[_\-]?[Kk]ey\s*[=:]\s*['\"]([A-Za-z0-9]{16,})['\"]"),
    re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]", re.IGNORECASE),
    re.compile(r"Bearer [A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
]


# ---------------------------------------------------------------------------
# Shared internal helpers
# ---------------------------------------------------------------------------


def _attr(element, name: str, default: Any = None) -> Any:
    """Get an android: namespaced attribute from an lxml element."""
    return element.get(f"{{{_ANDROID_NS}}}{name}", default)


def _get_permissions(apk) -> set[str]:
    """Return the full set of uses-permission names from an APK object."""
    perms = set(apk.get_permissions())
    # Also capture uses-permission-sdk-23 elements
    manifest_elem = apk.get_android_manifest_xml()
    for p in manifest_elem.findall("uses-permission-sdk-23"):
        name = _attr(p, "name")
        if name:
            perms.add(name)
    return perms


def _get_components(apk) -> dict[str, dict]:
    """Return a flat dict keyed by (tag, name) -> component attribute dict.

    Covers activities, activity-aliases, services, receivers, and providers.
    """
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

            # Collect intent filter actions for URI-scheme detection
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
                "permission": _attr(elem, "permission"),
                "intent_filters": filters,
            }

    return components


def _get_all_strings(session) -> set[str]:
    """Return all string values from the DEX string pool."""
    return {sa.get_value() for sa in session.analysis.get_strings()}


def _is_url(s: str) -> bool:
    return bool(_RE_HTTP_URL.match(s))


def _is_api_endpoint(s: str) -> bool:
    return bool(_RE_API_ENDPOINT.match(s))


def _is_potential_secret(s: str) -> bool:
    return any(p.search(s) for p in _SECRETS_PATTERNS)


def _class_fingerprint(class_analysis) -> int:
    """Compute a Method Signature Hash for a class.

    The fingerprint is the hash of the frozenset of (descriptor, access_flags)
    tuples for every method defined in the class.  Classes with the same MSH
    but different names are treated as renamed (obfuscation change).
    """
    sigs = frozenset(
        (m.get_method().get_descriptor(), m.get_method().get_access_flags())
        for m in class_analysis.get_methods()
        if m.get_method() is not None
    )
    return hash(sigs)


def _scan_manifest_findings(session_id: str) -> list[dict]:
    """Run scan_manifest_security and return just the findings list."""
    # Import lazily to avoid circular imports at module load time
    from apksaw.tools.security import scan_manifest_security
    result = scan_manifest_security(session_id)
    if result.get("status") != "ok":
        return []
    return result["data"].get("findings", [])


def _finding_key(finding: dict) -> str:
    """Stable identity key for a security finding (title + location)."""
    return f"{finding.get('title', '')}||{finding.get('location', '')}"


# ---------------------------------------------------------------------------
# Tool 1 – diff_apks
# ---------------------------------------------------------------------------


@mcp.tool()
def diff_apks(session_id_old: str, session_id_new: str) -> dict:
    """High-level comparison of two APK versions. Returns summary of all changes.

    Compares permissions, class sets, components, string URLs, and signing
    certificates between two previously loaded sessions.  Class comparison
    uses Method Signature Hashing (MSH) to remain meaningful even when
    obfuscated class names differ between releases.

    Args:
        session_id_old: Session ID for the older APK version (from load_apk).
        session_id_new: Session ID for the newer APK version (from load_apk).

    Returns:
        A dict with status "ok" and data containing metadata for both APKs and
        a summary section covering permissions, classes, components, URLs, and
        signing changes.
    """
    try:
        old_session = get_session(session_id_old)
        new_session = get_session(session_id_new)
        old_apk = old_session.apk
        new_apk = new_session.apk

        # -- Permissions -------------------------------------------------------
        old_perms = _get_permissions(old_apk)
        new_perms = _get_permissions(new_apk)
        perms_added = sorted(new_perms - old_perms)
        perms_removed = sorted(old_perms - new_perms)

        # -- Components --------------------------------------------------------
        old_components = _get_components(old_apk)
        new_components = _get_components(new_apk)
        comp_added = sorted(k for k in new_components if k not in old_components)
        comp_removed = sorted(k for k in old_components if k not in new_components)

        # -- Classes (MSH-aware) ----------------------------------------------
        old_analysis = old_session.analysis
        new_analysis = new_session.analysis

        old_classes: dict[str, int] = {}   # dalvik_name -> fingerprint
        for ca in old_analysis.get_classes():
            if not ca.is_external():
                old_classes[ca.name] = _class_fingerprint(ca)

        new_classes: dict[str, int] = {}
        for ca in new_analysis.get_classes():
            if not ca.is_external():
                new_classes[ca.name] = _class_fingerprint(ca)

        old_fp_to_names: dict[int, list[str]] = {}
        for name, fp in old_classes.items():
            old_fp_to_names.setdefault(fp, []).append(name)

        new_fp_to_names: dict[int, list[str]] = {}
        for name, fp in new_classes.items():
            new_fp_to_names.setdefault(fp, []).append(name)

        old_fps = set(old_classes.values())
        new_fps = set(new_classes.values())
        old_names = set(old_classes.keys())
        new_names = set(new_classes.keys())

        # Renamed: same fingerprint, name only exists in one version
        renamed_count = sum(
            1 for fp in (old_fps & new_fps)
            if set(old_fp_to_names.get(fp, [])) != set(new_fp_to_names.get(fp, []))
        )
        # Modified: same name, different fingerprint
        modified_count = sum(
            1 for name in (old_names & new_names)
            if old_classes[name] != new_classes[name]
        )
        # Truly added / removed (no MSH match at all)
        truly_added = len(new_fps - old_fps)
        truly_removed = len(old_fps - new_fps)

        # -- URLs -------------------------------------------------------------
        old_strings = _get_all_strings(old_session)
        new_strings = _get_all_strings(new_session)
        old_urls = {s for s in old_strings if _is_url(s)}
        new_urls = {s for s in new_strings if _is_url(s)}
        added_urls = sorted(new_urls - old_urls)
        removed_urls = sorted(old_urls - new_urls)

        # -- Signing ----------------------------------------------------------
        old_certs = old_apk.get_certificates()
        new_certs = new_apk.get_certificates()
        try:
            old_cert_hashes = {c.sha256.hex() for c in old_certs}
            new_cert_hashes = {c.sha256.hex() for c in new_certs}
        except Exception:
            old_cert_hashes = set()
            new_cert_hashes = set()
        signing_changed = old_cert_hashes != new_cert_hashes

        return {
            "status": "ok",
            "data": {
                "old": {
                    "package": old_apk.get_package(),
                    "version_name": old_apk.get_androidversion_name(),
                    "version_code": old_apk.get_androidversion_code(),
                    "sha256": old_session.sha256,
                },
                "new": {
                    "package": new_apk.get_package(),
                    "version_name": new_apk.get_androidversion_name(),
                    "version_code": new_apk.get_androidversion_code(),
                    "sha256": new_session.sha256,
                },
                "summary": {
                    "permissions_added": perms_added,
                    "permissions_removed": perms_removed,
                    "classes_added": truly_added,
                    "classes_removed": truly_removed,
                    "classes_modified": modified_count,
                    "classes_renamed": renamed_count,
                    "components_added": comp_added,
                    "components_removed": comp_removed,
                    "new_urls": added_urls,
                    "removed_urls": removed_urls,
                    "signing_changed": signing_changed,
                },
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
            "message": f"diff_apks failed: {exc}",
            "suggestion": "Ensure both sessions are valid and the APKs were loaded successfully.",
        }


# ---------------------------------------------------------------------------
# Tool 2 – diff_manifest
# ---------------------------------------------------------------------------


@mcp.tool()
def diff_manifest(session_id_old: str, session_id_new: str) -> dict:
    """Detailed manifest comparison: permissions, components, and attributes.

    Compares the AndroidManifest.xml of two APK versions and reports:

    - Permissions added / removed
    - Components added, removed, or modified (including exported-status changes)
    - Application-level attribute changes (debuggable, allowBackup,
      networkSecurityConfig, usesCleartextTraffic, etc.)
    - SDK version changes (minSdk, targetSdk)
    - New intent-filter actions and URI schemes

    Args:
        session_id_old: Session ID for the older APK version (from load_apk).
        session_id_new: Session ID for the newer APK version (from load_apk).

    Returns:
        A dict with status "ok" and detailed manifest diff data.
    """
    try:
        old_session = get_session(session_id_old)
        new_session = get_session(session_id_new)
        old_apk = old_session.apk
        new_apk = new_session.apk

        # -- Permissions -------------------------------------------------------
        old_perms = _get_permissions(old_apk)
        new_perms = _get_permissions(new_apk)

        # -- SDK versions ------------------------------------------------------
        def _sdk(apk, getter) -> int:
            try:
                return int(getattr(apk, getter)() or 0)
            except (TypeError, ValueError):
                return 0

        sdk_changes: dict[str, dict] = {}
        for attr_name, getter in [
            ("min_sdk", "get_min_sdk_version"),
            ("target_sdk", "get_target_sdk_version"),
        ]:
            old_val = _sdk(old_apk, getter)
            new_val = _sdk(new_apk, getter)
            if old_val != new_val:
                sdk_changes[attr_name] = {"old": old_val, "new": new_val}

        # -- Application attributes -------------------------------------------
        _APP_ATTRS = (
            "debuggable",
            "allowBackup",
            "usesCleartextTraffic",
            "networkSecurityConfig",
            "testOnly",
            "extractNativeLibs",
            "requestLegacyExternalStorage",
            "preserveLegacyExternalStorage",
            "appComponentFactory",
        )

        def _get_app_attrs(apk) -> dict[str, str]:
            manifest_elem = apk.get_android_manifest_xml()
            app_elem = manifest_elem.find("application")
            if app_elem is None:
                return {}
            return {
                a: _attr(app_elem, a)
                for a in _APP_ATTRS
                if _attr(app_elem, a) is not None
            }

        old_app_attrs = _get_app_attrs(old_apk)
        new_app_attrs = _get_app_attrs(new_apk)

        app_attr_changes: list[dict] = []
        all_attr_keys = set(old_app_attrs) | set(new_app_attrs)
        for key in sorted(all_attr_keys):
            old_val = old_app_attrs.get(key)
            new_val = new_app_attrs.get(key)
            if old_val != new_val:
                app_attr_changes.append({
                    "attribute": key,
                    "old": old_val,
                    "new": new_val,
                })

        # -- Components --------------------------------------------------------
        old_comps = _get_components(old_apk)
        new_comps = _get_components(new_apk)

        added_components: list[dict] = [
            new_comps[k] for k in sorted(new_comps) if k not in old_comps
        ]
        removed_components: list[dict] = [
            old_comps[k] for k in sorted(old_comps) if k not in new_comps
        ]
        modified_components: list[dict] = []
        for key in sorted(set(old_comps) & set(new_comps)):
            old_c = old_comps[key]
            new_c = new_comps[key]
            changes: dict[str, Any] = {}

            if old_c["exported"] != new_c["exported"]:
                changes["exported"] = {"old": old_c["exported"], "new": new_c["exported"]}
            if old_c.get("permission") != new_c.get("permission"):
                changes["permission"] = {
                    "old": old_c.get("permission"),
                    "new": new_c.get("permission"),
                }

            # Intent filter action / scheme changes
            def _collect_actions(comp: dict) -> set[str]:
                return {
                    action
                    for f in comp["intent_filters"]
                    for action in f["actions"]
                    if action
                }

            def _collect_schemes(comp: dict) -> set[str]:
                return {
                    scheme
                    for f in comp["intent_filters"]
                    for scheme in f["schemes"]
                    if scheme
                }

            old_actions = _collect_actions(old_c)
            new_actions = _collect_actions(new_c)
            if old_actions != new_actions:
                changes["intent_filter_actions"] = {
                    "added": sorted(new_actions - old_actions),
                    "removed": sorted(old_actions - new_actions),
                }

            old_schemes = _collect_schemes(old_c)
            new_schemes = _collect_schemes(new_c)
            if old_schemes != new_schemes:
                changes["uri_schemes"] = {
                    "added": sorted(new_schemes - old_schemes),
                    "removed": sorted(old_schemes - new_schemes),
                }

            if changes:
                modified_components.append({
                    "name": old_c["name"],
                    "tag": old_c["tag"],
                    "changes": changes,
                })

        # -- New URI schemes globally ------------------------------------------
        def _all_schemes(apk) -> set[str]:
            manifest_elem = apk.get_android_manifest_xml()
            app_elem = manifest_elem.find("application")
            schemes: set[str] = set()
            if app_elem is None:
                return schemes
            for tag in ("activity", "activity-alias", "service", "receiver"):
                for elem in app_elem.findall(tag):
                    for f in elem.findall("intent-filter"):
                        for d in f.findall("data"):
                            s = _attr(d, "scheme")
                            if s:
                                schemes.add(s)
            return schemes

        old_schemes = _all_schemes(old_apk)
        new_schemes = _all_schemes(new_apk)

        return {
            "status": "ok",
            "data": {
                "permissions": {
                    "added": sorted(new_perms - old_perms),
                    "removed": sorted(old_perms - new_perms),
                    "unchanged": sorted(old_perms & new_perms),
                },
                "sdk_changes": sdk_changes,
                "application_attributes": app_attr_changes,
                "components": {
                    "added": added_components,
                    "removed": removed_components,
                    "modified": modified_components,
                },
                "uri_schemes": {
                    "added": sorted(new_schemes - old_schemes),
                    "removed": sorted(old_schemes - new_schemes),
                },
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
            "message": f"diff_manifest failed: {exc}",
            "suggestion": "Ensure both sessions are valid and the APKs were loaded successfully.",
        }


# ---------------------------------------------------------------------------
# Tool 3 – diff_classes
# ---------------------------------------------------------------------------


@mcp.tool()
def diff_classes(
    session_id_old: str,
    session_id_new: str,
    package_filter: str = "",
) -> dict:
    """Compare class sets between APK versions using Method Signature Hashing.

    Method Signature Hashing (MSH) makes the comparison resilient to obfuscation:
    each class is fingerprinted by the frozenset of (descriptor, access_flags)
    tuples for all its methods.  Classes that match by MSH but have different
    names are reported as *renamed* rather than added/removed.

    Classification:
    - **renamed**: same MSH, different name (obfuscation-only change)
    - **added**: new MSH that did not exist in the old APK
    - **removed**: old MSH that no longer exists in the new APK
    - **modified**: same class name but different MSH (implementation changed)

    Args:
        session_id_old:  Session ID for the older APK version (from load_apk).
        session_id_new:  Session ID for the newer APK version (from load_apk).
        package_filter:  Optional Java-style package prefix to restrict results
                         (e.g. "com.example.app").  Empty string = include all.

    Returns:
        A dict with status "ok" and data containing lists of added, removed,
        modified, and renamed classes with counts.
    """
    try:
        old_session = get_session(session_id_old)
        new_session = get_session(session_id_new)

        def _build_class_map(session, pkg_filter: str) -> dict[str, int]:
            """Return {dalvik_name: fingerprint} for all non-external classes."""
            result: dict[str, int] = {}
            for ca in session.analysis.get_classes():
                if ca.is_external():
                    continue
                name: str = ca.name  # Dalvik format: Lcom/example/Foo;
                if pkg_filter:
                    # Convert to Java style for prefix matching
                    java_name = name[1:-1].replace("/", ".") if (
                        name.startswith("L") and name.endswith(";")
                    ) else name
                    if not java_name.startswith(pkg_filter):
                        continue
                result[name] = _class_fingerprint(ca)
            return result

        old_map = _build_class_map(old_session, package_filter)
        new_map = _build_class_map(new_session, package_filter)

        old_names = set(old_map.keys())
        new_names = set(new_map.keys())
        old_fps = set(old_map.values())
        new_fps = set(new_map.values())

        # Invert: fingerprint -> list of class names
        old_fp_to_names: dict[int, list[str]] = {}
        for name, fp in old_map.items():
            old_fp_to_names.setdefault(fp, []).append(name)

        new_fp_to_names: dict[int, list[str]] = {}
        for name, fp in new_map.items():
            new_fp_to_names.setdefault(fp, []).append(name)

        # -- Modified: same name, fingerprint changed --------------------------
        modified: list[dict] = []
        for name in sorted(old_names & new_names):
            if old_map[name] != new_map[name]:
                modified.append({
                    "class": name,
                    "old_fingerprint": old_map[name],
                    "new_fingerprint": new_map[name],
                })

        # -- Renamed: matching fingerprint, differing name sets ----------------
        renamed: list[dict] = []
        for fp in sorted(old_fps & new_fps):
            old_ns = sorted(old_fp_to_names.get(fp, []))
            new_ns = sorted(new_fp_to_names.get(fp, []))
            if old_ns != new_ns:
                renamed.append({
                    "fingerprint": fp,
                    "old_names": old_ns,
                    "new_names": new_ns,
                })

        # -- Truly added: fingerprint in new but not old -----------------------
        added_fps = new_fps - old_fps
        added: list[str] = sorted(
            name
            for fp in added_fps
            for name in new_fp_to_names.get(fp, [])
        )

        # -- Truly removed: fingerprint in old but not new ---------------------
        removed_fps = old_fps - new_fps
        removed: list[str] = sorted(
            name
            for fp in removed_fps
            for name in old_fp_to_names.get(fp, [])
        )

        return {
            "status": "ok",
            "data": {
                "package_filter": package_filter or None,
                "counts": {
                    "added": len(added),
                    "removed": len(removed),
                    "modified": len(modified),
                    "renamed": len(renamed),
                    "old_total": len(old_map),
                    "new_total": len(new_map),
                },
                "added": added,
                "removed": removed,
                "modified": modified,
                "renamed": renamed,
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
            "message": f"diff_classes failed: {exc}",
            "suggestion": "Ensure both sessions are valid and the APKs were loaded successfully.",
        }


# ---------------------------------------------------------------------------
# Tool 4 – diff_strings
# ---------------------------------------------------------------------------


@mcp.tool()
def diff_strings(
    session_id_old: str,
    session_id_new: str,
    filter: str = "",  # noqa: A002
) -> dict:
    """Compare string pools between two APK versions.

    Highlights strings that are new in the newer version by categorizing them
    as URLs, API endpoints, potential secrets, or other.  Also reports strings
    that were removed.

    An optional *filter* regex is applied to both the added and removed string
    sets before categorization.

    Args:
        session_id_old: Session ID for the older APK version (from load_apk).
        session_id_new: Session ID for the newer APK version (from load_apk).
        filter:         Optional Python regex to restrict which strings are
                        reported (applied to every string value).

    Returns:
        A dict with status "ok" and data containing:
        - new_strings: categorized dict (urls, api_endpoints, potential_secrets, other)
        - removed_strings: list of strings only in the old version
        - counts: totals for each category
    """
    try:
        old_session = get_session(session_id_old)
        new_session = get_session(session_id_new)

        compiled_filter = None
        if filter:
            try:
                compiled_filter = re.compile(filter, re.IGNORECASE)
            except re.error as exc:
                return {
                    "status": "error",
                    "message": f"Invalid regex filter: {exc}",
                    "suggestion": "Provide a valid Python regular expression.",
                }

        old_strings = _get_all_strings(old_session)
        new_strings = _get_all_strings(new_session)

        added = new_strings - old_strings
        removed = old_strings - new_strings

        def _apply_filter(string_set: set[str]) -> set[str]:
            if compiled_filter is None:
                return string_set
            return {s for s in string_set if compiled_filter.search(s)}

        added = _apply_filter(added)
        removed = _apply_filter(removed)

        # Categorize new strings
        new_categorized: dict[str, list[str]] = {
            "urls": [],
            "api_endpoints": [],
            "potential_secrets": [],
            "other": [],
        }

        for s in sorted(added):
            if _is_api_endpoint(s):
                new_categorized["api_endpoints"].append(s)
            elif _is_url(s):
                new_categorized["urls"].append(s)
            elif _is_potential_secret(s):
                new_categorized["potential_secrets"].append(s)
            else:
                new_categorized["other"].append(s)

        return {
            "status": "ok",
            "data": {
                "filter_applied": filter or None,
                "new_strings": new_categorized,
                "removed_strings": sorted(removed),
                "counts": {
                    "added_total": len(added),
                    "removed_total": len(removed),
                    "urls": len(new_categorized["urls"]),
                    "api_endpoints": len(new_categorized["api_endpoints"]),
                    "potential_secrets": len(new_categorized["potential_secrets"]),
                    "other": len(new_categorized["other"]),
                },
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
            "message": f"diff_strings failed: {exc}",
            "suggestion": "Ensure both sessions are valid and the APKs were loaded successfully.",
        }


# ---------------------------------------------------------------------------
# Tool 5 – diff_security
# ---------------------------------------------------------------------------


@mcp.tool()
def diff_security(session_id_old: str, session_id_new: str) -> dict:
    """Compare security posture between two APK versions.

    Runs scan_manifest_security on both versions and correlates findings by
    their title and location.  Reports:

    - **new_vulnerabilities**: issues present in the new version but not the old
    - **fixed_vulnerabilities**: issues present in the old version but not the new
    - **unchanged**: issues present in both versions
    - **severity_delta**: change in per-severity counts (positive = worse)

    Args:
        session_id_old: Session ID for the older APK version (from load_apk).
        session_id_new: Session ID for the newer APK version (from load_apk).

    Returns:
        A dict with status "ok" and data containing the three finding categories
        plus severity delta and summary statistics.
    """
    try:
        # Validate both sessions exist before running scans
        get_session(session_id_old)
        get_session(session_id_new)

        old_findings = _scan_manifest_findings(session_id_old)
        new_findings = _scan_manifest_findings(session_id_new)

        old_keyed: dict[str, dict] = {_finding_key(f): f for f in old_findings}
        new_keyed: dict[str, dict] = {_finding_key(f): f for f in new_findings}

        old_keys = set(old_keyed.keys())
        new_keys = set(new_keyed.keys())

        new_vulnerabilities = [new_keyed[k] for k in sorted(new_keys - old_keys)]
        fixed_vulnerabilities = [old_keyed[k] for k in sorted(old_keys - new_keys)]
        unchanged = [old_keyed[k] for k in sorted(old_keys & new_keys)]

        # Severity counts
        _SEVS = ("critical", "high", "medium", "low", "info")

        def _sev_counts(findings: list[dict]) -> dict[str, int]:
            counts: dict[str, int] = {s: 0 for s in _SEVS}
            for f in findings:
                sev = f.get("severity", "info")
                if sev in counts:
                    counts[sev] += 1
            return counts

        old_counts = _sev_counts(old_findings)
        new_counts = _sev_counts(new_findings)
        severity_delta = {s: new_counts[s] - old_counts[s] for s in _SEVS}

        # Overall verdict
        if any(v > 0 for v in severity_delta.values()):
            posture_change = "worse"
        elif any(v < 0 for v in severity_delta.values()):
            posture_change = "improved"
        else:
            posture_change = "unchanged"

        return {
            "status": "ok",
            "data": {
                "posture_change": posture_change,
                "new_vulnerabilities": new_vulnerabilities,
                "fixed_vulnerabilities": fixed_vulnerabilities,
                "unchanged": unchanged,
                "counts": {
                    "new_vulnerabilities": len(new_vulnerabilities),
                    "fixed_vulnerabilities": len(fixed_vulnerabilities),
                    "unchanged": len(unchanged),
                },
                "severity_summary": {
                    "old": old_counts,
                    "new": new_counts,
                    "delta": severity_delta,
                },
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
            "message": f"diff_security failed: {exc}",
            "suggestion": "Ensure both sessions are valid and the APKs were loaded successfully.",
        }
