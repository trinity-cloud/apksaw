"""Digital Asset Links posture verification.

``verify_app_links`` correlates the manifest's ``autoVerify=true`` intent
filters with live ``/.well-known/assetlinks.json`` responses to classify
each host as ``ok``, ``fingerprint_mismatch``, ``malformed``, ``missing``,
or ``unreachable``.
"""

from __future__ import annotations

import json
import re

from apksaw.server import mcp
from apksaw.session import get_session
from apksaw.utils.http_probe import http_get, ProbeError

_ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _norm_fingerprint(value: str) -> str:
    """Normalise a SHA-256 fingerprint to bare lowercase hex.

    Both sources must be normalised the same way: asn1crypto's
    ``sha256_fingerprint`` is **space**-separated uppercase (``"AB CD ..."``),
    while ``assetlinks.json`` uses **colon**-separated (``"AB:CD:..."``).
    Stripping every non-hex character canonicalises both to ``"abcd..."``.
    """
    return re.sub(r"[^0-9a-f]", "", value.lower())


def _resolve_name(comp_name: str, package: str) -> str:
    """Resolve a short Android component name to a fully-qualified class name."""
    name = comp_name.strip()
    if name.startswith("."):
        return package + name
    if "." not in name:
        return package + "." + name
    return name


def _extract_auto_verify_hosts(session) -> list[dict]:
    """Parse the manifest for autoVerify=true intent-filter hosts.

    Returns a list of dicts with keys: ``host``, ``activity``, ``scheme``.
    """
    apk = session.apk
    package = apk.get_package()
    manifest = apk.get_android_manifest_xml()
    if manifest is None:
        return []

    app_elem = manifest.find("application")
    if app_elem is None:
        return []

    hosts: list[dict] = []
    for activity_elem in app_elem.findall("activity"):
        activity_name_raw = activity_elem.get(f"{{{_ANDROID_NS}}}name") or ""
        activity_name = _resolve_name(activity_name_raw, package)

        for intent_filter in activity_elem.findall("intent-filter"):
            auto_verify_raw = (
                intent_filter.get(f"{{{_ANDROID_NS}}}autoVerify") or "false"
            )
            if auto_verify_raw.lower() != "true":
                continue

            # Must have android.intent.action.VIEW and category BROWSABLE
            actions = [
                a.get(f"{{{_ANDROID_NS}}}name", "")
                for a in intent_filter.findall("action")
            ]
            categories = [
                c.get(f"{{{_ANDROID_NS}}}name", "")
                for c in intent_filter.findall("category")
            ]
            if "android.intent.action.VIEW" not in actions:
                continue
            if "android.intent.category.BROWSABLE" not in categories:
                continue

            for data_elem in intent_filter.findall("data"):
                scheme = data_elem.get(f"{{{_ANDROID_NS}}}scheme") or "https"
                host = data_elem.get(f"{{{_ANDROID_NS}}}host") or ""
                if host:
                    hosts.append({
                        "host": host,
                        "activity": activity_name,
                        "scheme": scheme,
                    })

    return hosts


@mcp.tool()
def verify_app_links(session_id: str) -> dict:
    """Verify Android App Links posture via Digital Asset Links.

    Parses the manifest for ``autoVerify=true`` activities, extracts unique
    hosts, fetches ``/.well-known/assetlinks.json`` for each, and classifies
    every host as one of:

    * ``ok`` — statement list found, signing SHA-256 matches
    * ``fingerprint_mismatch`` — statements found but no fingerprint matches
    * ``malformed`` — JSON present but not a valid assetlinks statement list
    * ``missing`` — HTTP 404 (no assetlinks file)
    * ``unreachable`` — DNS / timeout / connection error

    Args:
        session_id: Session ID returned by ``load_apk``.

    Returns:
        ``{status, data: {results: [{host, status, details, ...}], summary}}``.
    """
    try:
        session = get_session(session_id)
        apk = session.apk

        # Get signing info for SHA-256 fingerprint matching
        try:
            signing_info = apk.get_certificates()
        except Exception:
            signing_info = []

        # Extract SHA-256 fingerprints from signing certs
        signing_sha256: list[str] = []
        for cert in signing_info:
            try:
                signing_sha256.append(_norm_fingerprint(cert.sha256_fingerprint))
            except Exception:
                pass

        hosts_data = _extract_auto_verify_hosts(session)

        if not hosts_data:
            return {
                "status": "ok",
                "data": {
                    "results": [],
                    "summary": {
                        "total_hosts": 0,
                        "ok": 0,
                        "fingerprint_mismatch": 0,
                        "malformed": 0,
                        "missing": 0,
                        "unreachable": 0,
                    },
                    "guidance": (
                        "No autoVerify=true activities with BROWSABLE intent "
                        "filters found. The app does not claim App Links."
                    ),
                },
            }

        # Deduplicate by host
        seen_hosts: set[str] = set()
        unique_hosts: list[dict] = []
        for h in hosts_data:
            if h["host"] not in seen_hosts:
                seen_hosts.add(h["host"])
                unique_hosts.append(h)

        results: list[dict] = []
        for host_info in unique_hosts:
            host = host_info["host"]
            # Digital Asset Links files are always served over HTTPS, regardless
            # of the intent-filter's declared scheme — fetch over https.
            url = f"https://{host}/.well-known/assetlinks.json"

            try:
                code, body, headers = http_get(url, timeout=10)
            except ProbeError:
                results.append({
                    "host": host,
                    "status": "unreachable",
                    "expected_url": url,
                    "details": "Host unreachable (DNS, timeout, or connection refused).",
                })
                continue
            except Exception as exc:
                results.append({
                    "host": host,
                    "status": "unreachable",
                    "expected_url": url,
                    "details": f"HTTP probe failed: {exc}",
                })
                continue

            if code == 404:
                results.append({
                    "host": host,
                    "status": "missing",
                    "expected_url": url,
                    "http_status": code,
                    "details": "No assetlinks.json found at this host.",
                })
                continue

            if code != 200:
                results.append({
                    "host": host,
                    "status": "unreachable",
                    "expected_url": url,
                    "http_status": code,
                    "details": f"Unexpected HTTP status {code}.",
                })
                continue

            # Parse the body as JSON
            try:
                statements = json.loads(body)
            except json.JSONDecodeError:
                results.append({
                    "host": host,
                    "status": "malformed",
                    "expected_url": url,
                    "http_status": code,
                    "details": "Response is not valid JSON.",
                })
                continue

            if not isinstance(statements, list):
                results.append({
                    "host": host,
                    "status": "malformed",
                    "expected_url": url,
                    "http_status": code,
                    "details": "JSON root is not a list (expected a statement array).",
                })
                continue

            if not signing_sha256:
                results.append({
                    "host": host,
                    "status": "fingerprint_mismatch",
                    "expected_url": url,
                    "http_status": code,
                    "statement_count": len(statements),
                    "details": (
                        "Could not extract signing certificate SHA-256 for "
                        "fingerprint comparison."
                    ),
                })
                continue

            # Look for a matching SHA-256 fingerprint in the statements
            matched = False
            for stmt in statements:
                if not isinstance(stmt, dict):
                    continue
                target = stmt.get("target", {})
                if not isinstance(target, dict):
                    continue
                for fp_entry in target.get("sha256_cert_fingerprints", []):
                    if isinstance(fp_entry, str):
                        if _norm_fingerprint(fp_entry) in signing_sha256:
                            matched = True
                            break
                if matched:
                    break

            if matched:
                results.append({
                    "host": host,
                    "status": "ok",
                    "expected_url": url,
                    "http_status": code,
                    "statement_count": len(statements),
                    "details": "Asset Links statement found with matching SHA-256 fingerprint.",
                })
            else:
                results.append({
                    "host": host,
                    "status": "fingerprint_mismatch",
                    "expected_url": url,
                    "http_status": code,
                    "statement_count": len(statements),
                    "details": (
                        "No assetlinks statement matches the app's signing "
                        "certificate SHA-256 fingerprint(s)."
                    ),
                })

        # Build summary
        status_counts: dict[str, int] = {
            "ok": 0,
            "fingerprint_mismatch": 0,
            "malformed": 0,
            "missing": 0,
            "unreachable": 0,
        }
        for r in results:
            s = r.get("status", "unreachable")
            if s in status_counts:
                status_counts[s] += 1

        return {
            "status": "ok",
            "data": {
                "results": results,
                "summary": {
                    "total_hosts": len(results),
                    **status_counts,
                },
                "signing_sha256": signing_sha256,
            },
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
            "message": f"verify_app_links failed: {exc}",
            "suggestion": "Ensure the APK was loaded successfully.",
        }
