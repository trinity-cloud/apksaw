"""WebView misconfiguration scanner.

``scan_webview_surface`` covers the hybrid-app WebView surface: each
security-relevant ``WebSettings`` setter argument is resolved via
``get_const_int_at_callsite`` (through the shared ``classify_webview_callsites``
helper, so this tool and ``scan_network_security_v2`` share one implementation
and dedup on ``(class, method, offset)``) and triaged:

* resolved-dangerous → finding at the setter's base severity, ``confidence: high``
* resolved-safe → **dropped** (no finding)
* unresolved → ``confidence: low``, ``verification_needed: true``

Severity is per-setter, not blanket: ``setJavaScriptEnabled`` /
``setDomStorageEnabled`` alone are low (normal in most apps), file/content access
and remote-debugging are high.
"""

from __future__ import annotations

from apksaw.server import mcp
from apksaw.session import get_session
from apksaw.utils.webview_common import classify_webview_callsites

_WS = r"Landroid/webkit/WebSettings;"
_WV = r"Landroid/webkit/WebView;"

# (method_name, classname, arg_index, dangerous_value, base_severity, title_suffix)
# Instance WebSettings setters take arg_index 1 (0 = this); the static
# WebView.setWebContentsDebuggingEnabled takes arg_index 0.
_WEBVIEW_SETTERS: list[tuple[str, str, int, int, str, str]] = [
    ("setAllowFileAccess", _WS, 1, 1, "high", "setAllowFileAccess(true)"),
    ("setAllowFileAccessFromFileURLs", _WS, 1, 1, "high", "setAllowFileAccessFromFileURLs(true)"),
    ("setAllowContentAccess", _WS, 1, 1, "high", "setAllowContentAccess(true)"),
    ("setWebContentsDebuggingEnabled", _WV, 0, 1, "high", "setWebContentsDebuggingEnabled(true)"),
    ("setSavePassword", _WS, 1, 1, "medium", "setSavePassword(true)"),
    # JS / DOM storage are normal in most hybrid apps — low on their own.
    ("setJavaScriptEnabled", _WS, 1, 1, "low", "setJavaScriptEnabled(true)"),
    ("setDomStorageEnabled", _WS, 1, 1, "low", "setDomStorageEnabled(true)"),
]

_CATEGORY = "webview"


def _finding(severity, title, description, locations, recommendation,
             confidence, details, verify_with=""):
    """Build a finding shaped like security_v2._finding_v2 for consistency."""
    return {
        "severity": severity,
        "category": _CATEGORY,
        "title": title,
        "description": description,
        "location": "; ".join(locations[:5]),
        "recommendation": recommendation,
        "confidence": confidence,
        "reachable_from_exported": None,  # not evaluated for WebView settings
        "details": details,
        "verification_needed": confidence != "high",
        "verify_with": verify_with,
    }


def _make_summary(findings: list[dict]) -> dict:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in summary:
            summary[sev] += 1
    return summary


@mcp.tool()
def scan_webview_surface(session_id: str) -> dict:
    """Scan WebView/WebSettings configuration for the full misconfiguration class.

    Resolves the actual boolean argument to each security-relevant setter, drops
    call-sites proven safe, and reports confirmed-dangerous and unresolved sites
    with triaged confidence and per-setter severity.

    Checks: ``setAllowFileAccess``, ``setAllowFileAccessFromFileURLs``,
    ``setAllowContentAccess``, ``setWebContentsDebuggingEnabled``,
    ``setSavePassword``, ``setJavaScriptEnabled``, ``setDomStorageEnabled``.
    (``setAllowUniversalAccessFromFileURLs`` and ``setMixedContentMode`` are
    owned by ``scan_network_security_v2`` via the same shared classifier, so the
    two tools do not double-report.)

    Args:
        session_id: Session ID returned by ``load_apk``.

    Returns:
        ``{status, data: {findings, summary, confidence_breakdown,
        needs_verification_count}}``.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        findings: list[dict] = []

        for method_name, classname, arg_index, dangerous_value, base_severity, title_suffix in _WEBVIEW_SETTERS:
            callsites = classify_webview_callsites(
                analysis, method_name, arg_index, dangerous_value, classname=classname,
            )
            dangerous = [c["location"] for c in callsites if c["verdict"] == "dangerous"]
            unresolved = [c["location"] for c in callsites if c["verdict"] == "unresolved"]

            if dangerous:
                findings.append(_finding(
                    severity=base_severity,
                    title=f"WebView {title_suffix} (confirmed)",
                    description=f"{method_name}() is called with the dangerous value (true).",
                    locations=dangerous,
                    recommendation=(
                        f"Set {method_name}(false) unless strictly required; "
                        f"review each call-site for legitimate use."
                    ),
                    confidence="high",
                    details=(
                        f"Argument resolved to TRUE by static trace at "
                        f"{len(dangerous)} call-site(s)."
                    ),
                ))

            if unresolved:
                findings.append(_finding(
                    severity="medium",
                    title=f"WebView {method_name} called (value not resolved)",
                    description=(
                        f"{method_name}() is called but the argument could not be "
                        f"resolved statically."
                    ),
                    locations=unresolved,
                    recommendation=(
                        f"Ensure {method_name}(false) is passed (the safe default), "
                        f"or remove the call."
                    ),
                    confidence="low",
                    details=(
                        f"{len(unresolved)} call-site(s) with an unresolved argument. "
                        f"Call-sites resolved to false were filtered out."
                    ),
                    verify_with=(
                        f"decompile_class on each listed class and read the boolean "
                        f"argument passed to {method_name}; confirm it is false."
                    ),
                ))

        summary = _make_summary(findings)
        confidence_breakdown = {"high": 0, "medium": 0, "low": 0}
        for f in findings:
            conf = f.get("confidence", "low")
            if conf in confidence_breakdown:
                confidence_breakdown[conf] += 1
        needs_verification = sum(1 for f in findings if f.get("verification_needed"))

        return {
            "status": "ok",
            "data": {
                "findings": findings,
                "summary": summary,
                "confidence_breakdown": confidence_breakdown,
                "needs_verification_count": needs_verification,
                "guidance": (
                    "Low-confidence findings need verification via decompile_class; "
                    "see each finding's verify_with. setJavaScriptEnabled/"
                    "setDomStorageEnabled are low on their own — escalate only when "
                    "the WebView loads untrusted (file:// or Intent-derived) content."
                ),
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
            "message": f"scan_webview_surface failed: {exc}",
            "suggestion": "Ensure the APK was loaded successfully.",
        }
