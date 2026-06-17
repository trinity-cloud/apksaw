"""Shared WebView setting call-site classifier.

Used by BOTH ``tools/webview.py`` (``scan_webview_surface``) and
``tools/security_v2.py`` (``scan_network_security_v2``) so the two tools share
one implementation and dedup on the same key — ``(class, method, offset)`` —
instead of re-implementing the resolve/triage loop and collapsing distinct
call-sites by ``class->method`` alone.
"""

from __future__ import annotations

from apksaw.utils.taint_lite import get_const_int_at_callsite

_WEBSETTINGS = r"Landroid/webkit/WebSettings;"


def classify_webview_callsites(
    analysis,
    method_name: str,
    arg_index: int,
    dangerous_value: int,
    classname: str = _WEBSETTINGS,
) -> list[dict]:
    """Classify every call-site of a WebSettings setter by its resolved arg.

    Returns a list of per-call-site dicts, deduplicated on
    ``(class, method, offset)``::

        {"class", "method", "offset", "location", "verdict"}

    ``verdict`` is ``"dangerous"`` (arg resolved to *dangerous_value*) or
    ``"unresolved"`` (arg not statically resolvable). Call-sites resolved to a
    safe value are omitted entirely. ``dangerous_value`` is ``1`` for boolean
    setters and ``0`` for ``setMixedContentMode`` (MIXED_CONTENT_ALWAYS_ALLOW).
    """
    results: list[dict] = []
    seen: set[tuple] = set()

    for target_ma in analysis.find_methods(classname=classname, methodname=method_name):
        for _, caller_ma, call_offset in target_ma.get_xref_from():
            key = (caller_ma.class_name, caller_ma.name, call_offset)
            if key in seen:
                continue
            seen.add(key)

            val = get_const_int_at_callsite(
                analysis, caller_ma, call_offset, arg_index=arg_index
            )
            if val is None:
                verdict = "unresolved"
            elif val == dangerous_value:
                verdict = "dangerous"
            else:
                continue  # resolved to a safe value → dropped

            try:
                loc = f"{caller_ma.class_name}->{caller_ma.name}@{call_offset:#x}"
            except Exception:
                loc = f"{caller_ma.class_name}->{caller_ma.name}"

            results.append({
                "class": caller_ma.class_name,
                "method": caller_ma.name,
                "offset": call_offset,
                "location": loc,
                "verdict": verdict,
            })

    return results
