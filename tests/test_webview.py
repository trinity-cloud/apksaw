"""Tests for scan_webview_surface: per-setter severity, tri-state triage,
offset-level locations, and finding shape.
"""

from unittest.mock import MagicMock, patch

from apksaw.tools.webview import scan_webview_surface

_WV = "apksaw.tools.webview"
_WVC = "apksaw.utils.webview_common"


def _analysis_with_callsite(method_names):
    """Mock analysis where each named setter has exactly one call-site @0x10."""
    def find_methods(classname=None, methodname=None):
        if methodname in method_names:
            caller = MagicMock()
            caller.class_name = "Lcom/x/A;"
            caller.name = "onCreate"
            target = MagicMock()
            target.get_xref_from.return_value = [(MagicMock(), caller, 0x10)]
            return [target]
        return []
    analysis = MagicMock()
    analysis.find_methods.side_effect = find_methods
    return analysis


def _run(method_name, resolved_value):
    session = MagicMock()
    session.analysis = _analysis_with_callsite({method_name})
    with patch(f"{_WV}.get_session", return_value=session), \
         patch(f"{_WVC}.get_const_int_at_callsite", return_value=resolved_value):
        return scan_webview_surface("s")


def test_file_access_true_is_high():
    f = _run("setAllowFileAccess", 1)["data"]["findings"]
    assert len(f) == 1
    assert f[0]["severity"] == "high" and f[0]["confidence"] == "high"


def test_js_enabled_true_is_low_not_high():
    # The key severity-policy fix: JS-enabled alone is low, not blanket high.
    f = _run("setJavaScriptEnabled", 1)["data"]["findings"]
    assert len(f) == 1
    assert f[0]["severity"] == "low"


def test_safe_false_is_dropped():
    assert _run("setAllowFileAccess", 0)["data"]["findings"] == []


def test_unresolved_is_low_conf_with_verify():
    f = _run("setAllowContentAccess", None)["data"]["findings"]
    assert len(f) == 1
    assert f[0]["confidence"] == "low"
    assert f[0]["verification_needed"] is True
    assert f[0]["verify_with"]


def test_debugging_enabled_is_high():
    f = _run("setWebContentsDebuggingEnabled", 1)["data"]["findings"]
    assert f[0]["severity"] == "high"


def test_location_includes_offset_and_summary_by_severity():
    data = _run("setAllowFileAccess", 1)["data"]
    assert "@0x10" in data["findings"][0]["location"]
    assert data["summary"]["high"] == 1
    # finding carries the _finding_v2-style shape
    assert "reachable_from_exported" in data["findings"][0]
