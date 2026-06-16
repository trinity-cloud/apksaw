"""Tests for automated security scanning tools."""

from __future__ import annotations

from unittest.mock import patch


from tests.conftest import _make_string_analysis

# Pre-import scanner functions at collection time (conftest.py stubs mcp/androguard)
from apksaw.tools.security import (
    scan_manifest_security,
    scan_crypto_issues,
    scan_network_security,
    scan_code_injection,
    scan_data_storage,
)

_SEC = "apksaw.tools.security"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _inject_session(mock_session):
    return patch(f"{_SEC}.get_session", return_value=mock_session)


def _assert_scanner_schema(result):
    """All scanners must return status=ok with findings list and summary dict."""
    assert result["status"] == "ok", f"Expected ok, got: {result}"
    data = result["data"]
    assert "findings" in data, "Missing 'findings' key"
    assert "summary" in data, "Missing 'summary' key"
    assert isinstance(data["findings"], list)
    assert isinstance(data["summary"], dict)
    for key in ("high", "medium", "low"):
        assert key in data["summary"], f"Missing '{key}' in summary"


# ---------------------------------------------------------------------------
# scan_manifest_security
# ---------------------------------------------------------------------------


def test_scan_manifest_returns_schema(mock_session):
    """scan_manifest_security always returns the expected schema on a valid session."""
    with _inject_session(mock_session):
        result = scan_manifest_security(mock_session.session_id)

    _assert_scanner_schema(result)


def test_scan_manifest_detects_debuggable(mock_session):
    """scan_manifest_security flags debuggable=true as a critical finding."""
    from lxml import etree

    NS = "http://schemas.android.com/apk/res/android"
    manifest = etree.Element("manifest")
    app = etree.SubElement(manifest, "application")
    app.set(f"{{{NS}}}debuggable", "true")
    app.set(f"{{{NS}}}allowBackup", "false")
    mock_session.apk.get_android_manifest_xml.return_value = manifest
    mock_session.apk.get_target_sdk_version.return_value = "33"
    mock_session.apk.get_min_sdk_version.return_value = "21"

    with _inject_session(mock_session):
        result = scan_manifest_security(mock_session.session_id)

    titles = [f["title"] for f in result["data"]["findings"]]
    assert any("debuggable" in t.lower() for t in titles)
    assert result["data"]["summary"]["critical"] >= 1


# ---------------------------------------------------------------------------
# scan_crypto_issues
# ---------------------------------------------------------------------------


def test_scan_crypto_returns_schema(mock_session):
    """scan_crypto_issues returns the expected schema."""
    mock_session.analysis.get_strings.side_effect = lambda: iter([])
    mock_session.analysis.find_methods.side_effect = lambda **kw: iter([])

    with _inject_session(mock_session):
        result = scan_crypto_issues(mock_session.session_id)

    _assert_scanner_schema(result)


# ---------------------------------------------------------------------------
# scan_network_security
# ---------------------------------------------------------------------------


def test_scan_network_detects_http_url(mock_session):
    """scan_network_security flags plain HTTP URLs found in string pool."""
    http_string = _make_string_analysis("http://insecure.example.com/api")
    mock_session.analysis.get_strings.side_effect = lambda: iter([http_string])
    mock_session.analysis.find_methods.side_effect = lambda **kw: iter([])
    mock_session.analysis.find_strings.side_effect = lambda string="", **kw: iter(
        [s for s in [http_string] if string in s.get_value()]
    )

    with _inject_session(mock_session):
        result = scan_network_security(mock_session.session_id)

    _assert_scanner_schema(result)
    titles = [f["title"] for f in result["data"]["findings"]]
    assert any(
        "http" in t.lower() or "cleartext" in t.lower() or "insecure" in t.lower()
        for t in titles
    )


# ---------------------------------------------------------------------------
# scan_code_injection
# ---------------------------------------------------------------------------


def test_scan_code_injection_returns_schema(mock_session):
    """scan_code_injection returns the expected schema on a clean APK."""
    mock_session.analysis.find_methods.side_effect = lambda **kw: iter([])

    with _inject_session(mock_session):
        result = scan_code_injection(mock_session.session_id)

    _assert_scanner_schema(result)


# ---------------------------------------------------------------------------
# scan_data_storage
# ---------------------------------------------------------------------------


def test_scan_data_storage_returns_schema(mock_session):
    """scan_data_storage returns the expected schema on a clean APK."""
    mock_session.analysis.find_methods.side_effect = lambda **kw: iter([])

    with _inject_session(mock_session):
        result = scan_data_storage(mock_session.session_id)

    _assert_scanner_schema(result)


# ---------------------------------------------------------------------------
# Bad session handling
# ---------------------------------------------------------------------------


def test_scanner_bad_session_returns_error():
    """All scanners return status=error for an unknown session_id."""
    with patch(f"{_SEC}.get_session", side_effect=KeyError("Session 'bad' not found")):
        result = scan_manifest_security("bad")

    assert result["status"] == "error"
