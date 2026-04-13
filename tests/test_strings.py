"""Tests for string extraction and search tools."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import _make_string_analysis

# Pre-import tool functions at collection time (conftest.py stubs mcp/androguard)
from apksaw.tools.strings import search_strings, extract_urls, extract_secrets


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _inject_session(mock_session):
    return patch("apksaw.tools.strings.get_session", return_value=mock_session)


def _set_strings(mock_session, string_values):
    """Replace the analysis strings with fresh mocks on each call."""
    string_mocks = [_make_string_analysis(v) for v in string_values]
    mock_session.analysis.get_strings.side_effect = lambda: iter(string_mocks)

    import re as _re

    def _find(string="", **kw):
        for sm in string_mocks:
            try:
                if _re.search(string, sm.get_value()):
                    yield sm
            except Exception:
                pass

    mock_session.analysis.find_strings.side_effect = _find
    return string_mocks


# ---------------------------------------------------------------------------
# search_strings
# ---------------------------------------------------------------------------


def test_search_strings_no_pattern_returns_all(mock_session):
    """search_strings with no pattern returns all strings in the pool."""
    _set_strings(mock_session, ["hello", "world", "foo"])

    with _inject_session(mock_session):
        result = search_strings(mock_session.session_id)

    assert result["status"] == "ok"
    assert result["data"]["total"] == 3


def test_search_strings_with_pattern(mock_session):
    """search_strings filters results by regex pattern."""
    _set_strings(mock_session, ["https://api.example.com", "http://insecure.com", "not a url"])

    with _inject_session(mock_session):
        result = search_strings(mock_session.session_id, pattern="^https://")

    assert result["status"] == "ok"
    values = [s["value"] for s in result["data"]["strings"]]
    assert all(v.startswith("https://") for v in values)


def test_search_strings_invalid_pattern_returns_error(mock_session):
    """search_strings returns error for an invalid regex."""
    with _inject_session(mock_session):
        result = search_strings(mock_session.session_id, pattern="[invalid(")

    assert result["status"] == "error"
    assert "Invalid regex" in result["message"]


# ---------------------------------------------------------------------------
# extract_urls
# ---------------------------------------------------------------------------


def test_extract_urls_categorises_correctly(mock_session):
    """extract_urls puts URLs into the right category buckets."""
    _set_strings(mock_session, [
        "https://secure.example.com/api",
        "http://insecure.example.com/data",
        "content://com.example.provider/data",
        "file:///data/data/com.example/prefs.xml",
        "just a plain string",
    ])

    with _inject_session(mock_session):
        result = extract_urls(mock_session.session_id)

    assert result["status"] == "ok"
    data = result["data"]
    assert len(data["https_urls"]) == 1
    assert data["https_urls"][0]["value"] == "https://secure.example.com/api"
    assert len(data["http_urls"]) == 1
    assert len(data["content_uris"]) == 1
    assert len(data["file_uris"]) == 1


# ---------------------------------------------------------------------------
# extract_secrets
# ---------------------------------------------------------------------------


def test_extract_secrets_detects_google_api_key(mock_session):
    """extract_secrets identifies a Google API key pattern."""
    # Matches: AIza[0-9A-Za-z\-_]{35}
    fake_key = "AIzaSyABC123XYZ456abc789def012ghi345jkl"
    _set_strings(mock_session, [fake_key, "innocent string"])

    with _inject_session(mock_session):
        result = extract_secrets(mock_session.session_id)

    assert result["status"] == "ok"
    pattern_names = [f["pattern_name"] for f in result["data"]["findings"]]
    assert "google_api_key" in pattern_names
    assert result["data"]["severity_counts"]["high"] >= 1


def test_extract_secrets_empty_when_clean(mock_session):
    """extract_secrets returns zero findings for benign strings."""
    _set_strings(mock_session, ["hello world", "some normal text", "nothing suspicious"])

    with _inject_session(mock_session):
        result = extract_secrets(mock_session.session_id)

    assert result["status"] == "ok"
    assert result["data"]["total"] == 0
