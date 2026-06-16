"""Tests for APK loading and manifest analysis tools."""

from __future__ import annotations

from unittest.mock import patch


# Pre-import tool module at collection time.
# conftest.py (root) installs mcp/androguard stubs before this runs, and
# apksaw.session's restore_sessions() is also patched there.
from apksaw.tools.apk import load_apk, get_manifest, get_permissions, get_components


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _inject_session(mock_session):
    """Patch get_session so it returns mock_session for any session_id."""
    return patch("apksaw.tools.apk.get_session", return_value=mock_session)


def _inject_create_session(mock_session):
    """Patch create_session so it returns mock_session without touching the filesystem."""
    return patch("apksaw.tools.apk.create_session", return_value=mock_session)


# ---------------------------------------------------------------------------
# load_apk
# ---------------------------------------------------------------------------


def test_load_apk_success(mock_session, sample_apk_path):
    """load_apk returns status=ok and the correct session_id for a valid file."""
    with _inject_create_session(mock_session):
        with patch("os.path.getsize", return_value=1024 * 1024):
            result = load_apk(str(sample_apk_path))

    assert result["status"] == "ok"
    data = result["data"]
    assert data["session_id"] == mock_session.session_id
    assert data["package_name"] == "com.example.testapp"
    assert "sha256" in data
    assert "file_size_mb" in data


def test_load_apk_missing_file():
    """load_apk returns status=error when the file does not exist."""
    with patch(
        "apksaw.tools.apk.create_session",
        side_effect=FileNotFoundError("APK not found: /no/such.apk"),
    ):
        result = load_apk("/no/such.apk")

    assert result["status"] == "error"
    assert "suggestion" in result


# ---------------------------------------------------------------------------
# get_manifest
# ---------------------------------------------------------------------------


def test_get_manifest_success(mock_session):
    """get_manifest returns structured manifest data for a valid session."""
    with _inject_session(mock_session):
        result = get_manifest(mock_session.session_id)

    assert result["status"] == "ok"
    data = result["data"]
    assert data["package"] == "com.example.testapp"
    assert "permissions" in data
    assert "components" in data
    assert "activities" in data["components"]


def test_get_manifest_bad_session():
    """get_manifest returns status=error for an unknown session_id."""
    with patch(
        "apksaw.tools.apk.get_session",
        side_effect=KeyError("Session 'bad' not found"),
    ):
        result = get_manifest("bad")

    assert result["status"] == "error"


# ---------------------------------------------------------------------------
# get_permissions
# ---------------------------------------------------------------------------


def test_get_permissions_identifies_dangerous(mock_session):
    """get_permissions correctly flags dangerous permissions."""
    with _inject_session(mock_session):
        result = get_permissions(mock_session.session_id)

    assert result["status"] == "ok"
    data = result["data"]
    # CAMERA and ACCESS_FINE_LOCATION are in _DANGEROUS_PERMISSIONS
    assert "android.permission.CAMERA" in data["dangerous"]
    assert "android.permission.ACCESS_FINE_LOCATION" in data["dangerous"]
    # INTERNET is not dangerous
    assert "android.permission.INTERNET" not in data["dangerous"]
    assert data["counts"]["dangerous"] >= 2


# ---------------------------------------------------------------------------
# get_components
# ---------------------------------------------------------------------------


def test_get_components_all(mock_session):
    """get_components with type='all' returns all four component categories."""
    with _inject_session(mock_session):
        result = get_components(mock_session.session_id, component_type="all")

    assert result["status"] == "ok"
    assert "activity" in result["data"]["components"]
    assert "service" in result["data"]["components"]
    assert "receiver" in result["data"]["components"]
    assert "provider" in result["data"]["components"]


def test_get_components_invalid_type(mock_session):
    """get_components returns error for an unrecognised component_type."""
    with _inject_session(mock_session):
        result = get_components(mock_session.session_id, component_type="widget")

    assert result["status"] == "error"
    assert "Invalid component_type" in result["message"]
