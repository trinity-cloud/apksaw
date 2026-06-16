"""Tests for ADB device interaction tools."""

from __future__ import annotations

from unittest.mock import patch


# Pre-import device tool functions at collection time
from apksaw.tools.device import device_info, list_packages, screenshot

_ADB_MODULE = "apksaw.tools.device"
_RUN_ADB = f"{_ADB_MODULE}.run_adb"
_CHECK_DEVICE = f"{_ADB_MODULE}.check_device_connected"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _device_connected():
    return patch(_CHECK_DEVICE, return_value=True)


def _device_disconnected():
    return patch(_CHECK_DEVICE, return_value=False)


# ---------------------------------------------------------------------------
# device_info
# ---------------------------------------------------------------------------


def test_device_info_success():
    """device_info returns structured device properties when a device is connected."""
    props = {
        "ro.product.model": "Pixel 10a",
        "ro.build.version.release": "15",
        "ro.build.version.sdk": "35",
        "ro.serialno": "EMULATOR123",
        "ro.build.fingerprint": "google/pixel/10a:15/AP3A/12345:user/release-keys",
    }

    def _getprop_side_effect(*args):
        # args looks like ("shell", "getprop", "ro.product.model")
        prop = args[-1]
        return props.get(prop, "")

    with _device_connected():
        with patch(_RUN_ADB, side_effect=_getprop_side_effect):
            result = device_info()

    assert result["status"] == "ok"
    data = result["data"]
    assert data["model"] == "Pixel 10a"
    assert data["android_version"] == "15"
    assert data["sdk_level"] == "35"


def test_device_info_no_device():
    """device_info returns status=error when no ADB device is connected."""
    with _device_disconnected():
        result = device_info()

    assert result["status"] == "error"
    assert "suggestion" in result


# ---------------------------------------------------------------------------
# list_packages
# ---------------------------------------------------------------------------


def test_list_packages_third_party():
    """list_packages returns a parsed list of third-party packages."""
    adb_output = "package:com.example.app\npackage:com.another.app\n"

    with _device_connected():
        with patch(_RUN_ADB, return_value=adb_output):
            result = list_packages(filter="third-party")

    assert result["status"] == "ok"
    assert "com.example.app" in result["data"]["packages"]
    assert "com.another.app" in result["data"]["packages"]
    assert result["data"]["count"] == 2


def test_list_packages_invalid_filter():
    """list_packages returns status=error for an unrecognised filter value."""
    with _device_connected():
        result = list_packages(filter="unknown-filter")

    assert result["status"] == "error"
    assert "Unknown filter" in result["message"]


def test_list_packages_no_device():
    """list_packages returns status=error when no device is connected."""
    with _device_disconnected():
        result = list_packages()

    assert result["status"] == "error"


# ---------------------------------------------------------------------------
# screenshot
# ---------------------------------------------------------------------------


def test_screenshot_success(tmp_path):
    """screenshot returns the local path to the captured image."""
    with _device_connected():
        with patch(_RUN_ADB, return_value=""):
            with patch(f"{_ADB_MODULE}.WORKSPACES_DIR", tmp_path):
                with patch(f"{_ADB_MODULE}.ensure_dirs"):
                    result = screenshot()

    assert result["status"] == "ok"
    assert "local_path" in result["data"]
    assert "timestamp" in result["data"]
