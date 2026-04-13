"""ADB device interaction tools for Android Threat Analyzer."""

import re
from datetime import datetime
from pathlib import Path

from apksaw.config import WORKSPACES_DIR, ensure_dirs
from apksaw.server import mcp
from apksaw.session import create_session
from apksaw.utils.adb import check_device_connected, run_adb


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _require_device() -> None:
    """Raise RuntimeError if no ADB device is connected."""
    if not check_device_connected():
        raise RuntimeError("No ADB device connected. Connect a device and enable USB debugging.")


def _getprop(prop: str) -> str:
    """Read a single Android system property via getprop."""
    return run_adb("shell", "getprop", prop)


def _parse_dumpsys_package(output: str, package_name: str) -> dict:
    """Parse relevant fields out of `dumpsys package <pkg>` output."""

    def _find(pattern: str, default: str = "") -> str:
        m = re.search(pattern, output)
        return m.group(1).strip() if m else default

    version_name = _find(r"versionName=([^\s]+)")
    version_code = _find(r"versionCode=(\d+)")
    target_sdk = _find(r"targetSdk=(\d+)")
    first_install = _find(r"firstInstallTime=([^\n]+)")
    last_update = _find(r"lastUpdateTime=([^\n]+)")

    # APK paths: grab all codePath / path entries
    apk_paths: list[str] = re.findall(r"codePath=([^\s\n]+)", output)
    if not apk_paths:
        apk_paths = re.findall(r"path:\s+([^\s\n]+\.apk)", output)

    # Declared permissions (what the app declares it provides)
    declared_perms: list[str] = re.findall(r"declared permissions:\s*\n((?:\s+\S+.*\n)*)", output)
    declared_permissions: list[str] = []
    if declared_perms:
        for block in declared_perms:
            declared_permissions.extend(
                line.strip().split(":")[0] for line in block.strip().splitlines() if line.strip()
            )

    # Requested permissions
    req_section = re.search(r"requested permissions:\s*\n((?:\s+\S+.*\n)*)", output)
    requested_permissions: list[str] = []
    if req_section:
        for line in req_section.group(1).strip().splitlines():
            perm = line.strip().split(":")[0]
            if perm:
                requested_permissions.append(perm)

    # Is it a system app?  Flags field contains SYSTEM for system apps.
    flags_match = re.search(r"pkgFlags=\[\s*([^\]]+)\s*\]", output)
    flags_str = flags_match.group(1) if flags_match else ""
    is_system = "SYSTEM" in flags_str

    return {
        "package_name": package_name,
        "version_name": version_name,
        "version_code": version_code,
        "target_sdk": target_sdk,
        "first_install_time": first_install,
        "last_update_time": last_update,
        "apk_paths": apk_paths,
        "declared_permissions": declared_permissions,
        "requested_permissions": requested_permissions,
        "is_system_app": is_system,
    }


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@mcp.tool()
def device_info() -> dict:
    """Return hardware and software information about the connected Android device.

    Reads system properties via ``adb shell getprop`` and returns a structured
    summary containing model name, Android version, SDK level, serial number,
    and build fingerprint.

    Returns:
        dict: ``{"status": "ok", "data": { ... }}`` on success, or
              ``{"status": "error", "message": "...", "suggestion": "..."}`` on failure.
    """
    try:
        _require_device()

        props = {
            "model": _getprop("ro.product.model"),
            "android_version": _getprop("ro.build.version.release"),
            "sdk_level": _getprop("ro.build.version.sdk"),
            "serial_number": _getprop("ro.serialno"),
            "build_fingerprint": _getprop("ro.build.fingerprint"),
        }

        return {"status": "ok", "data": props}

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Ensure a device is connected via USB with debugging enabled, or start an emulator.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check that ADB is installed and on PATH.",
        }


@mcp.tool()
def list_packages(filter: str = "third-party") -> dict:  # noqa: A002
    """List installed packages on the connected Android device.

    Args:
        filter: Which packages to include. One of:
                - ``"third-party"`` (default) — user-installed apps only (``pm list packages -3``)
                - ``"system"`` — pre-installed system apps (``pm list packages -s``)
                - ``"disabled"`` — disabled packages (``pm list packages -d``)
                - ``"all"`` — every package on the device

    Returns:
        dict: ``{"status": "ok", "data": {"packages": [...], "count": N},
                 "meta": {"filter": <filter>}}``
    """
    _FILTER_FLAGS: dict[str, list[str]] = {
        "all": [],
        "third-party": ["-3"],
        "system": ["-s"],
        "disabled": ["-d"],
    }

    try:
        _require_device()

        if filter not in _FILTER_FLAGS:
            return {
                "status": "error",
                "message": f"Unknown filter '{filter}'.",
                "suggestion": f"Use one of: {', '.join(_FILTER_FLAGS)}",
            }

        flags = _FILTER_FLAGS[filter]
        output = run_adb("shell", "pm", "list", "packages", *flags)

        packages = [
            line.removeprefix("package:").strip()
            for line in output.splitlines()
            if line.startswith("package:")
        ]

        return {
            "status": "ok",
            "data": {"packages": packages, "count": len(packages)},
            "meta": {"filter": filter},
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Ensure a device is connected and ADB is authorised.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check ADB connection and try again.",
        }


@mcp.tool()
def app_info(package_name: str) -> dict:
    """Return detailed information about an installed Android application.

    Runs ``adb shell dumpsys package <package_name>`` and parses out version
    information, SDK target, install timestamps, APK paths, declared and
    requested permissions, and whether the app is a system app.

    Args:
        package_name: The fully-qualified Android package name, e.g.
                      ``com.example.myapp``.

    Returns:
        dict: ``{"status": "ok", "data": { ... }}`` on success, or
              ``{"status": "error", "message": "...", "suggestion": "..."}`` on failure.
    """
    try:
        _require_device()

        if not package_name or not package_name.strip():
            return {
                "status": "error",
                "message": "package_name must not be empty.",
                "suggestion": "Provide a valid package name such as 'com.example.app'.",
            }

        output = run_adb("shell", "dumpsys", "package", package_name)

        if "Unable to find package" in output or not output:
            return {
                "status": "error",
                "message": f"Package '{package_name}' not found on device.",
                "suggestion": "Use list_packages() to confirm the package is installed.",
            }

        parsed = _parse_dumpsys_package(output, package_name)
        return {"status": "ok", "data": parsed}

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Ensure the device is connected and the package name is correct.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check ADB connection and package name spelling.",
        }


@mcp.tool()
def pull_apk(package_name: str) -> dict:
    """Extract an APK (or split APK set) from the device to the local workspace.

    Steps:
    1. Resolves the on-device APK path(s) with ``adb shell pm path``.
    2. Creates a per-package directory under ``WORKSPACES_DIR``.
    3. Pulls each APK with ``adb pull``.
    4. Creates an analysis session on ``base.apk`` (or the sole APK).

    Args:
        package_name: Fully-qualified Android package name.

    Returns:
        dict: ``{"status": "ok", "data": {"session_id": "...", "package": "...",
                 "apk_paths": [...], "is_split": bool}}``
    """
    try:
        _require_device()
        ensure_dirs()

        if not package_name or not package_name.strip():
            return {
                "status": "error",
                "message": "package_name must not be empty.",
                "suggestion": "Provide a valid package name such as 'com.example.app'.",
            }

        # Step 1: resolve on-device APK path(s)
        pm_output = run_adb("shell", "pm", "path", package_name)
        # Output lines look like: "package:/data/app/com.example-xxx/base.apk"
        device_paths = [
            line.split("package:", 1)[1].strip()
            for line in pm_output.splitlines()
            if line.startswith("package:")
        ]

        if not device_paths:
            return {
                "status": "error",
                "message": f"Could not find APK path for '{package_name}' on device.",
                "suggestion": "Confirm the package is installed with list_packages().",
            }

        # Step 2: create local destination directory
        pkg_dir = WORKSPACES_DIR / package_name
        pkg_dir.mkdir(parents=True, exist_ok=True)

        # Step 3: pull each APK
        local_paths: list[str] = []
        base_apk_local: Path | None = None

        for device_path in device_paths:
            filename = Path(device_path).name  # e.g. base.apk / split_config.arm64_v8a.apk
            local_file = pkg_dir / filename
            run_adb("pull", device_path, str(local_file), timeout=120)
            local_paths.append(str(local_file))
            if filename == "base.apk":
                base_apk_local = local_file

        # If no file was named exactly "base.apk" (single-APK apps), use the first one
        if base_apk_local is None:
            base_apk_local = Path(local_paths[0])

        is_split = len(local_paths) > 1

        # Step 4: create analysis session on base/primary APK
        session = create_session(str(base_apk_local))

        return {
            "status": "ok",
            "data": {
                "session_id": session.session_id,
                "package": package_name,
                "apk_paths": local_paths,
                "base_apk": str(base_apk_local),
                "is_split": is_split,
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Ensure the device is connected and the package is installed.",
        }
    except FileNotFoundError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "The pulled APK file was not found locally — check WORKSPACES_DIR permissions.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check ADB connection, available disk space, and package name.",
        }


@mcp.tool()
def screenshot() -> dict:
    """Capture a screenshot from the connected Android device.

    Takes a screenshot via ``adb shell screencap``, pulls it to the local
    workspace, then removes the temporary file from the device.

    Returns:
        dict: ``{"status": "ok", "data": {"local_path": "...", "timestamp": "..."}}``
              on success, or ``{"status": "error", ...}`` on failure.
    """
    DEVICE_PATH = "/sdcard/screenshot.png"

    try:
        _require_device()
        ensure_dirs()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        local_filename = f"screenshot_{timestamp}.png"
        local_path = WORKSPACES_DIR / "screenshots" / local_filename
        local_path.parent.mkdir(parents=True, exist_ok=True)

        # Capture on device
        run_adb("shell", "screencap", "-p", DEVICE_PATH)

        # Pull to local workspace
        run_adb("pull", DEVICE_PATH, str(local_path))

        # Clean up from device
        try:
            run_adb("shell", "rm", DEVICE_PATH)
        except RuntimeError:
            # Non-fatal — file may already be gone
            pass

        return {
            "status": "ok",
            "data": {
                "local_path": str(local_path),
                "timestamp": timestamp,
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Ensure the device is connected and has a writable /sdcard partition.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check ADB connection and available storage on the device.",
        }
