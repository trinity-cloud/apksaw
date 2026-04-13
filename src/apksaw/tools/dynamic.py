"""Dynamic analysis and Frida instrumentation tools for Android Threat Analyzer.

ADB-based dynamic monitoring is always available. Frida-gadget injection is
described (not auto-executed) because repackaging APKs is a user-directed,
sensitive operation that should never run without explicit confirmation.

Note on Frida: ``frida-tools`` is an optional dependency. The target device
is a stock (non-rooted) Pixel 10a, so frida-server cannot be pushed to
``/data/local/tmp``. Deeper instrumentation requires rebuilding the APK with
``frida-gadget`` injected.
"""

import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from apksaw.config import WORKSPACES_DIR, APKTOOL_JAR, TOOLS_DIR, ensure_dirs
from apksaw.server import mcp
from apksaw.session import get_session
from apksaw.utils.adb import check_device_connected, run_adb


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Standard logcat format (threadtime): "MM-DD HH:MM:SS.mmm  pid  tid prio tag  : message"
_LOGCAT_RE = re.compile(
    r"^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)"  # timestamp
    r"\s+(\d+)"                                      # pid
    r"\s+(\d+)"                                      # tid
    r"\s+([VDIWEFS])"                                # priority
    r"\s+(.*?)\s*:\s*(.*)"                           # tag : message
)


def _require_device() -> None:
    """Raise RuntimeError if no ADB device is connected."""
    if not check_device_connected():
        raise RuntimeError(
            "No ADB device connected. Connect a device and enable USB debugging."
        )


def _parse_logcat_line(line: str) -> dict | None:
    """Parse a single logcat threadtime-format line into a structured dict.

    Returns None if the line does not match the expected format.
    """
    m = _LOGCAT_RE.match(line)
    if not m:
        return None
    return {
        "timestamp": m.group(1).strip(),
        "pid": int(m.group(2)),
        "tid": int(m.group(3)),
        "priority": m.group(4),
        "tag": m.group(5).strip(),
        "message": m.group(6).strip(),
    }


def _parse_meminfo(output: str) -> dict:
    """Extract key memory figures from ``dumpsys meminfo`` output."""

    def _mb(pattern: str) -> str:
        m = re.search(pattern, output, re.IGNORECASE)
        if m:
            # Values are in kB; convert to MB for readability
            try:
                return f"{int(m.group(1).replace(',', '')) // 1024} MB"
            except ValueError:
                return m.group(1).strip()
        return "N/A"

    return {
        "java_heap_kb": _extract_kb(r"Java Heap:\s+([\d,]+)", output),
        "native_heap_kb": _extract_kb(r"Native Heap:\s+([\d,]+)", output),
        "total_pss_kb": _extract_kb(r"TOTAL PSS:\s+([\d,]+)", output),
        "total_rss_kb": _extract_kb(r"TOTAL RSS:\s+([\d,]+)", output),
        "graphics_kb": _extract_kb(r"Graphics:\s+([\d,]+)", output),
        "total_swap_kb": _extract_kb(r"TOTAL SWAP.*?:\s+([\d,]+)", output),
    }


def _extract_kb(pattern: str, text: str) -> int | None:
    """Return the first integer match of *pattern* in *text*, or None."""
    m = re.search(pattern, text, re.IGNORECASE)
    if m:
        try:
            return int(m.group(1).replace(",", ""))
        except ValueError:
            pass
    return None


def _parse_ps_line(line: str, package_name: str) -> dict | None:
    """Parse a line from ``adb shell ps -A`` that relates to *package_name*."""
    # ps -A columns: USER PID PPID VSZ RSS WCHAN ADDR S NAME
    parts = line.split()
    if len(parts) < 9:
        return None
    return {
        "user": parts[0],
        "pid": int(parts[1]),
        "ppid": int(parts[2]),
        "vsz_kb": int(parts[3]) if parts[3].isdigit() else None,
        "rss_kb": int(parts[4]) if parts[4].isdigit() else None,
        "state": parts[7],
        "name": parts[8],
    }


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@mcp.tool()
def monitor_logcat(
    session_id: str,
    package_name: str = "",
    duration: int = 10,
    filter_tag: str = "",
    filter_priority: str = "V",
) -> dict:
    """Capture logcat output from the connected Android device.

    Runs ``adb logcat`` for *duration* seconds (capped at 30) and returns
    parsed log entries. Optionally filters by package PID and/or tag.

    Args:
        session_id: Active analysis session ID (used for context only).
        package_name: If provided, resolve its PID and limit output to that
                      process via ``--pid=<pid>``.
        duration: Number of seconds of recent logs to capture (max 30).
        filter_tag: If provided, pass ``-s <tag>:<priority>`` to logcat.
        filter_priority: Minimum log priority when using filter_tag
                         (``V``, ``D``, ``I``, ``W``, ``E``, ``F``, ``S``).

    Returns:
        dict: ``{"status": "ok", "data": {"entries": [...], "count": N,
               "pid": pid_or_null, "duration": N, "raw_lines": N}}``
    """
    try:
        _require_device()

        duration = min(max(1, duration), 30)

        # Resolve PID if a package name was given
        pid: int | None = None
        if package_name:
            try:
                pid_output = run_adb("shell", "pidof", package_name)
                # pidof may return multiple space-separated PIDs; take first
                first_pid = pid_output.split()[0]
                pid = int(first_pid)
            except (RuntimeError, ValueError, IndexError):
                pid = None  # app not running — still capture global logs

        # Build logcat argument list
        logcat_args = ["shell", "logcat", "-v", "threadtime", "-d", "-t", str(duration * 100)]
        if pid is not None:
            logcat_args.append(f"--pid={pid}")
        if filter_tag:
            logcat_args += ["-s", f"{filter_tag}:{filter_priority}"]

        raw_output = run_adb(*logcat_args, timeout=duration + 15)

        lines = raw_output.splitlines()
        entries: list[dict] = []
        for line in lines:
            parsed = _parse_logcat_line(line)
            if parsed:
                entries.append(parsed)

        return {
            "status": "ok",
            "data": {
                "entries": entries,
                "count": len(entries),
                "pid": pid,
                "duration_s": duration,
                "raw_line_count": len(lines),
            },
            "meta": {
                "package_name": package_name or None,
                "filter_tag": filter_tag or None,
                "filter_priority": filter_priority,
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Ensure the device is connected and USB debugging is authorised.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check ADB connection and try again.",
        }


@mcp.tool()
def start_activity(
    package_name: str,
    activity_name: str = "",
    action: str = "",
    data_uri: str = "",
    extras: str = "",
) -> dict:
    """Launch an activity on the connected Android device.

    At least one of *activity_name* or *action* must be supplied. Extras are
    parsed as ``key=value`` pairs separated by whitespace or commas and passed
    with ``-e key value``.

    Args:
        package_name: Target application package name.
        activity_name: Fully-qualified activity class name (relative to
                       *package_name*). Passed as ``-n package/activity``.
        action: Intent action string, e.g. ``android.intent.action.VIEW``.
                Passed as ``-a action``.
        data_uri: Intent data URI, e.g. ``https://example.com``.
                  Passed as ``-d uri``.
        extras: Space- or comma-separated ``key=value`` pairs added as string
                extras with ``-e key value``.

    Returns:
        dict: ``{"status": "ok", "data": {"output": "...", "command": "..."}}``
    """
    try:
        _require_device()

        if not activity_name and not action:
            return {
                "status": "error",
                "message": "Provide at least one of activity_name or action.",
                "suggestion": "Example: activity_name='.MainActivity' or action='android.intent.action.VIEW'",
            }

        cmd = ["shell", "am", "start"]

        if activity_name:
            # Normalise leading dot shorthand
            if not activity_name.startswith(package_name) and not activity_name.startswith("."):
                activity_name = f".{activity_name}"
            cmd += ["-n", f"{package_name}/{activity_name}"]

        if action:
            cmd += ["-a", action]
            if package_name and not activity_name:
                cmd += ["-p", package_name]

        if data_uri:
            cmd += ["-d", data_uri]

        if extras:
            # Accept "key=value key2=value2" or "key=value,key2=value2"
            pairs = re.split(r"[\s,]+", extras.strip())
            for pair in pairs:
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cmd += ["-e", k.strip(), v.strip()]

        output = run_adb(*cmd)
        return {
            "status": "ok",
            "data": {
                "output": output,
                "command": "adb " + " ".join(cmd),
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Verify the package and activity names; check that the app is installed.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check ADB connection and try again.",
        }


@mcp.tool()
def send_broadcast(
    action: str,
    package_name: str = "",
    extras: str = "",
) -> dict:
    """Send a broadcast intent to the connected Android device.

    Args:
        action: Broadcast action string, e.g.
                ``android.intent.action.BOOT_COMPLETED``.
        package_name: If provided, restrict the broadcast to this package
                      via ``-p <package>``.
        extras: Space- or comma-separated ``key=value`` string extras.

    Returns:
        dict: ``{"status": "ok", "data": {"output": "...", "command": "..."}}``
    """
    try:
        _require_device()

        if not action:
            return {
                "status": "error",
                "message": "action must not be empty.",
                "suggestion": "Provide a broadcast action such as 'android.intent.action.BOOT_COMPLETED'.",
            }

        cmd = ["shell", "am", "broadcast", "-a", action]

        if package_name:
            cmd += ["-p", package_name]

        if extras:
            pairs = re.split(r"[\s,]+", extras.strip())
            for pair in pairs:
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cmd += ["-e", k.strip(), v.strip()]

        output = run_adb(*cmd)
        return {
            "status": "ok",
            "data": {
                "output": output,
                "command": "adb " + " ".join(cmd),
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Verify the action string and device connection.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check ADB connection and try again.",
        }


@mcp.tool()
def get_runtime_info(package_name: str) -> dict:
    """Retrieve runtime information about a running Android application.

    Gathers process details, memory usage, battery stats, and network UID from
    the device using ``ps``, ``dumpsys meminfo``, ``dumpsys batterystats``, and
    ``dumpsys netstats``.

    Args:
        package_name: Fully-qualified Android package name.

    Returns:
        dict: ``{"status": "ok", "data": {"process": {...}, "memory": {...},
               "battery": {...}, "network": {...}}}``
    """
    try:
        _require_device()

        if not package_name:
            return {
                "status": "error",
                "message": "package_name must not be empty.",
                "suggestion": "Provide a valid package name such as 'com.example.app'.",
            }

        # --- Process info ---
        process_info: dict = {}
        try:
            ps_output = run_adb("shell", "ps", "-A")
            processes = []
            for line in ps_output.splitlines():
                if package_name in line:
                    parsed = _parse_ps_line(line, package_name)
                    if parsed:
                        processes.append(parsed)
            process_info = {
                "processes": processes,
                "running": len(processes) > 0,
            }
        except RuntimeError as exc:
            process_info = {"error": str(exc), "running": False}

        # --- Memory info ---
        memory_info: dict = {}
        try:
            mem_output = run_adb("shell", "dumpsys", "meminfo", package_name, timeout=20)
            memory_info = _parse_meminfo(mem_output)
        except RuntimeError as exc:
            memory_info = {"error": str(exc)}

        # --- Battery stats ---
        battery_info: dict = {}
        try:
            bat_output = run_adb(
                "shell", "dumpsys", "batterystats", "--charged", package_name, timeout=30
            )
            # Extract wake lock and alarm counts (brief parse)
            wake_locks = re.findall(r"Wake lock\s+(\S+):\s+([\d.]+)\s+ms", bat_output)
            alarms = re.findall(r"Wakeup alarm\s+(\S+):\s+(\d+)\s+times", bat_output)
            battery_info = {
                "wake_locks": [{"name": n, "duration_ms": d} for n, d in wake_locks],
                "wakeup_alarms": [{"name": n, "count": int(c)} for n, c in alarms],
                "wake_lock_count": len(wake_locks),
                "alarm_count": len(alarms),
            }
        except RuntimeError as exc:
            battery_info = {"error": str(exc)}

        # --- Network stats (UID-based) ---
        network_info: dict = {}
        try:
            # Resolve UID for package
            uid_output = run_adb("shell", "dumpsys", "package", package_name)
            uid_match = re.search(r"userId=(\d+)", uid_output)
            uid = uid_match.group(1) if uid_match else None

            if uid:
                net_output = run_adb("shell", "dumpsys", "netstats", "detail", timeout=20)
                # Find lines mentioning this UID
                uid_lines = [
                    ln.strip()
                    for ln in net_output.splitlines()
                    if f"uid={uid}" in ln or f"UID={uid}" in ln
                ]
                network_info = {
                    "uid": uid,
                    "netstats_lines": uid_lines[:20],  # cap output
                }
            else:
                network_info = {"uid": None, "note": "Could not resolve UID for package."}
        except RuntimeError as exc:
            network_info = {"error": str(exc)}

        return {
            "status": "ok",
            "data": {
                "package_name": package_name,
                "process": process_info,
                "memory": memory_info,
                "battery": battery_info,
                "network": network_info,
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Ensure the device is connected and the app is installed.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check ADB connection and package name.",
        }


@mcp.tool()
def force_stop(package_name: str) -> dict:
    """Force-stop a running Android application.

    Runs ``adb shell am force-stop <package>``. If the app has multiple
    processes they are all stopped.

    Args:
        package_name: Fully-qualified Android package name.

    Returns:
        dict: ``{"status": "ok", "data": {"package_name": "...", "output": "..."}}``
    """
    try:
        _require_device()

        if not package_name:
            return {
                "status": "error",
                "message": "package_name must not be empty.",
                "suggestion": "Provide a valid package name such as 'com.example.app'.",
            }

        output = run_adb("shell", "am", "force-stop", package_name)
        return {
            "status": "ok",
            "data": {
                "package_name": package_name,
                "output": output or "(no output — force-stop succeeded)",
            },
        }

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
            "suggestion": "Check ADB connection and try again.",
        }


@mcp.tool()
def clear_app_data(package_name: str) -> dict:
    """Clear all data for an installed Android application.

    Runs ``adb shell pm clear <package>``. This removes shared preferences,
    databases, caches, and external app data. The operation cannot be undone.

    Args:
        package_name: Fully-qualified Android package name.

    Returns:
        dict: ``{"status": "ok", "data": {"package_name": "...", "output": "..."}}``
    """
    try:
        _require_device()

        if not package_name:
            return {
                "status": "error",
                "message": "package_name must not be empty.",
                "suggestion": "Provide a valid package name such as 'com.example.app'.",
            }

        output = run_adb("shell", "pm", "clear", package_name)

        success = "success" in output.lower()
        return {
            "status": "ok" if success else "error",
            "data": {
                "package_name": package_name,
                "output": output,
                "cleared": success,
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Ensure the device is connected and the package is installed.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check ADB connection and try again.",
        }


@mcp.tool()
def install_apk(apk_path: str) -> dict:
    """Install an APK file onto the connected Android device.

    Uses ``adb install -r`` so an existing installation of the same package
    is replaced without losing data. The APK must already exist on the host
    machine at *apk_path*.

    Args:
        apk_path: Absolute path to the APK file on the host machine.

    Returns:
        dict: ``{"status": "ok", "data": {"apk_path": "...", "output": "..."}}``
    """
    try:
        _require_device()

        if not apk_path:
            return {
                "status": "error",
                "message": "apk_path must not be empty.",
                "suggestion": "Provide the absolute path to the APK file.",
            }

        local = Path(apk_path)
        if not local.exists():
            return {
                "status": "error",
                "message": f"APK file not found: {apk_path}",
                "suggestion": "Verify the path and ensure the file exists on the host.",
            }

        if local.suffix.lower() != ".apk":
            return {
                "status": "error",
                "message": f"File does not appear to be an APK: {apk_path}",
                "suggestion": "Provide a file with a .apk extension.",
            }

        output = run_adb("install", "-r", str(local), timeout=120)
        success = "success" in output.lower()
        return {
            "status": "ok" if success else "error",
            "data": {
                "apk_path": str(local),
                "output": output,
                "installed": success,
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Check that the device is connected and accepts app installs (no MDM block).",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check ADB connection and APK validity.",
        }


@mcp.tool()
def uninstall_app(package_name: str) -> dict:
    """Uninstall an application from the connected Android device.

    Runs ``adb uninstall <package>``. System apps cannot be uninstalled this
    way — use ``pm disable-user`` for those instead.

    Args:
        package_name: Fully-qualified Android package name.

    Returns:
        dict: ``{"status": "ok", "data": {"package_name": "...", "output": "..."}}``
    """
    try:
        _require_device()

        if not package_name:
            return {
                "status": "error",
                "message": "package_name must not be empty.",
                "suggestion": "Provide a valid package name such as 'com.example.app'.",
            }

        output = run_adb("uninstall", package_name)
        success = "success" in output.lower()
        return {
            "status": "ok" if success else "error",
            "data": {
                "package_name": package_name,
                "output": output,
                "uninstalled": success,
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Verify the package is installed and not a system app.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check ADB connection and try again.",
        }


@mcp.tool()
def take_screenshot(output_path: str = "") -> dict:
    """Capture a screenshot of the connected device's screen.

    Takes a screenshot via ``adb shell screencap``, pulls it to the host, then
    removes the temporary file from the device. If *output_path* is omitted the
    image is saved to the analysis workspace under a timestamped filename.

    Args:
        output_path: Optional absolute path on the host where the PNG should be
                     saved. Directories are created if they do not exist.

    Returns:
        dict: ``{"status": "ok", "data": {"local_path": "...", "timestamp": "..."}}``
    """
    DEVICE_TMP = "/sdcard/screenshot_tmp.png"

    try:
        _require_device()
        ensure_dirs()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if output_path:
            local = Path(output_path)
        else:
            screenshots_dir = WORKSPACES_DIR / "screenshots"
            screenshots_dir.mkdir(parents=True, exist_ok=True)
            local = screenshots_dir / f"screenshot_{timestamp}.png"

        local.parent.mkdir(parents=True, exist_ok=True)

        # Capture on device
        run_adb("shell", "screencap", "-p", DEVICE_TMP)

        # Pull to host
        run_adb("pull", DEVICE_TMP, str(local))

        # Clean up from device (non-fatal)
        try:
            run_adb("shell", "rm", DEVICE_TMP)
        except RuntimeError:
            pass

        return {
            "status": "ok",
            "data": {
                "local_path": str(local),
                "timestamp": timestamp,
            },
        }

    except RuntimeError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Ensure the device is connected and /sdcard is writable.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check ADB connection and available device storage.",
        }


@mcp.tool()
def prepare_frida_apk(session_id: str, frida_script: str = "") -> dict:
    """Describe (and optionally verify tool availability for) Frida-gadget APK injection.

    Because injecting code into APKs is a sensitive, multi-step operation it is
    intentionally **not** fully automated. This tool:

    1. Resolves the APK path from the active session.
    2. Checks whether ``apktool``, ``zipalign``, ``apksigner``, and the Frida
       gadget shared library are available.
    3. Returns step-by-step shell commands the analyst should run manually to
       repackage the APK with ``frida-gadget`` and re-sign it.

    This approach keeps the analyst in control of a process that modifies
    application binaries. The resulting APK must be signed with a test key
    before installation.

    Args:
        session_id: Active analysis session ID — used to locate the source APK.
        frida_script: Optional path to a custom Frida JavaScript file that
                      should be bundled alongside the gadget.

    Returns:
        dict: ``{"status": "ok", "data": {"apk_path": "...", "tool_check": {...},
               "steps": [...], "commands": [...]}}``
    """
    try:
        session = get_session(session_id)
        apk_path = str(session.apk_path)
        package_name = session.package_name or session.apk_path.stem
        workspace = str(session.workspace)

        # --- Tool availability checks ---
        tool_check: dict = {}

        # apktool
        apktool_ok = False
        apktool_cmd = ""
        if APKTOOL_JAR.exists():
            apktool_ok = True
            apktool_cmd = f"java -jar {APKTOOL_JAR}"
        elif shutil.which("apktool"):
            apktool_ok = True
            apktool_cmd = "apktool"
        tool_check["apktool"] = {
            "available": apktool_ok,
            "command": apktool_cmd or None,
            "note": "Install via: brew install apktool  OR  download apktool.jar",
        }

        # zipalign
        zipalign_path = shutil.which("zipalign")
        tool_check["zipalign"] = {
            "available": zipalign_path is not None,
            "path": zipalign_path,
            "note": "Part of Android SDK build-tools; add build-tools to PATH.",
        }

        # apksigner
        apksigner_path = shutil.which("apksigner")
        tool_check["apksigner"] = {
            "available": apksigner_path is not None,
            "path": apksigner_path,
            "note": "Part of Android SDK build-tools.",
        }

        # Frida gadget shared library (arm64-v8a is most common for Pixel devices)
        gadget_search_dirs = [
            TOOLS_DIR / "frida-gadget",
            Path.home() / ".apksaw" / "tools" / "frida-gadget",
            Path("/tmp/frida-gadget"),
        ]
        gadget_path: str | None = None
        for d in gadget_search_dirs:
            candidate = d / "libfrida-gadget.so"
            if candidate.exists():
                gadget_path = str(candidate)
                break
        tool_check["frida_gadget_so"] = {
            "available": gadget_path is not None,
            "path": gadget_path,
            "note": (
                "Download from https://github.com/frida/frida/releases — "
                f"choose frida-gadget-*-android-arm64.so.xz and place as "
                f"{gadget_search_dirs[0] / 'libfrida-gadget.so'}"
            ),
        }

        # frida-tools Python package
        try:
            import frida  # noqa: F401
            frida_tools_ok = True
            import importlib.metadata
            frida_version = importlib.metadata.version("frida")
        except ImportError:
            frida_tools_ok = False
            frida_version = None
        tool_check["frida_tools_python"] = {
            "available": frida_tools_ok,
            "version": frida_version,
            "note": "Install via: pip install frida-tools",
        }

        all_ok = apktool_ok and zipalign_path and apksigner_path and gadget_path

        # --- Step-by-step instructions ---
        decompile_dir = f"{workspace}/decompiled"
        recompiled_apk = f"{workspace}/{package_name}_patched_unsigned.apk"
        aligned_apk = f"{workspace}/{package_name}_patched_aligned.apk"
        signed_apk = f"{workspace}/{package_name}_patched_signed.apk"
        keystore = f"{workspace}/debug.keystore"
        gadget_dest = f"{decompile_dir}/lib/arm64-v8a/libfrida-gadget.so"
        gadget_config = f"{decompile_dir}/lib/arm64-v8a/libfrida-gadget.config.so"

        steps = [
            {
                "step": 1,
                "title": "Decompile the APK with apktool",
                "description": (
                    f"Decode the APK resources and smali code into {decompile_dir}. "
                    "The -f flag overwrites any previous decompilation."
                ),
            },
            {
                "step": 2,
                "title": "Copy the Frida gadget shared library",
                "description": (
                    f"Copy libfrida-gadget.so to {gadget_dest}. "
                    "Create the arm64-v8a directory if it does not exist. "
                    "For 32-bit device support also add an armeabi-v7a copy."
                ),
            },
            {
                "step": 3,
                "title": "Write a gadget configuration file (optional)",
                "description": (
                    f"Create {gadget_config} to control how the gadget behaves. "
                    "In listen mode the gadget waits for a Frida client to attach. "
                    "In script mode it executes a bundled JS file automatically."
                ),
            },
            {
                "step": 4,
                "title": "Patch the smali entry point to load the gadget",
                "description": (
                    "Find the application's main Activity (or Application subclass) "
                    "in the smali source and insert a System.loadLibrary(\"frida-gadget\") "
                    "call as early as possible — ideally at the top of the static "
                    "initialiser (<clinit>) or onCreate. The smali instruction is:\n"
                    '    const-string v0, "frida-gadget"\n'
                    "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V"
                ),
            },
            {
                "step": 5,
                "title": "Rebuild the APK with apktool",
                "description": f"Recompile the smali back to an APK at {recompiled_apk}.",
            },
            {
                "step": 6,
                "title": "Zipalign the APK",
                "description": (
                    f"Align the APK to 4-byte boundaries (required before signing): "
                    f"{aligned_apk}"
                ),
            },
            {
                "step": 7,
                "title": "Sign the APK",
                "description": (
                    f"Generate a debug keystore (if you do not already have one) and sign "
                    f"the aligned APK. The resulting file is {signed_apk}."
                ),
            },
            {
                "step": 8,
                "title": "Install the patched APK",
                "description": (
                    "Uninstall the original app first (its signature differs from the "
                    "re-signed version), then install the patched APK. "
                    "Use -r only if the original is already uninstalled."
                ),
            },
            {
                "step": 9,
                "title": "Attach Frida and run your script",
                "description": (
                    "Launch the app on the device. The gadget will pause execution "
                    "and wait for a Frida client. Connect from the host:"
                ),
            },
        ]

        gadget_config_json = (
            '{\n'
            '  "interaction": {\n'
            '    "type": "listen",\n'
            '    "address": "127.0.0.1",\n'
            '    "port": 27042,\n'
            '    "on_load": "wait"\n'
            '  }\n'
            '}'
        )

        if frida_script:
            gadget_config_json = (
                '{\n'
                '  "interaction": {\n'
                '    "type": "script",\n'
                f'    "path": "/data/local/tmp/frida_script.js"\n'
                '  }\n'
                '}'
            )

        commands = [
            f"# Step 1 — Decompile",
            f"{apktool_cmd or 'apktool'} d -f -o {decompile_dir} {apk_path}",
            "",
            f"# Step 2 — Copy gadget",
            f"mkdir -p {decompile_dir}/lib/arm64-v8a",
            f"cp {gadget_path or '/path/to/libfrida-gadget.so'} {gadget_dest}",
            "",
            f"# Step 3 — Write gadget config",
            f"cat > {gadget_config} << 'GADGET_CONFIG'\n{gadget_config_json}\nGADGET_CONFIG",
            "",
            "# Step 4 — Patch smali (manual edit required — see step description above)",
            "",
            f"# Step 5 — Rebuild",
            f"{apktool_cmd or 'apktool'} b {decompile_dir} -o {recompiled_apk}",
            "",
            f"# Step 6 — Zipalign",
            f"{zipalign_path or 'zipalign'} -v 4 {recompiled_apk} {aligned_apk}",
            "",
            f"# Step 7 — Create keystore (first time only)",
            f"keytool -genkey -v -keystore {keystore} -alias androiddebugkey "
            f"-keyalg RSA -keysize 2048 -validity 10000 "
            f"-storepass android -keypass android -dname 'CN=Android Debug,O=Android,C=US'",
            f"# Step 7 — Sign",
            f"{apksigner_path or 'apksigner'} sign --ks {keystore} "
            f"--ks-pass pass:android --key-pass pass:android --out {signed_apk} {aligned_apk}",
            "",
            f"# Step 8 — Install (uninstall original first if same package)",
            f"adb uninstall {package_name}",
            f"adb install {signed_apk}",
            "",
            "# Step 9 — Attach Frida (after launching the app on device)",
            "adb forward tcp:27042 tcp:27042",
            f"frida -H 127.0.0.1:27042 -f {package_name}",
        ]

        if frida_script:
            commands += [
                "",
                "# Or run with a script directly:",
                f"frida -H 127.0.0.1:27042 -f {package_name} -l {frida_script}",
            ]

        return {
            "status": "ok",
            "data": {
                "apk_path": apk_path,
                "package_name": package_name,
                "workspace": workspace,
                "tools_ready": all_ok,
                "tool_check": tool_check,
                "steps": steps,
                "commands": commands,
                "note": (
                    "This tool describes the injection process but does NOT execute it. "
                    "Run the commands above manually after reviewing each step. "
                    "Frida-gadget injection modifies the APK — only proceed on apps "
                    "you have authorisation to analyse."
                ),
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session, then pass the session_id.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Check that the session_id is valid.",
        }
