"""Bootstrap external tool dependencies."""

import os
import stat
import zipfile
import urllib.request
from pathlib import Path
from ..config import TOOLS_DIR, JADX_BIN, APKTOOL_JAR, ensure_dirs

# Tool versions and download URLs
JADX_VERSION = "1.5.1"
APKTOOL_VERSION = "2.10.0"

JADX_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"
APKTOOL_URL = f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VERSION}/apktool_{APKTOOL_VERSION}.jar"


def _progress_hook(label: str):
    """Return a urllib reporthook that prints download progress."""
    def hook(block_num: int, block_size: int, total_size: int):
        if total_size <= 0:
            downloaded = block_num * block_size
            print(f"\r{label}: {downloaded // 1024} KB downloaded...", end="", flush=True)
        else:
            downloaded = min(block_num * block_size, total_size)
            pct = downloaded * 100 // total_size
            bar_len = 30
            filled = bar_len * downloaded // total_size
            bar = "#" * filled + "-" * (bar_len - filled)
            print(f"\r{label}: [{bar}] {pct}%", end="", flush=True)
    return hook


def ensure_jadx() -> Path:
    """Download JADX zip, extract to TOOLS_DIR/jadx/, make bin/jadx executable.

    Returns the path to the JADX binary. Skips download if already present.

    Raises:
        RuntimeError: on network failure or extraction error.
    """
    ensure_dirs()

    if JADX_BIN.exists():
        print(f"JADX already present at {JADX_BIN}")
        return JADX_BIN

    jadx_dir = TOOLS_DIR / "jadx"
    zip_path = TOOLS_DIR / f"jadx-{JADX_VERSION}.zip"

    print(f"Downloading JADX {JADX_VERSION} from {JADX_URL}")
    try:
        urllib.request.urlretrieve(JADX_URL, zip_path, reporthook=_progress_hook("JADX"))
        print()  # newline after progress bar
    except Exception as exc:
        # Clean up partial download
        zip_path.unlink(missing_ok=True)
        raise RuntimeError(f"Failed to download JADX: {exc}") from exc

    print(f"Extracting JADX to {jadx_dir} ...")
    try:
        jadx_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(jadx_dir)
    except zipfile.BadZipFile as exc:
        jadx_dir.rmdir()
        zip_path.unlink(missing_ok=True)
        raise RuntimeError(f"JADX zip is corrupt: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"Failed to extract JADX (disk space?): {exc}") from exc
    finally:
        zip_path.unlink(missing_ok=True)

    if not JADX_BIN.exists():
        raise RuntimeError(
            f"Extraction succeeded but JADX binary not found at {JADX_BIN}. "
            "The zip layout may have changed — check the release archive."
        )

    # Make the binary executable
    current_mode = JADX_BIN.stat().st_mode
    JADX_BIN.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Also fix jadx-gui if present
    jadx_gui = JADX_BIN.parent / "jadx-gui"
    if jadx_gui.exists():
        jadx_gui.chmod(jadx_gui.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"JADX installed at {JADX_BIN}")
    return JADX_BIN


def ensure_apktool() -> Path:
    """Download apktool jar to TOOLS_DIR/apktool.jar.

    Returns the path to the jar. Skips download if already present.

    Raises:
        RuntimeError: on network failure.
    """
    ensure_dirs()

    if APKTOOL_JAR.exists():
        print(f"apktool already present at {APKTOOL_JAR}")
        return APKTOOL_JAR

    print(f"Downloading apktool {APKTOOL_VERSION} from {APKTOOL_URL}")
    try:
        urllib.request.urlretrieve(APKTOOL_URL, APKTOOL_JAR, reporthook=_progress_hook("apktool"))
        print()  # newline after progress bar
    except Exception as exc:
        APKTOOL_JAR.unlink(missing_ok=True)
        raise RuntimeError(f"Failed to download apktool: {exc}") from exc

    if APKTOOL_JAR.stat().st_size < 1024:
        APKTOOL_JAR.unlink(missing_ok=True)
        raise RuntimeError("apktool download appears incomplete (file too small).")

    print(f"apktool installed at {APKTOOL_JAR}")
    return APKTOOL_JAR


def ensure_all_tools() -> dict:
    """Ensure all required tools are present, downloading if necessary.

    Returns:
        dict with keys "jadx" and "apktool", each mapping to a dict with:
            - "path": Path to the tool (or None on failure)
            - "ok": bool — True if the tool is ready to use
            - "error": str or None — error message on failure
    """
    results: dict[str, dict] = {}

    for name, fn in (("jadx", ensure_jadx), ("apktool", ensure_apktool)):
        try:
            path = fn()
            results[name] = {"path": path, "ok": True, "error": None}
        except RuntimeError as exc:
            results[name] = {"path": None, "ok": False, "error": str(exc)}

    return results


def check_tools() -> dict:
    """Check which tools are available without downloading anything.

    Returns:
        dict with keys "jadx" and "apktool", each mapping to a dict with:
            - "path": Path or None
            - "ok": bool
            - "version": str or None (reported version string where detectable)
    """
    import subprocess

    results: dict[str, dict] = {}

    # --- JADX ---
    jadx_ok = JADX_BIN.exists() and os.access(JADX_BIN, os.X_OK)
    jadx_version: str | None = None
    if jadx_ok:
        try:
            proc = subprocess.run(
                [str(JADX_BIN), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            jadx_version = proc.stdout.strip() or proc.stderr.strip() or None
        except Exception:
            pass
    results["jadx"] = {
        "path": JADX_BIN if jadx_ok else None,
        "ok": jadx_ok,
        "version": jadx_version,
    }

    # --- apktool ---
    apktool_ok = APKTOOL_JAR.exists() and APKTOOL_JAR.stat().st_size > 1024
    apktool_version: str | None = None
    if apktool_ok:
        try:
            proc = subprocess.run(
                ["java", "-jar", str(APKTOOL_JAR), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            apktool_version = proc.stdout.strip() or proc.stderr.strip() or None
        except Exception:
            pass
    results["apktool"] = {
        "path": APKTOOL_JAR if apktool_ok else None,
        "ok": apktool_ok,
        "version": apktool_version,
    }

    return results
