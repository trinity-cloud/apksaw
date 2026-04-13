"""JADX decompiler wrapper."""

import asyncio
import subprocess
from pathlib import Path
from ..config import JADX_BIN


async def run_jadx(apk_path: str, output_dir: str, extra_args: list[str] | None = None) -> str:
    """Run JADX to decompile an APK.

    Args:
        apk_path: Path to the APK file.
        output_dir: Directory to write decompiled sources into.
        extra_args: Additional CLI arguments passed to JADX after the defaults.

    Returns:
        Combined stdout + stderr output from JADX as a string.

    Raises:
        FileNotFoundError: If the APK does not exist.
        RuntimeError: If JADX exits with a non-zero status code.
    """
    apk = Path(apk_path)
    if not apk.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    jadx_bin = _resolve_jadx_bin()

    cmd = [
        str(jadx_bin),
        "-d", str(out),
        "--no-imports",
        "--no-debug-info",
        *(extra_args or []),
        str(apk),
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout_bytes, stderr_bytes = await proc.communicate()
    combined = (stdout_bytes + stderr_bytes).decode(errors="replace")

    if proc.returncode != 0:
        raise RuntimeError(
            f"JADX exited with code {proc.returncode}.\n"
            f"Command: {' '.join(cmd)}\n"
            f"Output:\n{combined}"
        )

    return combined


def check_jadx() -> bool:
    """Check if JADX is available and executable.

    Returns:
        True if JADX binary exists and responds to --version.
    """
    jadx_bin = JADX_BIN
    if not jadx_bin.exists():
        return False

    try:
        result = subprocess.run(
            [str(jadx_bin), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


async def decompile_apk(apk_path: str, output_dir: str) -> Path:
    """Full APK decompilation with JADX.

    Ensures JADX is installed (downloads it if necessary), then decompiles
    the given APK into *output_dir*.

    Args:
        apk_path: Path to the APK file.
        output_dir: Directory where decompiled sources will be written.

    Returns:
        Path to the output directory containing the decompiled sources.

    Raises:
        FileNotFoundError: If the APK does not exist.
        RuntimeError: If JADX installation or decompilation fails.
    """
    apk = Path(apk_path)
    if not apk.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    if not check_jadx():
        # Attempt to bootstrap JADX automatically
        from .bootstrap import ensure_jadx
        print("JADX not found — attempting to download...")
        ensure_jadx()

        if not check_jadx():
            raise RuntimeError(
                f"JADX still not available after bootstrap attempt. "
                f"Expected binary at {JADX_BIN}."
            )

    out = Path(output_dir)
    print(f"Decompiling {apk.name} -> {out} ...")
    await run_jadx(apk_path, output_dir)
    print(f"Decompilation complete: {out}")
    return out


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_jadx_bin() -> Path:
    """Return the JADX binary path, raising RuntimeError if absent."""
    if not JADX_BIN.exists():
        raise RuntimeError(
            f"JADX binary not found at {JADX_BIN}. "
            "Run bootstrap.ensure_jadx() to install it."
        )
    return JADX_BIN
