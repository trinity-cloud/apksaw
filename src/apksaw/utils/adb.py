"""ADB command wrapper utilities."""

import asyncio
import subprocess
from ..config import ADB_PATH


def run_adb(*args: str, timeout: int = 30) -> str:
    """Run an ADB command synchronously and return stdout."""
    cmd = [ADB_PATH] + list(args)
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"ADB command failed: {' '.join(cmd)}\n"
            f"stderr: {result.stderr.strip()}"
        )
    return result.stdout.strip()


async def run_adb_async(*args: str, timeout: int = 30) -> str:
    """Run an ADB command asynchronously and return stdout."""
    cmd = [ADB_PATH] + list(args)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise TimeoutError(f"ADB command timed out after {timeout}s: {' '.join(cmd)}")

    if proc.returncode != 0:
        raise RuntimeError(
            f"ADB command failed: {' '.join(cmd)}\n"
            f"stderr: {stderr.decode().strip()}"
        )
    return stdout.decode().strip()


def check_device_connected() -> bool:
    """Check if any ADB device is connected."""
    try:
        output = run_adb("devices")
        lines = output.strip().split("\n")
        return any("device" in line and "List" not in line for line in lines)
    except (RuntimeError, FileNotFoundError):
        return False
