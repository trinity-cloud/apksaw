"""Configuration and path management."""

import os
from pathlib import Path

BASE_DIR = Path(os.environ.get("APKSAW_HOME", Path.home() / ".apksaw"))
TOOLS_DIR = BASE_DIR / "tools"
WORKSPACES_DIR = BASE_DIR / "workspaces"
DB_PATH = BASE_DIR / "db" / "index.db"

# External tool paths
JADX_BIN = TOOLS_DIR / "jadx" / "bin" / "jadx"
APKTOOL_JAR = TOOLS_DIR / "apktool.jar"

# ADB
ADB_PATH = os.environ.get("ADB_PATH", "adb")

# Defaults
DEFAULT_LIMIT = 50
MAX_LIMIT = 500


def ensure_dirs():
    """Create all required directories."""
    for d in [TOOLS_DIR, WORKSPACES_DIR, DB_PATH.parent]:
        d.mkdir(parents=True, exist_ok=True)
