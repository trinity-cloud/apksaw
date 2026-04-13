"""Session management for APK analysis.

Sessions are persisted to SQLite via :mod:`apksaw.db` so that
previously analysed APKs can be restored across process restarts without
re-running Androguard.  Androguard objects themselves (APK, DEX, Analysis)
are never serialised — they are loaded lazily on first access.

On module import, :func:`restore_sessions` is called automatically to
populate the in-memory ``_sessions`` dict with lightweight metadata stubs
for every session found in the database.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .config import WORKSPACES_DIR, ensure_dirs
from . import db


@dataclass
class Session:
    """Holds state for an APK analysis session."""

    session_id: str
    apk_path: Path
    sha256: str
    package_name: str = ""
    workspace: Path = field(default=None)

    # Lazy-loaded Androguard objects
    _apk_obj: Any = field(default=None, repr=False)
    _dex_list: Any = field(default=None, repr=False)
    _analysis_obj: Any = field(default=None, repr=False)

    def __post_init__(self):
        if self.workspace is None:
            self.workspace = WORKSPACES_DIR / self.sha256
            self.workspace.mkdir(parents=True, exist_ok=True)

    def get_androguard(self) -> tuple:
        """Return (apk, dex_list, analysis), loading if needed."""
        if self._apk_obj is None:
            from androguard.misc import AnalyzeAPK

            self._apk_obj, self._dex_list, self._analysis_obj = AnalyzeAPK(
                str(self.apk_path)
            )
            self.package_name = self._apk_obj.get_package()
        return self._apk_obj, self._dex_list, self._analysis_obj

    @property
    def apk(self):
        """Androguard APK object."""
        self.get_androguard()
        return self._apk_obj

    @property
    def dex_list(self):
        """List of DalvikVMFormat objects."""
        self.get_androguard()
        return self._dex_list

    @property
    def analysis(self):
        """Androguard Analysis object with cross-references."""
        self.get_androguard()
        return self._analysis_obj


# ---------------------------------------------------------------------------
# Global session store
# ---------------------------------------------------------------------------

# Maps session_id -> Session.  Populated from SQLite at import time by
# restore_sessions() and extended by create_session() at runtime.
_sessions: dict[str, Session] = {}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _session_from_row(row: dict) -> Session:
    """Build a lightweight Session stub from a DB row.

    The APK file may no longer be present on disk (e.g. analysed on a
    different machine or the APK was moved).  We do not raise here —
    the missing file will only surface when the caller actually accesses
    ``session.apk`` / ``session.analysis``.
    """
    return Session(
        session_id=row["session_id"],
        apk_path=Path(row["apk_path"]),
        sha256=row["sha256"],
        package_name=row.get("package_name", ""),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def restore_sessions() -> None:
    """Load all persisted session metadata from SQLite into ``_sessions``.

    Called automatically at module import time.  Only metadata is restored;
    Androguard objects are *not* loaded until actually needed (lazy loading).

    Silently ignores any database errors so that a missing or corrupt DB
    does not prevent the tool from starting up.
    """
    try:
        db.init_db()
        for row in db.list_all_sessions():
            sid = row["session_id"]
            if sid not in _sessions:
                _sessions[sid] = _session_from_row(row)
    except Exception:
        # Do not crash on import if the DB is unavailable
        pass


def create_session(apk_path: str) -> Session:
    """Create (or restore) an analysis session for an APK file.

    Workflow:
    1. Compute the SHA-256 of the APK.
    2. Check the in-memory cache — return the existing session if present.
    3. Check the SQLite database — if a prior session exists for this APK,
       restore it without re-running Androguard.
    4. Otherwise create a fresh session and persist it to the database.

    Args:
        apk_path: Filesystem path to the APK file.

    Returns:
        A :class:`Session` object.  The Androguard objects inside it are
        *not* yet loaded; they are initialised lazily on first access.

    Raises:
        FileNotFoundError: If the APK file does not exist.
    """
    ensure_dirs()
    path = Path(apk_path)
    if not path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    sha256 = hashlib.sha256(path.read_bytes()).hexdigest()

    # 1. In-memory cache hit
    for s in _sessions.values():
        if s.sha256 == sha256:
            db.touch_session(s.session_id)
            return s

    # 2. Database hit — restore without re-analysis
    db.init_db()
    existing = db.load_session(sha256)
    if existing is not None:
        session = _session_from_row(existing)
        # Always use the current apk_path in case the file was moved
        session.apk_path = path
        _sessions[session.session_id] = session
        db.touch_session(session.session_id)
        return session

    # 3. Brand-new session
    session_id = uuid.uuid4().hex[:12]
    session = Session(session_id=session_id, apk_path=path, sha256=sha256)
    _sessions[session_id] = session
    db.save_session(session)
    return session


def get_session(session_id: str) -> Session:
    """Retrieve an existing session by ID and update its last-accessed time.

    Args:
        session_id: The session identifier returned by :func:`create_session`.

    Returns:
        The corresponding :class:`Session` object.

    Raises:
        KeyError: If no session with the given ID is found.
    """
    if session_id not in _sessions:
        raise KeyError(
            f"Session '{session_id}' not found. "
            f"Available sessions: {list(_sessions.keys())}. "
            f"Call load_apk first to create a session."
        )
    session = _sessions[session_id]
    try:
        db.touch_session(session_id)
    except Exception:
        pass  # Do not fail if DB is temporarily unavailable
    return session


def list_sessions() -> list[dict]:
    """List all active sessions (in-memory).

    Returns:
        A list of dicts with ``session_id``, ``package_name``, ``sha256``,
        and ``apk_path`` for every session currently loaded in memory.
    """
    return [
        {
            "session_id": s.session_id,
            "package_name": s.package_name,
            "sha256": s.sha256,
            "apk_path": str(s.apk_path),
        }
        for s in _sessions.values()
    ]


# ---------------------------------------------------------------------------
# Restore persisted sessions on import
# ---------------------------------------------------------------------------

restore_sessions()
