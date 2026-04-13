"""SQLite persistence layer for apksaw sessions and analysis data.

All data lives in a single SQLite database at ``config.DB_PATH``.
The schema is created lazily on first use via ``init_db()``.

Schema overview:
    sessions      — one row per unique APK (keyed by sha256)
    classes       — class index extracted from DEX
    methods       — method index extracted from DEX
    strings_cache — interesting string values found in the APK
    findings      — cached security-scan results per scanner
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

from .config import DB_PATH, ensure_dirs


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    sha256       TEXT UNIQUE NOT NULL,
    apk_path     TEXT NOT NULL,
    package_name TEXT DEFAULT '',
    version_name TEXT DEFAULT '',
    version_code TEXT DEFAULT '',
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS classes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256       TEXT NOT NULL,
    class_name   TEXT NOT NULL,
    dalvik_name  TEXT NOT NULL,
    method_count INTEGER DEFAULT 0,
    field_count  INTEGER DEFAULT 0,
    is_external  BOOLEAN DEFAULT 0,
    dex_index    INTEGER DEFAULT 0,
    UNIQUE(sha256, dalvik_name)
);

CREATE TABLE IF NOT EXISTS methods (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256       TEXT NOT NULL,
    class_name   TEXT NOT NULL,
    method_name  TEXT NOT NULL,
    descriptor   TEXT DEFAULT '',
    access_flags TEXT DEFAULT '',
    is_external  BOOLEAN DEFAULT 0,
    UNIQUE(sha256, class_name, method_name, descriptor)
);

CREATE TABLE IF NOT EXISTS strings_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256      TEXT NOT NULL,
    value       TEXT NOT NULL,
    xref_count  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256       TEXT NOT NULL,
    scanner      TEXT NOT NULL,
    severity     TEXT NOT NULL,
    title        TEXT NOT NULL,
    finding_json TEXT NOT NULL,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_classes_sha256  ON classes(sha256);
CREATE INDEX IF NOT EXISTS idx_methods_sha256  ON methods(sha256);
CREATE INDEX IF NOT EXISTS idx_strings_sha256  ON strings_cache(sha256);
CREATE INDEX IF NOT EXISTS idx_findings_sha256 ON findings(sha256);
"""


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    """Context manager that yields a configured SQLite connection.

    Enables WAL mode for better concurrent read performance and sets a
    sensible busy-timeout so parallel writers don't immediately fail.
    Row factory is set to ``sqlite3.Row`` so callers can access columns
    by name.
    """
    con = sqlite3.connect(str(DB_PATH), timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Create all tables and indexes if they do not already exist.

    Safe to call multiple times (uses ``CREATE TABLE IF NOT EXISTS``).
    Also ensures the directory containing the database file exists.
    """
    ensure_dirs()
    with _conn() as con:
        con.executescript(_DDL)


def save_session(session: Any) -> None:
    """Persist session metadata to the ``sessions`` table.

    Accepts a ``Session`` dataclass instance (from ``session.py``).
    If a row for this ``sha256`` already exists it is replaced, which
    updates the ``apk_path`` and metadata fields but preserves
    ``created_at``.

    Args:
        session: A ``Session`` object with at least ``session_id``,
                 ``sha256``, ``apk_path``, and ``package_name``.
    """
    with _conn() as con:
        con.execute(
            """
            INSERT INTO sessions
                (session_id, sha256, apk_path, package_name,
                 version_name, version_code)
            VALUES (?, ?, ?, ?, ?, '')
            ON CONFLICT(sha256) DO UPDATE SET
                session_id   = excluded.session_id,
                apk_path     = excluded.apk_path,
                package_name = excluded.package_name,
                version_name = excluded.version_name,
                last_accessed = CURRENT_TIMESTAMP
            """,
            (
                session.session_id,
                session.sha256,
                str(session.apk_path),
                session.package_name or "",
                getattr(session, "version_name", "") or "",
            ),
        )


def load_session(sha256: str) -> dict | None:
    """Look up a previously persisted session by APK SHA-256 hash.

    Returns a plain dict with session metadata if found, or ``None`` if
    no session exists for this APK.

    Args:
        sha256: Hex-encoded SHA-256 digest of the APK file.

    Returns:
        A dict with keys ``session_id``, ``sha256``, ``apk_path``,
        ``package_name``, ``version_name``, ``version_code``,
        ``created_at``, and ``last_accessed``; or ``None``.
    """
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM sessions WHERE sha256 = ?", (sha256,)
        ).fetchone()
    if row is None:
        return None
    return dict(row)


def touch_session(session_id: str) -> None:
    """Update the ``last_accessed`` timestamp for the given session.

    Args:
        session_id: The session identifier to touch.
    """
    with _conn() as con:
        con.execute(
            "UPDATE sessions SET last_accessed = CURRENT_TIMESTAMP "
            "WHERE session_id = ?",
            (session_id,),
        )


def list_all_sessions() -> list[dict]:
    """Return metadata for every persisted session, newest first.

    Returns:
        A list of dicts (same shape as :func:`load_session`), ordered by
        ``last_accessed`` descending.  Returns an empty list when no
        sessions have been saved yet.
    """
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM sessions ORDER BY last_accessed DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_session(sha256: str) -> None:
    """Remove all persisted data for an APK identified by its SHA-256 hash.

    Deletes rows from ``sessions``, ``classes``, ``methods``,
    ``strings_cache``, and ``findings``.

    Args:
        sha256: Hex-encoded SHA-256 digest of the APK to remove.
    """
    with _conn() as con:
        for table in ("sessions", "classes", "methods", "strings_cache", "findings"):
            con.execute(f"DELETE FROM {table} WHERE sha256 = ?", (sha256,))


# ---------------------------------------------------------------------------
# Classes
# ---------------------------------------------------------------------------

def save_classes(sha256: str, classes_list: list[dict]) -> None:
    """Bulk-insert class index entries for an APK.

    Duplicate ``(sha256, dalvik_name)`` pairs are silently ignored so this
    function is idempotent and safe to call again after a re-analysis.

    Args:
        sha256:       Hex-encoded SHA-256 of the APK.
        classes_list: Iterable of dicts with keys ``class_name``,
                      ``dalvik_name``, ``method_count``, ``field_count``,
                      ``is_external``, and optionally ``dex_index``.
    """
    rows = [
        (
            sha256,
            c.get("class_name", ""),
            c.get("dalvik_name", ""),
            c.get("method_count", 0),
            c.get("field_count", 0),
            int(bool(c.get("is_external", False))),
            c.get("dex_index", 0),
        )
        for c in classes_list
    ]
    with _conn() as con:
        con.executemany(
            """
            INSERT OR IGNORE INTO classes
                (sha256, class_name, dalvik_name, method_count,
                 field_count, is_external, dex_index)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def load_classes(
    sha256: str,
    filter: str = "",
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """Query the cached class index for an APK.

    Args:
        sha256:  Hex-encoded SHA-256 of the APK.
        filter:  Optional SQL ``LIKE`` pattern applied to ``class_name``
                 (e.g. ``'%Activity%'``).  An empty string returns all classes.
        limit:   Maximum number of rows to return (default 50).
        offset:  Row offset for pagination (default 0).

    Returns:
        A list of dicts with keys ``class_name``, ``dalvik_name``,
        ``method_count``, ``field_count``, ``is_external``, ``dex_index``.
        Returns an empty list if the APK has not been indexed yet.
    """
    with _conn() as con:
        if filter:
            rows = con.execute(
                """
                SELECT class_name, dalvik_name, method_count,
                       field_count, is_external, dex_index
                FROM classes
                WHERE sha256 = ? AND class_name LIKE ?
                ORDER BY class_name
                LIMIT ? OFFSET ?
                """,
                (sha256, filter, limit, offset),
            ).fetchall()
        else:
            rows = con.execute(
                """
                SELECT class_name, dalvik_name, method_count,
                       field_count, is_external, dex_index
                FROM classes
                WHERE sha256 = ?
                ORDER BY class_name
                LIMIT ? OFFSET ?
                """,
                (sha256, limit, offset),
            ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def save_findings(sha256: str, scanner: str, findings: list[dict]) -> None:
    """Cache security-scan findings for an APK and scanner combination.

    Each finding dict is serialized to JSON and stored as a row.  Existing
    findings for the same ``(sha256, scanner)`` pair are deleted first so
    re-running a scanner always replaces stale results.

    Args:
        sha256:   Hex-encoded SHA-256 of the APK.
        scanner:  Short scanner identifier (e.g. ``"manifest"``, ``"crypto"``).
        findings: List of finding dicts.  Each must contain at least
                  ``"severity"`` and ``"title"`` keys.
    """
    with _conn() as con:
        # Replace stale results for this scanner
        con.execute(
            "DELETE FROM findings WHERE sha256 = ? AND scanner = ?",
            (sha256, scanner),
        )
        rows = [
            (
                sha256,
                scanner,
                f.get("severity", "info"),
                f.get("title", ""),
                json.dumps(f),
            )
            for f in findings
        ]
        con.executemany(
            """
            INSERT INTO findings (sha256, scanner, severity, title, finding_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            rows,
        )


def load_findings(sha256: str, scanner: str = "") -> list[dict] | None:
    """Retrieve cached findings for an APK, optionally filtered by scanner.

    Args:
        sha256:   Hex-encoded SHA-256 of the APK.
        scanner:  If provided, only return findings from this scanner.
                  Pass an empty string (default) to return all scanners.

    Returns:
        A list of finding dicts (deserialised from JSON), or ``None`` if
        no findings have been cached for this APK (and scanner).
    """
    with _conn() as con:
        if scanner:
            rows = con.execute(
                """
                SELECT finding_json FROM findings
                WHERE sha256 = ? AND scanner = ?
                ORDER BY id
                """,
                (sha256, scanner),
            ).fetchall()
        else:
            rows = con.execute(
                """
                SELECT finding_json FROM findings
                WHERE sha256 = ?
                ORDER BY id
                """,
                (sha256,),
            ).fetchall()

    if not rows:
        return None
    return [json.loads(r["finding_json"]) for r in rows]
