"""Tests for session management: create_session, get_session, list_sessions."""

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Import the session module at test-module level so patches can reference it.
# The module calls restore_sessions() on import, so we patch the DB helpers first.
with patch("apksaw.db.init_db"), patch("apksaw.db.list_all_sessions", return_value=[]):
    import apksaw.session as _session_module
    from apksaw.session import create_session, get_session, list_sessions


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _db_patches():
    """Patches that prevent any real SQLite I/O inside session functions."""
    return [
        patch.object(_session_module.db, "init_db"),
        patch.object(_session_module.db, "save_session"),
        patch.object(_session_module.db, "touch_session"),
        patch.object(_session_module.db, "load_session", return_value=None),
        patch.object(_session_module.db, "list_all_sessions", return_value=[]),
        patch.object(_session_module, "ensure_dirs"),
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_create_session_returns_session_with_sha256(sample_apk_path):
    """create_session on a real file returns a Session with the correct SHA256."""
    for p in _db_patches():
        p.start()
    try:
        with patch.object(_session_module, "_sessions", {}):
            session = create_session(str(sample_apk_path))

        expected_sha256 = hashlib.sha256(sample_apk_path.read_bytes()).hexdigest()
        assert session.sha256 == expected_sha256
        assert session.apk_path == sample_apk_path
        assert len(session.session_id) == 12  # uuid4().hex[:12]
    finally:
        for p in _db_patches():
            try:
                p.stop()
            except RuntimeError:
                pass


def test_create_session_deduplicates_by_sha256(sample_apk_path):
    """Calling create_session twice with the same APK returns the same session."""
    fake_sessions = {}
    for p in _db_patches():
        p.start()
    try:
        with patch.object(_session_module, "_sessions", fake_sessions):
            session1 = create_session(str(sample_apk_path))
            session2 = create_session(str(sample_apk_path))

        assert session1.session_id == session2.session_id
    finally:
        for p in _db_patches():
            try:
                p.stop()
            except RuntimeError:
                pass


def test_create_session_raises_for_missing_file(tmp_path):
    """create_session raises FileNotFoundError when the path does not exist."""
    for p in _db_patches():
        p.start()
    try:
        with pytest.raises(FileNotFoundError, match="APK not found"):
            create_session(str(tmp_path / "nonexistent.apk"))
    finally:
        for p in _db_patches():
            try:
                p.stop()
            except RuntimeError:
                pass


def test_get_session_returns_known_session(sample_apk_path):
    """get_session retrieves a session that was previously created."""
    fake_sessions = {}
    for p in _db_patches():
        p.start()
    try:
        with patch.object(_session_module, "_sessions", fake_sessions):
            created = create_session(str(sample_apk_path))
            retrieved = get_session(created.session_id)

        assert retrieved.session_id == created.session_id
    finally:
        for p in _db_patches():
            try:
                p.stop()
            except RuntimeError:
                pass


def test_get_session_raises_for_unknown_id():
    """get_session raises KeyError for an ID that was never created."""
    with patch.object(_session_module, "_sessions", {}):
        with pytest.raises(KeyError, match="not found"):
            get_session("doesnotexist")


def test_list_sessions_reflects_created_sessions(sample_apk_path):
    """list_sessions returns one entry per unique session in _sessions."""
    fake_sessions = {}
    for p in _db_patches():
        p.start()
    try:
        with patch.object(_session_module, "_sessions", fake_sessions):
            create_session(str(sample_apk_path))
            sessions = list_sessions()

        assert len(sessions) == 1
        entry = sessions[0]
        assert "session_id" in entry
        assert "sha256" in entry
        assert "apk_path" in entry
    finally:
        for p in _db_patches():
            try:
                p.stop()
            except RuntimeError:
                pass
