"""Tests for secrets_probe: the active⇒confirm gate, confidence labelling,
and the guarantee that passive mode never returns record samples.
"""

from unittest.mock import patch

from apksaw.tools.secrets_probe import (
    _build_response,
    probe_aws_key,
    probe_firebase_rtdb,
    probe_firebase_storage,
)

_SP = "apksaw.tools.secrets_probe"


# --- active ⇒ confirm gate enforced inside EACH active-capable probe --------

def test_storage_active_requires_confirm_no_network():
    with patch(f"{_SP}.http_get") as mock_get:
        result = probe_firebase_storage("gs://b.appspot.com", active=True, confirm=False)
    assert result["status"] == "error"
    mock_get.assert_not_called()


def test_aws_active_requires_confirm():
    # Gate is checked before secret/botocore — no deps needed for this path.
    result = probe_aws_key("AKIAEXAMPLE", "secret", active=True, confirm=False)
    assert result["status"] == "error"


# --- confidence labelling ---------------------------------------------------

def test_build_response_confidence_derivation():
    assert _build_response("x", True, "unknown", "passive", "medium", {})["data"]["confidence"] == "low"
    assert _build_response("x", True, "world_readable", "passive", "high", {})["data"]["confidence"] == "high"


def test_unknown_exposure_is_low_confidence():
    with patch(f"{_SP}.http_get", return_value=(418, "", {})):
        d = probe_firebase_rtdb("mydb")["data"]
    assert d["exposure"] == "unknown"
    assert d["confidence"] == "low"
    assert d["verification_needed"] is True


# --- passive RTDB: world-readable detection without leaking values ----------

def test_rtdb_world_readable_high_conf_no_sample():
    with patch(f"{_SP}.http_get", return_value=(200, '{"users": true, "cfg": true}', {})):
        d = probe_firebase_rtdb("mydb")["data"]
    assert d["exposure"] == "world_readable"
    assert d["confidence"] == "high"
    assert "sample" not in d["evidence"]  # passive never returns records


def test_rtdb_non_dict_root_detected():
    # array root must still be recognised as world-readable (was a false negative)
    with patch(f"{_SP}.http_get", return_value=(200, '["a","b","c"]', {})):
        d = probe_firebase_rtdb("mydb")["data"]
    assert d["exposure"] == "world_readable"
    assert d["evidence"]["key_count"] == 3


def test_rtdb_auth_required():
    with patch(f"{_SP}.http_get", return_value=(401, "", {})):
        d = probe_firebase_rtdb("mydb")["data"]
    assert d["exposure"] == "auth_required"
