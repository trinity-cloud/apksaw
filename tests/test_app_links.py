"""Tests for verify_app_links — locks the SHA-256 fingerprint format fix.

asn1crypto renders sha256_fingerprint space-separated uppercase; assetlinks.json
uses colon-separated. The bug compared the two without normalising, so every
well-configured host falsely reported fingerprint_mismatch.
"""

import json
from unittest.mock import MagicMock, patch

from lxml import etree

from apksaw.tools.app_links import verify_app_links

_AL = "apksaw.tools.app_links"
_ANDROID_NS = "http://schemas.android.com/apk/res/android"

# A 32-byte SHA-256, rendered the two ways the two sources actually use.
_FP_BYTES = [0xAB, 0xCD] + list(range(30))
_FP_SPACE = " ".join(f"{b:02X}" for b in _FP_BYTES)   # asn1crypto cert side
_FP_COLON = ":".join(f"{b:02X}" for b in _FP_BYTES)   # assetlinks.json side


def _session_with_cert():
    cert = MagicMock()
    cert.sha256_fingerprint = _FP_SPACE
    session = MagicMock()
    session.apk.get_certificates.return_value = [cert]
    return session


def _assetlinks(fp_colon: str) -> str:
    return json.dumps([{
        "relation": ["delegate_permission/common.handle_all_urls"],
        "target": {
            "namespace": "android_app",
            "package_name": "com.example",
            "sha256_cert_fingerprints": [fp_colon],
        },
    }])


def _run(http_return):
    session = _session_with_cert()
    hosts = [{"host": "example.com", "activity": "A", "scheme": "https"}]
    with patch(f"{_AL}.get_session", return_value=session), \
         patch(f"{_AL}._extract_auto_verify_hosts", return_value=hosts), \
         patch(f"{_AL}.http_get", return_value=http_return):
        return verify_app_links("s")


def test_fingerprint_matches_across_space_and_colon_formats():
    result = _run((200, _assetlinks(_FP_COLON), {}))
    assert result["status"] == "ok"
    assert [r["status"] for r in result["data"]["results"]] == ["ok"]


def test_fingerprint_mismatch_is_reported():
    wrong = ":".join(f"{b:02X}" for b in range(32))
    result = _run((200, _assetlinks(wrong), {}))
    assert [r["status"] for r in result["data"]["results"]] == ["fingerprint_mismatch"]


def test_missing_assetlinks_file():
    result = _run((404, "", {}))
    assert result["data"]["results"][0]["status"] == "missing"


def test_malformed_assetlinks_json():
    result = _run((200, "not json", {}))
    assert result["data"]["results"][0]["status"] == "malformed"


def test_auto_verify_is_read_from_intent_filter():
    session = _session_with_cert()
    session.apk.get_package.return_value = "com.example"

    manifest = etree.Element("manifest")
    application = etree.SubElement(manifest, "application")
    activity = etree.SubElement(application, "activity")
    activity.set(f"{{{_ANDROID_NS}}}name", ".MainActivity")

    intent_filter = etree.SubElement(activity, "intent-filter")
    intent_filter.set(f"{{{_ANDROID_NS}}}autoVerify", "true")
    action = etree.SubElement(intent_filter, "action")
    action.set(f"{{{_ANDROID_NS}}}name", "android.intent.action.VIEW")
    category = etree.SubElement(intent_filter, "category")
    category.set(f"{{{_ANDROID_NS}}}name", "android.intent.category.BROWSABLE")
    data = etree.SubElement(intent_filter, "data")
    data.set(f"{{{_ANDROID_NS}}}scheme", "https")
    data.set(f"{{{_ANDROID_NS}}}host", "example.com")

    session.apk.get_android_manifest_xml.return_value = manifest

    with patch(f"{_AL}.get_session", return_value=session), \
         patch(f"{_AL}.http_get", return_value=(200, _assetlinks(_FP_COLON), {})):
        result = verify_app_links("s")

    assert result["status"] == "ok"
    assert result["data"]["results"][0]["host"] == "example.com"
    assert result["data"]["results"][0]["status"] == "ok"
