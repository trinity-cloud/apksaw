"""Tests for http_probe SSRF defences and scheme handling."""

import urllib.error

import pytest

from apksaw.utils.http_probe import (
    ProbeError,
    _host_is_blocked,
    _safe_redirect_handler,
    http_get,
)


def test_host_is_blocked_local_and_metadata():
    for h in [
        "localhost", "metadata.google.internal",
        "127.0.0.1", "169.254.169.254", "10.0.0.5",
        "192.168.1.1", "172.16.0.1", "::1", "0.0.0.0", "",
    ]:
        assert _host_is_blocked(h), h


def test_host_is_blocked_allows_public():
    for h in ["example.com", "8.8.8.8", "abc.firebaseio.com"]:
        assert not _host_is_blocked(h), h


def test_http_get_refuses_local_target_before_network():
    with pytest.raises(ProbeError):
        http_get("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(ProbeError):
        http_get("http://localhost:8080/x")


def test_http_get_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        http_get("file:///etc/passwd")


def test_redirect_handler_blocks_metadata_and_schemes():
    h = _safe_redirect_handler()
    with pytest.raises(urllib.error.URLError):
        h.redirect_request(None, None, 302, "Found", {}, "http://169.254.169.254/")
    with pytest.raises(urllib.error.URLError):
        h.redirect_request(None, None, 302, "Found", {}, "file:///etc/passwd")
    with pytest.raises(urllib.error.URLError):
        h.redirect_request(None, None, 302, "Found", {}, "http://localhost/admin")
