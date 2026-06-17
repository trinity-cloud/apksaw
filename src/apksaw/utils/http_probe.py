"""Thin stdlib urllib wrapper for safe HTTP probing.

Shared by ``secrets_probe`` and ``verify_app_links`` — centralises timeout,
body-capping, and SSRF defences so every consumer gets the same guarantees.

Rules:
- Timeout enforced on every request (default 10 s).
- Only ``http``/``https`` schemes; never ``file://`` or other schemes.
- Refuses requests AND redirects to loopback/link-local/private/reserved IP
  literals and known-local hostnames (blocks cloud-metadata SSRF, e.g.
  ``169.254.169.254``). Note: hostnames are not DNS-resolved, so a name that
  resolves to a private IP is not caught — literal-IP and known-name vectors are.
- Response body is capped (default 64 KiB) on both success and error paths.
- Returns a uniform ``(status_code, body_text, headers)`` triple.
"""

from __future__ import annotations

import ipaddress
import urllib.error
import urllib.request
from urllib.parse import urlparse

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_BODY_CAP = 64 * 1024  # 64 KiB

_BLOCKED_HOSTNAMES = frozenset({"localhost", "metadata.google.internal"})


class ProbeError(Exception):
    """Raised when a probe cannot complete (timeout, DNS, connection, or SSRF block)."""


def _host_is_blocked(host: str) -> bool:
    """Return True if *host* is a local/internal target that must not be probed.

    Blocks known-local hostnames and any loopback / link-local / private /
    reserved / multicast / unspecified IP literal. Non-IP hostnames are allowed
    (not resolved here), so this catches the literal-IP metadata/loopback
    vectors, not DNS-rebinding.
    """
    h = (host or "").strip().lower().strip(".")
    if not h:
        return True
    if h in _BLOCKED_HOSTNAMES:
        return True
    h_ip = h[1:-1] if h.startswith("[") and h.endswith("]") else h
    try:
        ip = ipaddress.ip_address(h_ip)
    except ValueError:
        return False  # hostname, not an IP literal — allowed
    return (
        ip.is_loopback or ip.is_private or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _safe_redirect_handler() -> urllib.request.HTTPRedirectHandler:
    """Return a redirect handler that refuses non-http(s) and local targets."""

    class _SafeRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            parsed = urlparse(newurl)
            if parsed.scheme not in ("http", "https"):
                raise urllib.error.URLError(
                    f"redirect to non-http(s) scheme refused: {parsed.scheme}"
                )
            if _host_is_blocked(parsed.hostname or ""):
                raise urllib.error.URLError(
                    f"redirect to local/internal host refused: {parsed.hostname}"
                )
            return urllib.request.HTTPRedirectHandler.redirect_request(
                self, req, fp, code, msg, headers, newurl
            )

    return _SafeRedirect()


def http_get(
    url: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    body_cap: int = _DEFAULT_BODY_CAP,
    headers: dict[str, str] | None = None,
) -> tuple[int, str, dict[str, str]]:
    """Perform a GET request and return ``(status, body, response_headers)``.

    Raises:
        ProbeError: On timeout, DNS failure, connection error, or a blocked
            (local/internal) target.
        ValueError: If *url* scheme is not http/https.
    """
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"Only http/https URLs allowed, got: {url}")

    parsed = urlparse(url)
    if _host_is_blocked(parsed.hostname or ""):
        raise ProbeError(f"refusing to probe local/internal host: {parsed.hostname}")

    req = urllib.request.Request(url)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    opener = urllib.request.build_opener(_safe_redirect_handler())

    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # HTTPError is a valid response — read its (capped) body too.
        code = exc.code
        resp_headers = dict(exc.headers) if exc.headers else {}
        raw = exc.read(body_cap) if exc.fp else b""
        body = raw.decode("utf-8", errors="replace")
        return code, body, resp_headers
    except urllib.error.URLError as exc:
        raise ProbeError(str(exc.reason)) from exc
    except OSError as exc:
        raise ProbeError(str(exc)) from exc

    code = resp.getcode()
    resp_headers = dict(resp.headers) if resp.headers else {}
    raw = resp.read(body_cap)
    body = raw.decode("utf-8", errors="replace")
    resp.close()
    return code, body, resp_headers
