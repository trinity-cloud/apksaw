"""Live secret verification probes.

Five MCP tools that turn ``extract_secrets`` candidates into confirmed (or
dismissed) findings via controlled, passive-by-default HTTP requests.

**Authorization contract (read before calling):** only run against
apps/projects you own or are explicitly authorised to test. Passive mode
(default) classifies validity and scope **without retrieving data**.
Active mode requires both ``active=True`` **and** ``confirm=True``; it
returns a *bounded* proof (at most ``sample_cap`` records) and is
enforced independently inside every per-type probe — not only in the
dispatcher.
"""

from __future__ import annotations

import json
import re
from typing import Any

from apksaw.server import mcp
from apksaw.utils.http_probe import http_get, ProbeError

# ---------------------------------------------------------------------------
# Key-type inference helpers
# ---------------------------------------------------------------------------

_GOOGLE_API_KEY_RE = re.compile(r"^AIza[0-9A-Za-z\-_]{35}$")
_FIREBASE_RTDB_RE = re.compile(
    r"https?://[a-z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)"
)
_FIREBASE_STORAGE_RE = re.compile(r"gs://[a-z0-9-]+\.appspot\.com")
_AWS_AKID_RE = re.compile(r"^AKIA[0-9A-Z]{16}$")


def _infer_key_type(value: str) -> str:
    """Best-effort key-type inference from value shape.

    Returns one of ``'google_api_key'``, ``'firebase_rtdb'``,
    ``'firebase_storage'``, ``'aws_key'``, or ``''``.
    """
    if _GOOGLE_API_KEY_RE.match(value):
        return "google_api_key"
    if _FIREBASE_RTDB_RE.search(value):
        return "firebase_rtdb"
    if _FIREBASE_STORAGE_RE.search(value):
        return "firebase_storage"
    if _AWS_AKID_RE.match(value):
        return "aws_key"
    return ""


# ---------------------------------------------------------------------------
# Shared gate helpers
# ---------------------------------------------------------------------------


def _active_gate(active: bool, confirm: bool) -> dict | None:
    """Return an error dict if active mode is requested without confirm.

    Returns ``None`` when the gate is satisfied (caller may proceed).
    """
    if active and not confirm:
        return {
            "status": "error",
            "message": (
                "active=True requires confirm=True. "
                "Passive probe results (active=False) are always available."
            ),
            "data": None,
        }
    return None


# Exposure values that the probe could NOT conclusively establish (the request
# returned something unexpected/ambiguous). These are reported at low confidence
# so the agent treats them as leads to verify, not live-confirmed findings.
_INCONCLUSIVE_EXPOSURES = frozenset({"unknown"})


def _build_response(
    key_type: str,
    valid: bool,
    exposure: str,
    mode: str,
    severity: str,
    evidence: dict,
    notes: str = "",
    sample: list | None = None,
    confidence: str | None = None,
) -> dict:
    """Uniform response builder for all probe tools.

    ``confidence`` defaults to ``"high"`` for conclusive, live-verified
    exposures and ``"low"`` for inconclusive ones; callers may override for
    branches (e.g. an inconclusive AWS STS error) that are not captured by the
    exposure string alone.
    """
    if confidence is None:
        confidence = "low" if exposure in _INCONCLUSIVE_EXPOSURES else "high"
    resp: dict[str, Any] = {
        "key_type": key_type,
        "valid": valid,
        "exposure": exposure,
        "mode": mode,
        "severity": severity,
        "confidence": confidence,
        "verification_needed": confidence != "high",
        "evidence": evidence,
        "notes": notes,
    }
    if sample is not None:
        resp["evidence"]["sample"] = sample
    return {"status": "ok", "data": resp}


# ---------------------------------------------------------------------------
# Tool: probe_google_api_key
# ---------------------------------------------------------------------------


@mcp.tool()
def probe_google_api_key(value: str) -> dict:
    """Verify a Google API key against a cheap classification endpoint.

    Sends one request to the Geocoding API (non-billing, minimal cost)
    and classifies the key by reading the error/permission envelope.
    **Always passive** — no data is retrieved beyond the classification
    signal.

    Args:
        value: The API key string (typically starts with ``AIza``).

    Returns:
        ``{status, data: {key_type, valid, exposure, mode, confidence, evidence}}``.
    """
    url = (
        "https://maps.googleapis.com/maps/api/geocode/json"
        f"?key={value}&address=0,0"
    )
    try:
        code, body, headers = http_get(url, timeout=10)
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {}

        status = data.get("status", "")
        error_msg = data.get("error_message", "")

        if status == "OK" or status == "ZERO_RESULTS":
            return _build_response(
                key_type="google_api_key",
                valid=True,
                exposure="unrestricted",
                mode="passive",
                severity="high",
                evidence={
                    "http_status": code,
                    "api_status": status,
                    "signal": "key accepted; no referer/package/IP restriction",
                },
                notes="Key is valid and unrestricted. Scope it via Google Cloud Console.",
            )
        if status in ("REQUEST_DENIED",) and "ip" in error_msg.lower():
            return _build_response(
                key_type="google_api_key",
                valid=True,
                exposure="restricted",
                mode="passive",
                severity="medium",
                evidence={
                    "http_status": code,
                    "api_status": status,
                    "error_message": error_msg,
                    "signal": "key is IP-restricted (or referer/package-restricted)",
                },
                notes="Key is valid but restricted by IP/referer/package. Check Google Cloud Console for the exact restriction.",
            )
        if status in ("REQUEST_DENIED", "INVALID_REQUEST"):
            return _build_response(
                key_type="google_api_key",
                valid=False,
                exposure="invalid",
                mode="passive",
                severity="info",
                evidence={
                    "http_status": code,
                    "api_status": status,
                    "error_message": error_msg,
                    "signal": "key rejected by Google",
                },
                notes="Key is invalid or has been revoked.",
            )

        return _build_response(
            key_type="google_api_key",
            valid=True,
            exposure="unknown",
            mode="passive",
            severity="medium",
            evidence={
                "http_status": code,
                "api_status": status,
                "error_message": error_msg,
                "signal": "unexpected API response",
            },
            notes="Could not classify key. Inspect the error_message.",
        )

    except ProbeError as exc:
        return {
            "status": "error",
            "message": f"Network probe failed: {exc}",
            "data": None,
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"probe_google_api_key failed: {exc}",
            "data": None,
        }


# ---------------------------------------------------------------------------
# Tool: probe_firebase_rtdb
# ---------------------------------------------------------------------------


@mcp.tool()
def probe_firebase_rtdb(value: str) -> dict:
    """Classify a Firebase Realtime Database as world-readable or protected.

    Sends ``GET /.json?shallow=true&limitToFirst=1`` — returns **key
    names only**, never record values.  **Always passive** — no user data
    is retrieved.

    Args:
        value: Database name or full ``https://<db>.firebaseio.com`` URL.

    Returns:
        ``{status, data: {key_type, valid, exposure, mode, confidence, evidence}}``.
    """
    db_url = value.strip()
    if not db_url.startswith("https://"):
        db_url = f"https://{db_url}.firebaseio.com"
    db_url = db_url.rstrip("/")
    url = f"{db_url}/.json?shallow=true&limitToFirst=1"

    try:
        code, body, headers = http_get(url, timeout=10)
    except ProbeError as exc:
        return {
            "status": "error",
            "message": f"Network probe failed: {exc}",
            "data": None,
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"probe_firebase_rtdb failed: {exc}",
            "data": None,
        }

    if code == 200:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = None
        # Any non-empty 200 body — dict of keys, a list root, or a scalar —
        # means the root is world-readable (shallow returns keys only, no values).
        if data not in (None, {}, []):
            count = len(data) if isinstance(data, (dict, list)) else 1
            return _build_response(
                key_type="firebase_rtdb",
                valid=True,
                exposure="world_readable",
                mode="passive",
                severity="high",
                evidence={
                    "http_status": code,
                    "signal": "database returned data via shallow query",
                    "key_count": count,
                },
                notes="Database is world-readable. Restrict via Firebase Rules.",
            )
        # Empty body but 200 = auth required or empty db
        return _build_response(
            key_type="firebase_rtdb",
            valid=True,
            exposure="auth_required",
            mode="passive",
            severity="info",
            evidence={
                "http_status": code,
                "signal": "database exists but returned no keys (auth required or empty)",
            },
            notes="Database exists but is not publicly readable.",
        )

    if code in (401, 403):
        return _build_response(
            key_type="firebase_rtdb",
            valid=True,
            exposure="auth_required",
            mode="passive",
            severity="info",
            evidence={
                "http_status": code,
                "signal": "authentication required to access database",
            },
            notes="Database exists and requires authentication.",
        )

    if code == 404:
        return _build_response(
            key_type="firebase_rtdb",
            valid=False,
            exposure="not_found",
            mode="passive",
            severity="info",
            evidence={
                "http_status": code,
                "signal": "database not found",
            },
            notes="Database does not exist or has been deleted.",
        )

    return _build_response(
        key_type="firebase_rtdb",
        valid=True,
        exposure="unknown",
        mode="passive",
        severity="medium",
        evidence={
            "http_status": code,
            "signal": f"unexpected HTTP status {code}",
        },
        notes=f"Unexpected response ({code}). Inspect manually.",
    )


# ---------------------------------------------------------------------------
# Tool: probe_firebase_storage
# ---------------------------------------------------------------------------


@mcp.tool()
def probe_firebase_storage(
    value: str,
    active: bool = False,
    confirm: bool = False,
    sample_cap: int = 5,
) -> dict:
    """Classify a Firebase Storage bucket as publicly listable or restricted.

    **Passive (default):** checks bucket metadata / listing permission
    without downloading objects. **Active (``active=True`` AND
    ``confirm=True``):** lists up to *sample_cap* object names (never
    downloads content).

    The ``active ⇒ confirm`` gate is enforced inside this tool;
    ``active=True, confirm=False`` returns an error without making any
    active request.

    Args:
        value: Bucket URL (``gs://<bucket>`` or
            ``https://firebasestorage.googleapis.com/v0/b/<bucket>``).
        active: When ``True``, attempt to list objects.
        confirm: **Required** for active mode.  Must be explicitly
            ``True``.
        sample_cap: Maximum object names to return in active mode
            (default 5).

    Returns:
        ``{status, data: {key_type, valid, exposure, mode, confidence, evidence}}``.
    """
    gate = _active_gate(active, confirm)
    if gate:
        return gate

    # Normalise bucket name
    bucket = value.strip()
    if bucket.startswith("gs://"):
        bucket = bucket[5:].rstrip("/")
    elif "firebasestorage.googleapis.com" in bucket:
        # Extract bucket from full URL
        m = re.search(r"/b/([^/]+)", bucket)
        bucket = m.group(1) if m else bucket

    # Passive: check listing permission via bucket metadata
    url = (
        f"https://firebasestorage.googleapis.com/v0/b/{bucket}"
        f"?maxResults=1&alt=json"
    )
    try:
        code, body, headers = http_get(url, timeout=10)
    except ProbeError as exc:
        return {
            "status": "error",
            "message": f"Network probe failed: {exc}",
            "data": None,
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"probe_firebase_storage failed: {exc}",
            "data": None,
        }

    if code in (200, 204):
        # Bucket exists and is accessible — determine if public
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}

        items = data.get("items", []) if isinstance(data, dict) else []
        sample: list[str] = []

        if active and confirm:
            # Active mode: list up to sample_cap objects
            if items:
                sample = [
                    item.get("name", "?")
                    for item in items[:sample_cap]
                ]
            else:
                # Try listing with a larger page
                list_url = (
                    f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o"
                    f"?maxResults={sample_cap}&alt=json"
                )
                try:
                    _code, _body, _headers = http_get(list_url, timeout=10)
                    list_data = json.loads(_body) if _body else {}
                    sample = [
                        item.get("name", "?")
                        for item in list_data.get("items", [])[:sample_cap]
                    ]
                except (ProbeError, json.JSONDecodeError) as exc:
                    # Surface the failure rather than silently reporting
                    # "restricted" (which would misclassify a network error).
                    return {
                        "status": "error",
                        "message": f"Active object-listing request failed: {exc}",
                        "data": None,
                    }

            return _build_response(
                key_type="firebase_storage",
                valid=True,
                exposure="public_list" if sample else "restricted",
                mode="active",
                severity="high" if sample else "medium",
                evidence={
                    "http_status": code,
                    "signal": "bucket listable" if sample else "bucket exists but listing restricted",
                },
                notes=(
                    f"Active probe listed {len(sample)} object(s) "
                    f"(capped at {sample_cap})."
                ),
                sample=sample if sample else None,
            )

        # Passive mode only
        exposure = "public_list" if items else "restricted"
        return _build_response(
            key_type="firebase_storage",
            valid=True,
            exposure=exposure,
            mode="passive",
            severity="high" if items else "medium",
            evidence={
                "http_status": code,
                "signal": (
                    "bucket is publicly listable"
                    if items
                    else "bucket exists but listing may be restricted"
                ),
            },
            notes="Passive check only. Use active=True + confirm=True to list objects.",
        )

    if code in (401, 403):
        return _build_response(
            key_type="firebase_storage",
            valid=True,
            exposure="restricted",
            mode="passive",
            severity="info",
            evidence={
                "http_status": code,
                "signal": "authentication required",
            },
            notes="Bucket exists and requires authentication.",
        )

    if code == 404:
        return _build_response(
            key_type="firebase_storage",
            valid=False,
            exposure="not_found",
            mode="passive",
            severity="info",
            evidence={
                "http_status": code,
                "signal": "bucket not found",
            },
            notes="Bucket does not exist or has been deleted.",
        )

    return _build_response(
        key_type="firebase_storage",
        valid=True,
        exposure="unknown",
        mode="passive",
        severity="medium",
        evidence={
            "http_status": code,
            "signal": f"unexpected HTTP status {code}",
        },
        notes=f"Unexpected response ({code}). Inspect manually.",
    )


# ---------------------------------------------------------------------------
# Tool: probe_aws_key
# ---------------------------------------------------------------------------


@mcp.tool()
def probe_aws_key(
    access_key_id: str,
    secret_access_key: str = "",
    active: bool = False,
    confirm: bool = False,
    sample_cap: int = 5,
) -> dict:
    """Verify an AWS access key via ``sts:GetCallerIdentity``.

    **Passive (default):** calls ``sts:GetCallerIdentity`` — identifies
    the principal, touches no resource.  **Active (``active=True`` AND
    ``confirm=True``):** enumerates attached managed policy names (never
    retrieves policy documents).

    The ``active ⇒ confirm`` gate is enforced inside this tool.

    Requires the optional **botocore** package.  Without it, returns a
    clear install message — no traceback.

    Args:
        access_key_id: AWS access key ID (starts with ``AKIA``).
        secret_access_key: Corresponding secret access key.
        active: When ``True``, enumerate attached policies.
        confirm: **Required** for active mode.
        sample_cap: Maximum policy names to return (default 5).

    Returns:
        ``{status, data: {key_type, valid, exposure, mode, confidence, evidence}}``.
    """
    gate = _active_gate(active, confirm)
    if gate:
        return gate

    if not secret_access_key:
        return {
            "status": "error",
            "message": (
                "secret_access_key is required for AWS key verification. "
                "Provide the full key pair (access_key_id + secret_access_key)."
            ),
            "data": None,
        }

    try:
        import botocore.exceptions  # noqa: PLC0415
        import botocore.session  # noqa: PLC0415
    except ImportError:
        return {
            "status": "error",
            "message": (
                "botocore is not installed — required for AWS key verification. "
                "Install it with: uv sync --extra probe  or  pip install botocore"
            ),
            "data": None,
        }

    try:
        session = botocore.session.Session()
        # Create an STS client
        sts = session.create_client(
            "sts",
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name="us-east-1",
        )

        try:
            identity = sts.get_caller_identity()
            arn = identity.get("Arn", "unknown")
            account = identity.get("Account", "unknown")
        except botocore.exceptions.ClientError as exc:
            # Read the authoritative error code, not a stringified-exception
            # substring (which misclassified SignatureDoesNotMatch as valid).
            err_code = exc.response.get("Error", {}).get("Code", "")
            if err_code in (
                "InvalidClientTokenId", "SignatureDoesNotMatch",
                "AuthFailure", "InvalidAccessKeyId", "AccessDenied",
            ):
                # GetCallerIdentity needs no IAM permission, so any of these
                # means the key itself is bad/revoked.
                return _build_response(
                    key_type="aws_key",
                    valid=False,
                    exposure="invalid",
                    mode="passive",
                    severity="info",
                    evidence={
                        "signal": "key rejected by AWS STS",
                        "error_code": err_code,
                    },
                    notes="Key is invalid or has been revoked.",
                )
            # Any other ClientError is inconclusive — do not claim the key valid.
            return _build_response(
                key_type="aws_key",
                valid=False,
                exposure="unknown",
                mode="passive",
                severity="medium",
                evidence={
                    "signal": "GetCallerIdentity returned an unexpected error",
                    "error_code": err_code,
                },
                notes=f"Inconclusive STS error ({err_code}). Inspect manually.",
                confidence="low",
            )
        except Exception as exc:
            return {
                "status": "error",
                "message": f"AWS STS call failed (network/client error): {exc}",
                "data": None,
            }

        # Passive: valid key, identified principal
        evidence: dict = {
            "signal": f"principal: {arn}, account: {account}",
            "principal_arn": arn,
            "account_id": account,
        }

        if active and confirm:
            # Active: enumerate attached policies
            try:
                iam = session.create_client(
                    "iam",
                    aws_access_key_id=access_key_id,
                    aws_secret_access_key=secret_access_key,
                    region_name="us-east-1",
                )
                # Extract user name from ARN
                user_match = re.search(r"user/([^/]+)", arn)
                user_name = user_match.group(1) if user_match else None
                policies: list[str] = []
                if user_name:
                    try:
                        resp = iam.list_attached_user_policies(
                            UserName=user_name, MaxItems=sample_cap
                        )
                        policies = [
                            p.get("PolicyName", "?")
                            for p in resp.get("AttachedPolicies", [])
                        ][:sample_cap]
                    except Exception:
                        pass
                sample = policies if policies else None
                return _build_response(
                    key_type="aws_key",
                    valid=True,
                    exposure="active_enumerated",
                    mode="active",
                    severity="high" if policies else "medium",
                    evidence={
                        **evidence,
                        "signal": f"principal: {arn}, policies: {len(policies)} listed",
                        "policy_count": len(policies),
                    },
                    notes=(
                        f"Active probe listed {len(policies)} attached policy name(s) "
                        f"(capped at {sample_cap})."
                    ),
                    sample=sample,
                )
            except Exception as exc:
                return _build_response(
                    key_type="aws_key",
                    valid=True,
                    exposure="restricted",
                    mode="active",
                    severity="medium",
                    evidence={
                        **evidence,
                        "signal": f"principal: {arn}; policy list failed: {exc}",
                    },
                    notes=(
                        "Key is valid but attached policy enumeration failed — "
                        "the key may not have IAM read permissions."
                    ),
                )

        return _build_response(
            key_type="aws_key",
            valid=True,
            exposure="valid_principal",
            mode="passive",
            severity="medium",
            evidence=evidence,
            notes=(
                f"Key is valid. Principal: {arn}. "
                "Use active=True + confirm=True to enumerate attached policies."
            ),
        )

    except Exception as exc:
        return {
            "status": "error",
            "message": f"probe_aws_key failed: {exc}",
            "data": None,
        }


# ---------------------------------------------------------------------------
# Tool: probe_secret (dispatcher)
# ---------------------------------------------------------------------------


@mcp.tool()
def probe_secret(
    value: str,
    key_type: str = "",
    active: bool = False,
    confirm: bool = False,
    sample_cap: int = 5,
) -> dict:
    """Verify a discovered secret against its live service.

    Dispatcher that routes to the appropriate per-type probe.  Accepts
    either a raw value + *key_type*, or a finding dict straight from
    ``extract_secrets`` (which carries ``pattern_name`` → *key_type*
    mapping).

    **AUTHORIZATION:** only run against apps/services you own or are
    explicitly authorised to test. Passive mode (default) classifies
    validity and scope without retrieving data. Active mode
    (``active=True`` AND ``confirm=True``) returns a BOUNDED proof (at
    most *sample_cap* records) and must be opted into per call.

    Args:
        value: The secret string (API key, URL, etc.).
        key_type: One of ``google_api_key``, ``firebase_rtdb``,
            ``firebase_storage``, ``aws_key``.  Empty string = infer
            from value shape.
        active: When ``True``, perform active escalation (where
            supported).  Also requires ``confirm=True``.
        confirm: **Required** for any active escalation.
        sample_cap: Maximum records/objects an active probe may return
            (default 5).

    Returns:
        ``{status, data: {key_type, valid, exposure, mode, confidence,
        evidence}}``.
    """
    # Resolve key_type
    kt = key_type.strip() if key_type else _infer_key_type(value)
    if not kt:
        return {
            "status": "error",
            "message": (
                "Could not infer key_type from value shape. "
                "Pass key_type explicitly: google_api_key, firebase_rtdb, "
                "firebase_storage, or aws_key."
            ),
            "data": None,
        }

    if kt == "google_api_key":
        # Google API key probe is passive-only; active/confirm are ignored
        return probe_google_api_key(value)
    if kt == "firebase_rtdb":
        # Firebase RTDB is passive-only
        return probe_firebase_rtdb(value)
    if kt == "firebase_storage":
        return probe_firebase_storage(
            value, active=active, confirm=confirm, sample_cap=sample_cap
        )
    if kt == "aws_key":
        return probe_aws_key(
            value, active=active, confirm=confirm, sample_cap=sample_cap
        )

    return {
        "status": "error",
        "message": f"Unknown key_type: '{kt}'",
        "data": None,
    }
