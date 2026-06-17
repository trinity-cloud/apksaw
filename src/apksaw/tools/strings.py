"""String extraction and search tools for Android APK analysis."""

import math
import re
from typing import Iterator

from apksaw.server import mcp
from apksaw.session import get_session

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Common Android/Java boilerplate prefixes and exact strings to filter out
_BOILERPLATE_PREFIXES = (
    "android.",
    "java.",
    "javax.",
    "com.android.",
    "com.google.android.",
    "dalvik.",
    "org.apache.",
    "org.xml.",
    "org.json.",
    "sun.",
    "libcore.",
)

_BOILERPLATE_EXACT = frozenset(
    {
        "true",
        "false",
        "null",
        "void",
        "int",
        "long",
        "float",
        "double",
        "boolean",
        "byte",
        "char",
        "short",
        "UTF-8",
        "UTF8",
        "ISO-8859-1",
        "US-ASCII",
        "application/json",
        "application/xml",
        "text/plain",
        "text/html",
        "Content-Type",
        "Content-Length",
        "Accept",
        "Authorization",
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    }
)

# ---------------------------------------------------------------------------
# Regex patterns (compiled once at import time)
# ---------------------------------------------------------------------------

_RE_CLASS_DESCRIPTOR = re.compile(r"^L[\w/$]+;$")

_RE_URL_HTTP = re.compile(r"^https?://", re.IGNORECASE)
_RE_URL_FTP = re.compile(r"^ftp://", re.IGNORECASE)
_RE_URL_CONTENT = re.compile(r"^content://", re.IGNORECASE)
_RE_URL_FILE = re.compile(r"^file://", re.IGNORECASE)
_RE_DOMAIN_LIKE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|co|app|dev|api|cloud|ai|info|biz|mobi|me)(?:/[^\s]*)?$",
    re.IGNORECASE,
)

# (pattern_name, severity, confidence, description, compiled_re)
# ``confidence`` reflects how strongly the pattern alone implies a real secret:
#   high   — a definitive, well-known key format (Google/AWS/PEM) or a fixed
#            vendor domain. Format match is near-conclusive for the *type*.
#   medium — context/assignment heuristics that frequently match placeholders,
#            test values, or examples and therefore need confirmation.
_SECRETS_PATTERNS: list[tuple[str, str, str, str, re.Pattern]] = [
    (
        "google_api_key",
        "high",
        "high",
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    ),
    (
        "aws_access_key",
        "high",
        "high",
        "AWS Access Key ID",
        re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    (
        "aws_secret_context",
        "high",
        "medium",
        "AWS Secret Key context",
        re.compile(r"(?:aws_secret|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+]{20,})['\"]?", re.IGNORECASE),
    ),
    (
        "generic_api_key",
        "medium",
        "medium",
        "Generic API Key assignment",
        re.compile(r"[Aa]pi[_\-]?[Kk]ey\s*[=:]\s*['\"]([A-Za-z0-9]{16,})['\"]"),
    ),
    (
        "firebase_url",
        "medium",
        "high",
        "Firebase Realtime Database URL",
        re.compile(r"[a-z0-9\-]+\.firebaseio\.com", re.IGNORECASE),
    ),
    (
        "private_key_pem",
        "high",
        "high",
        "PEM Private Key block",
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ),
    (
        "password_context",
        "medium",
        "medium",
        "Hardcoded password value",
        re.compile(
            r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]",
            re.IGNORECASE,
        ),
    ),
    (
        "bearer_token",
        "high",
        "medium",
        "Bearer token",
        re.compile(r"Bearer [A-Za-z0-9\-._~+/]+=*"),
    ),
    (
        "slack_token",
        "high",
        "high",
        "Slack token",
        re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    ),
    (
        "stripe_secret_key",
        "high",
        "high",
        "Stripe secret key",
        re.compile(r"sk_live_[0-9A-Za-z]{16,}"),
    ),
    (
        "github_token",
        "high",
        "high",
        "GitHub personal access token",
        re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"),
    ),
    (
        "jwt",
        "medium",
        "high",
        "JSON Web Token",
        re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ),
]

_RE_HIGH_ENTROPY_B64 = re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")

# A token that looks like a Java/Kotlin identifier, class path, descriptor, or
# crypto-transformation string rather than a real secret. These dominate the
# DEX string pool and were the source of thousands of false-positive
# "high entropy" hits in real audits (e.g. ``ActivityResultRegistry``,
# ``AES/CBC/PKCS7Padding``).
_RE_IDENTIFIER_LIKE = re.compile(
    r"^[A-Za-z][A-Za-z0-9]*(?:[/_$.][A-Za-z][A-Za-z0-9]*)*$"
)

# Interesting-string category patterns
_RE_FILE_PATH = re.compile(r"(?:/[\w.\-]+){2,}|[\w\-]+\.(?:apk|dex|so|jar|sh|db|sqlite|json|xml|pem|key|crt|p12|pfx)")
_RE_SQL = re.compile(
    r"\b(?:SELECT|INSERT\s+INTO|UPDATE\s+\w|DELETE\s+FROM|CREATE\s+TABLE|DROP\s+TABLE|ALTER\s+TABLE|PRAGMA)\b",
    re.IGNORECASE,
)
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_RE_SHELL = re.compile(
    r"\b(?:chmod|chown|su\b|busybox|/system/bin|/system/xbin|/sbin|/proc/|/data/data|mount\s|iptables|nc\s|netcat|curl\s|wget\s)\b",
    re.IGNORECASE,
)
_RE_SENSITIVE_KW = re.compile(
    r"\b(?:password|passwd|pwd|token|secret|api[_\-]?key|auth(?:entication|orization)?|credential|private[_\-]?key|access[_\-]?key)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------


def _xref_methods(string_analysis) -> list[str]:
    """Return a deduplicated list of 'ClassName->method_name' xref strings."""
    results: list[str] = []
    for class_analysis, method_analysis in string_analysis.get_xref_from():
        class_name = class_analysis.name
        method_name = method_analysis.name
        results.append(f"{class_name}->{method_name}")
    return sorted(set(results))


def _iter_strings(session_id: str):
    """Yield StringAnalysis objects for a given session."""
    session = get_session(session_id)
    return session.analysis.get_strings()


def _shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of *value* in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_identifier(value: str) -> bool:
    """True if *value* resembles a class path / identifier / constant name.

    These (e.g. ``ActivityResultRegistry``, ``AES/CBC/PKCS7Padding``) match a
    loose base64 character set but are not secrets. Filtering them removes the
    dominant false-positive class in the DEX string pool.
    """
    return bool(_RE_IDENTIFIER_LIKE.match(value))


def _is_high_entropy_b64(value: str) -> bool:
    """Return True if *value* looks like genuinely high-entropy secret material.

    Tightened well beyond a charset+length check to suppress the dominant
    false-positive class (Java identifiers, class descriptors, crypto
    transformation strings). A candidate must:

    - be at least 24 chars of the base64 alphabet;
    - NOT parse as an identifier / class path / transformation string;
    - show character-class diversity typical of real keys (a mix of
      upper/lower/digit, or base64 symbols ``+`` ``/`` ``=``);
    - have Shannon entropy above ~3.6 bits/char (random key material sits
      well above this; English-ish identifiers sit below).
    """
    if len(value) < 24:
        return False
    if not _RE_HIGH_ENTROPY_B64.match(value):
        return False

    entropy = _shannon_entropy(value)
    # Identifier / class-path / transformation strings are rejected — unless the
    # entropy is so high the value cannot be a readable identifier (real keys
    # that happen to be '/'-separated, e.g. AWS secret keys, sit well above this).
    if _looks_like_identifier(value) and entropy < 4.2:
        return False

    has_lower = any(c.islower() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_digit = any(c.isdigit() for c in value)
    has_symbol = ("+" in value) or ("/" in value) or value.endswith("=")
    if sum((has_lower, has_upper, has_digit)) < 2 and not has_symbol:
        return False

    return entropy >= 3.6


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


@mcp.tool()
def search_strings(
    session_id: str,
    pattern: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Search strings in the DEX string pool.

    If *pattern* is provided it is used as a regular expression to filter the
    string pool.  Without a pattern all strings are returned (paginated via
    *offset* / *limit*).

    For each matched string the response includes its value, length, and a
    count of methods that reference it (xref_count).

    Args:
        session_id: Active analysis session ID returned by ``load_apk``.
        pattern:    Optional regex pattern to filter strings (empty = return all).
        limit:      Maximum number of results to return (default 50).
        offset:     Number of results to skip for pagination (default 0).

    Returns:
        dict: ``{"status": "ok", "data": {"strings": [...], "total": N,
                 "offset": O, "limit": L}}``
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        if pattern:
            try:
                re.compile(pattern)
            except re.error as exc:
                return {
                    "status": "error",
                    "message": f"Invalid regex pattern: {exc}",
                    "suggestion": "Provide a valid Python regular expression.",
                }
            raw_iter: Iterator = analysis.find_strings(string=pattern)
        else:
            raw_iter = analysis.get_strings()

        all_strings: list[dict] = []
        for sa in raw_iter:
            value = sa.get_value()
            all_strings.append(
                {
                    "value": value,
                    "length": len(value),
                    "xref_count": len(list(sa.get_xref_from())),
                }
            )

        total = len(all_strings)
        page = all_strings[offset : offset + limit]

        return {
            "status": "ok",
            "data": {
                "strings": page,
                "total": total,
                "offset": offset,
                "limit": limit,
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a valid session.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Ensure the session is valid and the APK was successfully loaded.",
        }


@mcp.tool()
def extract_urls(session_id: str) -> dict:
    """Extract all URL-like strings from the APK.

    Scans the DEX string pool for strings matching ``https?://``, ``ftp://``,
    ``content://``, ``file://``, and bare domain-like strings without a
    protocol prefix.

    Results are categorized into ``http_urls``, ``https_urls``,
    ``content_uris``, ``file_uris``, and ``other``.  For each URL the response
    also lists which methods reference it.

    Args:
        session_id: Active analysis session ID.

    Returns:
        dict: ``{"status": "ok", "data": {"http_urls": [...], "https_urls": [...],
                 "content_uris": [...], "file_uris": [...], "other": [...],
                 "total": N}}``
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        categories: dict[str, list[dict]] = {
            "https_urls": [],
            "http_urls": [],
            "ftp_urls": [],
            "content_uris": [],
            "file_uris": [],
            "other": [],
        }

        for sa in analysis.get_strings():
            value = sa.get_value()
            methods = _xref_methods(sa)
            entry = {"value": value, "methods": methods}

            if re.match(r"^https://", value, re.IGNORECASE):
                categories["https_urls"].append(entry)
            elif re.match(r"^http://", value, re.IGNORECASE):
                categories["http_urls"].append(entry)
            elif _RE_URL_FTP.match(value):
                categories["ftp_urls"].append(entry)
            elif _RE_URL_CONTENT.match(value):
                categories["content_uris"].append(entry)
            elif _RE_URL_FILE.match(value):
                categories["file_uris"].append(entry)
            elif _RE_DOMAIN_LIKE.match(value):
                categories["other"].append(entry)

        total = sum(len(v) for v in categories.values())

        return {
            "status": "ok",
            "data": {**categories, "total": total},
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a valid session.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Ensure the session is valid and the APK was successfully loaded.",
        }


@mcp.tool()
def extract_secrets(session_id: str) -> dict:
    """Search for potential hardcoded secrets, API keys, and credentials.

    Scans the DEX string pool against a curated list of patterns that
    commonly indicate secrets embedded in APK code:

    - Google API keys (``AIza…``), AWS access/secret keys, PEM private keys
    - Slack / Stripe / GitHub tokens, JWTs, Firebase Realtime Database URLs
    - Generic API-key and password assignments, Bearer tokens
    - High-entropy blobs (entropy + diversity filtered, identifiers excluded)

    Each finding records the matched value, the pattern name, a severity, a
    ``confidence`` level, a ``verification_needed`` flag, a ``verify_with``
    recipe, and which methods reference the string.

    IMPORTANT — finding a string that *looks* like a key is not the same as
    finding an exploitable secret. The high-entropy detector in particular is
    noisy; treat anything with ``verification_needed=true`` as a candidate and
    confirm it via ``verify_with`` before reporting it to the user.

    Args:
        session_id: Active analysis session ID.

    Returns:
        dict: ``{"status": "ok", "data": {"findings": [...], "total": N,
                 "severity_counts": {...}, "confidence_counts": {...},
                 "needs_verification_count": N, "guidance": "..."}}``
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        findings: list[dict] = []
        seen: set[str] = set()  # deduplicate by (pattern_name, value)

        # Map pattern_name → probe tool name for live verification
        _PROBE_HINT_MAP: dict[str, str] = {
            "google_api_key": "probe_google_api_key",
            "firebase_url": "probe_firebase_rtdb",
            "aws_access_key": "probe_aws_key",
        }

        for sa in analysis.get_strings():
            value = sa.get_value()
            methods = _xref_methods(sa)

            # Check each named pattern
            for pattern_name, severity, confidence, description, compiled_re in _SECRETS_PATTERNS:
                if compiled_re.search(value):
                    key = f"{pattern_name}:{value}"
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            {
                                "value": value,
                                "pattern_name": pattern_name,
                                "description": description,
                                "severity": severity,
                                "confidence": confidence,
                                "verification_needed": confidence != "high",
                                "verify_with": (
                                    "Decompile a referencing method and confirm this is a "
                                    "live credential, not a placeholder, example, or test "
                                    "value. For API keys, check whether the key is scoped/"
                                    "restricted before treating it as exploitable."
                                ),
                                "probe_hint": _PROBE_HINT_MAP.get(pattern_name, ""),
                                "methods": methods,
                            }
                        )

            # High-entropy blob check (only if nothing else matched). This is the
            # noisiest detector by far, so it is always low-confidence and must be
            # verified — the value is just as likely to be encoded data, a hash,
            # or an obfuscated identifier as a real secret.
            b64_key = f"high_entropy_b64:{value}"
            if b64_key not in seen and _is_high_entropy_b64(value):
                seen.add(b64_key)
                findings.append(
                    {
                        "value": value,
                        "pattern_name": "high_entropy_b64",
                        "description": "High-entropy string (possible secret — unconfirmed)",
                        "severity": "low",
                        "confidence": "low",
                        "verification_needed": True,
                        "verify_with": (
                            "Decompile a referencing method and determine what this string "
                            "is. High entropy alone does not make it a secret — it may be "
                            "encoded data, a hash, a resource id, or an obfuscated name."
                        ),
                        "methods": methods,
                    }
                )

        # Sort: high → medium → low, then alphabetically by pattern name
        _sev_order = {"high": 0, "medium": 1, "low": 2}
        findings.sort(key=lambda f: (_sev_order.get(f["severity"], 99), f["pattern_name"]))

        severity_counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        confidence_counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        for f in findings:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1
            confidence_counts[f["confidence"]] = confidence_counts.get(f["confidence"], 0) + 1

        needs_verification = sum(1 for f in findings if f.get("verification_needed"))

        return {
            "status": "ok",
            "data": {
                "findings": findings,
                "total": len(findings),
                "severity_counts": severity_counts,
                "confidence_counts": confidence_counts,
                "needs_verification_count": needs_verification,
                "guidance": (
                    "Format-validated high-confidence hits (Google/AWS/PEM/Slack/"
                    "Stripe/GitHub/Firebase) are very likely real keys of that type, "
                    "but still confirm they are live and unrestricted before "
                    "reporting impact. Everything with verification_needed=true — "
                    "especially high_entropy_b64 — is a candidate: follow verify_with "
                    "before presenting it to the user as a secret."
                ),
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a valid session.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Ensure the session is valid and the APK was successfully loaded.",
        }


@mcp.tool()
def search_code(session_id: str, pattern: str, limit: int = 50) -> dict:
    """Search through disassembled Dalvik bytecode for a pattern.

    Iterates over every method in the APK's analysis, converts each
    instruction to its string representation, and returns matches for
    *pattern* (Python regex).  String references, class references, and
    method invocations are all included in the searchable text per
    instruction.

    Args:
        session_id: Active analysis session ID.
        pattern:    Python regex pattern to search for.
        limit:      Maximum number of matching locations to return (default 50).

    Returns:
        dict: ``{"status": "ok", "data": {"matches": [...], "total_found": N,
                 "truncated": bool}}``

        Each match includes:
        - ``class_name``
        - ``method_name``
        - ``method_descriptor``
        - ``matched_instruction`` — the disassembled instruction text that matched
        - ``offset`` — bytecode offset of the instruction
    """
    try:
        if not pattern:
            return {
                "status": "error",
                "message": "pattern must not be empty.",
                "suggestion": "Provide a non-empty regex pattern to search for.",
            }

        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            return {
                "status": "error",
                "message": f"Invalid regex pattern: {exc}",
                "suggestion": "Provide a valid Python regular expression.",
            }

        session = get_session(session_id)
        analysis = session.analysis

        matches: list[dict] = []
        total_found = 0

        for method_analysis in analysis.get_methods():
            encoded_method = method_analysis.get_method()
            # Skip abstract / native / interface methods (no code)
            if encoded_method is None:
                continue
            code = encoded_method.get_code()
            if code is None:
                continue

            class_name = method_analysis.class_name
            method_name = method_analysis.name
            descriptor = method_analysis.descriptor

            try:
                instructions = list(code.get_bc().get_instructions())
            except Exception:  # noqa: BLE001
                continue

            for instr in instructions:
                try:
                    instr_str = str(instr)
                except Exception:  # noqa: BLE001
                    continue

                if compiled.search(instr_str):
                    total_found += 1
                    if len(matches) < limit:
                        matches.append(
                            {
                                "class_name": class_name,
                                "method_name": method_name,
                                "method_descriptor": descriptor,
                                "matched_instruction": instr_str,
                                "offset": instr.get_ref_off() if hasattr(instr, "get_ref_off") else None,
                            }
                        )

        return {
            "status": "ok",
            "data": {
                "matches": matches,
                "total_found": total_found,
                "truncated": total_found > limit,
                "limit": limit,
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a valid session.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Ensure the session is valid and the APK was successfully loaded.",
        }


@mcp.tool()
def extract_interesting_strings(session_id: str) -> dict:
    """Automatically extract noteworthy strings from the APK.

    Filters out Android/Java boilerplate (class descriptors, very short or
    very long strings, common framework strings) and returns strings that are
    likely to be application-specific and security-relevant, grouped into
    categories:

    - ``file_paths`` — file-system paths and common file extensions
    - ``sql_queries`` — SQL statements (SELECT, INSERT, CREATE TABLE, …)
    - ``ip_addresses`` — IPv4 addresses
    - ``email_addresses`` — e-mail addresses
    - ``shell_commands`` — shell / root commands and sensitive paths
    - ``sensitive_keywords`` — strings containing password / token / key / auth
    - ``other`` — anything else that survived the boilerplate filter

    Args:
        session_id: Active analysis session ID.

    Returns:
        dict: ``{"status": "ok", "data": {"categories": {...},
                 "total": N, "filtered_out": N}}``

        Each entry inside a category list contains ``value``, ``length``,
        and ``xref_count``.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        categories: dict[str, list[dict]] = {
            "file_paths": [],
            "sql_queries": [],
            "ip_addresses": [],
            "email_addresses": [],
            "shell_commands": [],
            "sensitive_keywords": [],
            "other": [],
        }

        total_seen = 0
        filtered_out = 0

        for sa in analysis.get_strings():
            total_seen += 1
            value = sa.get_value()

            # ---- boilerplate filters ----
            # Class descriptors (Landroid/os/Bundle;)
            if _RE_CLASS_DESCRIPTOR.match(value):
                filtered_out += 1
                continue

            # Length bounds
            if len(value) < 4 or len(value) > 500:
                filtered_out += 1
                continue

            # Very common boilerplate exact matches
            if value in _BOILERPLATE_EXACT:
                filtered_out += 1
                continue

            # Common Android/Java package prefixes
            if any(value.startswith(prefix) for prefix in _BOILERPLATE_PREFIXES):
                filtered_out += 1
                continue

            # Strings that are just numeric (version codes, etc.)
            if value.isdigit():
                filtered_out += 1
                continue

            # ---- categorise survivors ----
            xref_count = len(list(sa.get_xref_from()))
            entry = {"value": value, "length": len(value), "xref_count": xref_count}
            categorised = False

            if _RE_SQL.search(value):
                categories["sql_queries"].append(entry)
                categorised = True
            if _RE_FILE_PATH.search(value):
                categories["file_paths"].append(entry)
                categorised = True
            if _RE_IP.search(value):
                categories["ip_addresses"].append(entry)
                categorised = True
            if _RE_EMAIL.search(value):
                categories["email_addresses"].append(entry)
                categorised = True
            if _RE_SHELL.search(value):
                categories["shell_commands"].append(entry)
                categorised = True
            if _RE_SENSITIVE_KW.search(value):
                categories["sensitive_keywords"].append(entry)
                categorised = True

            if not categorised:
                categories["other"].append(entry)

        total_kept = sum(len(v) for v in categories.values())

        return {
            "status": "ok",
            "data": {
                "categories": categories,
                "total": total_kept,
                "filtered_out": filtered_out,
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a valid session.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Ensure the session is valid and the APK was successfully loaded.",
        }
