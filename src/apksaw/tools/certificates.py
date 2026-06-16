"""APK certificate and signing analysis tools."""

import hashlib
import zipfile
from datetime import datetime, timezone
from typing import Any, Optional

from apksaw.server import mcp
from apksaw.session import get_session


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _format_fingerprint(digest_bytes: bytes) -> str:
    """Format a raw digest as uppercase colon-separated hex (AA:BB:CC:...)."""
    return ":".join(f"{b:02X}" for b in digest_bytes)


def _fingerprints(cert_der: bytes) -> dict[str, str]:
    """Return SHA-1 and SHA-256 fingerprints for a DER-encoded certificate."""
    return {
        "sha1": _format_fingerprint(hashlib.sha1(cert_der).digest()),  # noqa: S324
        "sha256": _format_fingerprint(hashlib.sha256(cert_der).digest()),
    }


def _dn_to_str(name) -> str:
    """Convert a cryptography X.509 Name to an RFC 4514-style string."""
    try:
        return name.rfc4514_string()
    except Exception:
        pass
    # Fallback: manual construction
    try:
        parts = []
        for attr in name:
            oid_dotted = attr.oid.dotted_string
            # Try human-readable OID name
            try:
                oid_label = attr.oid._name  # private but works across versions
            except AttributeError:
                oid_label = oid_dotted
            parts.append(f"{oid_label}={attr.value}")
        return ", ".join(parts)
    except Exception:
        return str(name)


def _datetime_to_iso(dt: datetime) -> str:
    """Return an ISO-8601 string, always UTC."""
    try:
        if dt.tzinfo is None:
            # Androguard / older cryptography returns naive UTC datetimes
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return str(dt)


def _key_info(public_key) -> dict[str, Any]:
    """Extract algorithm name and key size from a public key object."""
    from cryptography.hazmat.primitives.asymmetric import (
        dsa,
        ec,
        ed448,
        ed25519,
        rsa,
    )

    if isinstance(public_key, rsa.RSAPublicKey):
        return {"algorithm": "RSA", "key_size": public_key.key_size}
    if isinstance(public_key, dsa.DSAPublicKey):
        return {"algorithm": "DSA", "key_size": public_key.key_size}
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return {
            "algorithm": "EC",
            "key_size": public_key.key_size,
            "curve": public_key.curve.name,
        }
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return {"algorithm": "Ed25519", "key_size": 256}
    if isinstance(public_key, ed448.Ed448PublicKey):
        return {"algorithm": "Ed448", "key_size": 448}
    return {"algorithm": type(public_key).__name__, "key_size": None}


def _parse_cert_der(cert_der: bytes) -> dict[str, Any]:
    """Parse a DER-encoded X.509 certificate into a structured dict.

    Returns a dict with all relevant fields, or raises on failure.
    """
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert = x509.load_der_x509_certificate(cert_der, default_backend())

    subject_str = _dn_to_str(cert.subject)
    issuer_str = _dn_to_str(cert.issuer)
    is_self_signed = subject_str == issuer_str

    # Signature algorithm
    try:
        sig_algo = cert.signature_algorithm_oid.dotted_string
        try:
            sig_algo = cert.signature_hash_algorithm.name.upper() + "with" + _key_info(cert.public_key())["algorithm"]
        except Exception:
            pass
    except Exception:
        sig_algo = "unknown"

    # Validity dates
    try:
        not_before = _datetime_to_iso(cert.not_valid_before_utc)
    except AttributeError:
        # cryptography < 42.x uses not_valid_before (naive UTC)
        not_before = _datetime_to_iso(cert.not_valid_before)  # type: ignore[attr-defined]

    try:
        not_after = _datetime_to_iso(cert.not_valid_after_utc)
    except AttributeError:
        not_after = _datetime_to_iso(cert.not_valid_after)  # type: ignore[attr-defined]

    fps = _fingerprints(cert_der)

    return {
        "subject": subject_str,
        "issuer": issuer_str,
        "serial_number": str(cert.serial_number),
        "not_before": not_before,
        "not_after": not_after,
        "signature_algorithm": sig_algo,
        "public_key": _key_info(cert.public_key()),
        "fingerprint_sha1": fps["sha1"],
        "fingerprint_sha256": fps["sha256"],
        "is_self_signed": is_self_signed,
    }


def _is_debug_cert(cert_info: dict) -> bool:
    """Return True if the certificate looks like an Android debug certificate."""
    subject = cert_info.get("subject", "").lower()
    # Standard AOSP debug key: CN=Android Debug, O=Android, C=US
    if "cn=android debug" in subject:
        return True
    # Some toolchains use "debug" in the organization field
    if "o=android" in subject and "debug" in subject:
        return True
    return False


def _get_certs_v1(apk) -> list[bytes]:
    """Extract DER-encoded signing certificates from META-INF via PKCS#7."""
    certs: list[bytes] = []
    try:
        apk_path = str(apk.get_filename())
    except Exception:
        return certs

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                upper = name.upper()
                if upper.startswith("META-INF/") and upper.endswith(
                    (".RSA", ".DSA", ".EC")
                ):
                    try:
                        pkcs7_data = zf.read(name)
                        certs.extend(_extract_certs_from_pkcs7(pkcs7_data))
                    except Exception:
                        pass
    except Exception:
        pass

    return certs


def _extract_certs_from_pkcs7(pkcs7_data: bytes) -> list[bytes]:
    """Extract DER-encoded X.509 certs from a PKCS#7 SignedData blob."""
    der_certs: list[bytes] = []

    # Approach 1: cryptography's pkcs7 module (available since 3.x)
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7 as cpkcs7

        p7 = cpkcs7.load_der_pkcs7_certificates(pkcs7_data)
        for cert in p7:
            der_certs.append(cert.public_bytes(
                __import__("cryptography").hazmat.primitives.serialization.Encoding.DER
            ))
        if der_certs:
            return der_certs
    except Exception:
        pass

    # Approach 2: pyOpenSSL (optional dependency)
    try:
        from OpenSSL.crypto import load_pkcs7_data, FILETYPE_ASN1, _util

        p7 = load_pkcs7_data(FILETYPE_ASN1, pkcs7_data)
        certs_stack = _util.lib.PKCS7_get0_signers(p7._pkcs7, None, 0)
        if certs_stack != _util.ffi.NULL:
            count = _util.lib.sk_X509_num(certs_stack)
            for i in range(count):
                x509 = _util.lib.sk_X509_value(certs_stack, i)
                from OpenSSL.crypto import X509, dump_certificate, FILETYPE_ASN1 as FT_ASN1
                cert = X509.__new__(X509)
                cert._x509 = _util.ffi.gc(
                    _util.lib.X509_dup(x509), _util.lib.X509_free
                )
                der_certs.append(dump_certificate(FT_ASN1, cert))
        if der_certs:
            return der_certs
    except Exception:
        pass

    # Approach 3: asn1crypto (lightweight pure-python fallback)
    try:
        from asn1crypto import cms, pem as asn1pem

        if asn1pem.detect(pkcs7_data):
            _, _, pkcs7_data = asn1pem.unarmor(pkcs7_data)
        content_info = cms.ContentInfo.load(pkcs7_data)
        signed_data = content_info["content"].parsed
        for cert_choice in signed_data["certificates"]:
            try:
                der_certs.append(cert_choice.chosen.dump())
            except Exception:
                pass
        if der_certs:
            return der_certs
    except Exception:
        pass

    return der_certs


def _collect_all_cert_ders(apk) -> dict[str, list[bytes]]:
    """Return DER cert bytes grouped by signing scheme.

    Keys: "v2", "v3", "v1" — values are lists of DER bytes.
    Empty list means not signed or extraction failed.
    """
    result: dict[str, list[bytes]] = {"v1": [], "v2": [], "v3": []}

    # --- v2 ---
    try:
        v2_certs = apk.get_certificates_der_v2()
        if v2_certs:
            result["v2"] = list(v2_certs)
    except AttributeError:
        pass
    except Exception:
        pass

    # --- v3 ---
    try:
        v3_certs = apk.get_certificates_der_v3()
        if v3_certs:
            result["v3"] = list(v3_certs)
    except AttributeError:
        pass
    except Exception:
        pass

    # --- v1 ---
    try:
        if apk.is_signed_v1():
            result["v1"] = _get_certs_v1(apk)
    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Tool: get_signing_info
# ---------------------------------------------------------------------------


@mcp.tool()
def get_signing_info(session_id: str) -> dict:
    """Get comprehensive APK signing and certificate information.

    Detects which signing schemes are used (v1 JAR signing, v2 APK Signature
    Scheme, v3 with key rotation) and parses the certificate(s) for each
    scheme.  Certificate details include subject/issuer Distinguished Names,
    serial number, validity period, signature and public-key algorithms, key
    size, SHA-1 and SHA-256 fingerprints, and whether the certificate is
    self-signed or a debug certificate.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with::

            {
              "status": "ok",
              "data": {
                "schemes": {"v1": bool, "v2": bool, "v3": bool},
                "certificates": [
                  {
                    "scheme": "v1"|"v2"|"v3",
                    "subject": "<DN>",
                    "issuer": "<DN>",
                    "serial_number": "<str>",
                    "not_before": "<ISO-8601>",
                    "not_after": "<ISO-8601>",
                    "signature_algorithm": "<str>",
                    "public_key": {"algorithm": str, "key_size": int, ...},
                    "fingerprint_sha1": "AA:BB:...",
                    "fingerprint_sha256": "AA:BB:...",
                    "is_self_signed": bool,
                    "is_debug": bool,
                  },
                  ...
                ],
                "is_debug": bool,
              }
            }
    """
    try:
        session = get_session(session_id)
        apk = session.apk

        # Determine which schemes are active
        schemes: dict[str, bool] = {"v1": False, "v2": False, "v3": False}
        for scheme in ("v1", "v2", "v3"):
            try:
                schemes[scheme] = bool(getattr(apk, f"is_signed_{scheme}")())
            except Exception:
                schemes[scheme] = False

        # Collect raw DER bytes per scheme
        cert_ders_by_scheme = _collect_all_cert_ders(apk)

        # Parse certificates
        parsed_certs: list[dict[str, Any]] = []
        parse_errors: list[str] = []

        for scheme in ("v1", "v2", "v3"):
            for cert_der in cert_ders_by_scheme[scheme]:
                try:
                    info = _parse_cert_der(cert_der)
                    info["scheme"] = scheme
                    info["is_debug"] = _is_debug_cert(info)
                    parsed_certs.append(info)
                except Exception as exc:
                    parse_errors.append(
                        f"scheme={scheme}: failed to parse certificate — {exc}"
                    )

        # Deduplicate certificates that appear in multiple schemes by fingerprint
        seen_fps: set[str] = set()
        unique_certs: list[dict] = []
        for cert in parsed_certs:
            fp = cert.get("fingerprint_sha256", "")
            if fp not in seen_fps:
                seen_fps.add(fp)
                unique_certs.append(cert)
            else:
                # Cert already recorded; update the scheme field to reflect all schemes
                for existing in unique_certs:
                    if existing.get("fingerprint_sha256") == fp:
                        existing_scheme = existing.get("scheme", "")
                        new_scheme = cert.get("scheme", "")
                        if new_scheme not in existing_scheme:
                            existing["scheme"] = f"{existing_scheme},{new_scheme}"
                        break

        is_debug = any(c.get("is_debug") for c in unique_certs)

        data: dict[str, Any] = {
            "schemes": schemes,
            "certificates": unique_certs,
            "is_debug": is_debug,
        }
        if parse_errors:
            data["parse_errors"] = parse_errors

        return {"status": "ok", "data": data}

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Failed to retrieve signing info: {exc}",
            "suggestion": (
                "Ensure the APK was loaded successfully and that the "
                "'cryptography' package is installed."
            ),
        }


# ---------------------------------------------------------------------------
# Tool: check_certificate_security
# ---------------------------------------------------------------------------


def _years_between(iso_start: str, iso_end: str) -> Optional[float]:
    """Return the approximate number of years between two ISO-8601 strings."""
    try:
        # Attempt full ISO parse via fromisoformat (Python 3.11+ handles Z)
        try:
            start = datetime.fromisoformat(iso_start)
            end = datetime.fromisoformat(iso_end)
        except ValueError:
            # Fallback: strip trailing Z and treat as UTC
            start = datetime.strptime(iso_start.rstrip("Z"), "%Y-%m-%dT%H:%M:%S+00:00")
            end = datetime.strptime(iso_end.rstrip("Z"), "%Y-%m-%dT%H:%M:%S+00:00")
        delta = end - start
        return delta.total_seconds() / (365.25 * 24 * 3600)
    except Exception:
        return None


@mcp.tool()
def check_certificate_security(session_id: str) -> dict:
    """Perform a security assessment of the APK's signing configuration.

    Checks for known weaknesses and misconfigurations:

    - v1-only signing: vulnerable to the Janus attack (CVE-2017-13156) on
      Android < 8.0, because a DEX header can be prepended without breaking
      the v1 signature.
    - Missing v2/v3 signing: apps targeting modern Android should use at least
      APK Signature Scheme v2 for stronger tamper protection.
    - Debug certificate: indicates a non-production / test build.
    - Self-signed certificate: normal for Android but noted for completeness.
    - Expired certificate: the current date is past ``not_after``.
    - Weak public key: RSA or DSA < 2048 bits; EC < 256 bits.
    - Weak signature algorithm: contains MD5 or SHA-1.
    - Unusually long validity period: > 25 years (may indicate a
      machine-generated "forever" certificate).

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with::

            {
              "status": "ok",
              "data": {
                "findings": [
                  {
                    "id": str,
                    "severity": "critical"|"high"|"medium"|"low"|"info",
                    "title": str,
                    "detail": str,
                  },
                  ...
                ],
                "summary": {
                  "critical": int,
                  "high": int,
                  "medium": int,
                  "low": int,
                  "info": int,
                  "total": int,
                },
              }
            }
    """
    try:
        # Re-use get_signing_info internally to avoid duplicating logic
        signing_result = get_signing_info(session_id)
        if signing_result.get("status") != "ok":
            return signing_result

        sign_data = signing_result["data"]
        schemes: dict[str, bool] = sign_data.get("schemes", {})
        certs: list[dict] = sign_data.get("certificates", [])

        findings: list[dict[str, str]] = []
        now = datetime.now(tz=timezone.utc)

        # -------------------------------------------------------------------
        # Scheme-level checks
        # -------------------------------------------------------------------

        v1 = schemes.get("v1", False)
        v2 = schemes.get("v2", False)
        v3 = schemes.get("v3", False)

        if not v1 and not v2 and not v3:
            findings.append({
                "id": "CERT_NOT_SIGNED",
                "severity": "critical",
                "title": "APK is not signed",
                "detail": (
                    "No recognized signing scheme (v1, v2, v3) was detected. "
                    "Android will refuse to install unsigned APKs."
                ),
            })
        else:
            if v1 and not v2 and not v3:
                findings.append({
                    "id": "CERT_V1_ONLY",
                    "severity": "high",
                    "title": "Only v1 (JAR) signing is used — Janus vulnerability",
                    "detail": (
                        "APK is signed exclusively with v1 (JAR) signing. "
                        "This is vulnerable to the Janus attack (CVE-2017-13156): "
                        "an attacker can prepend a DEX file to the APK without "
                        "invalidating the v1 signature, allowing arbitrary code "
                        "execution on devices running Android < 8.0 (API 26). "
                        "Add APK Signature Scheme v2 or v3."
                    ),
                })

            if not v2 and not v3:
                findings.append({
                    "id": "CERT_NO_V2_V3",
                    "severity": "medium",
                    "title": "No v2 or v3 APK signing scheme present",
                    "detail": (
                        "APK Signature Scheme v2 (Android 7.0+) and v3 "
                        "(Android 9.0+ key rotation) are absent. "
                        "Modern signing schemes provide stronger integrity "
                        "guarantees and are required by Google Play for new apps."
                    ),
                })

        # -------------------------------------------------------------------
        # Per-certificate checks
        # -------------------------------------------------------------------

        for i, cert in enumerate(certs):
            label = cert.get("subject", f"cert[{i}]")
            scheme = cert.get("scheme", "?")

            # Debug certificate
            if cert.get("is_debug"):
                findings.append({
                    "id": f"CERT_DEBUG_{i}",
                    "severity": "high",
                    "title": f"Debug certificate detected (scheme {scheme})",
                    "detail": (
                        f"Subject: {label}. "
                        "Debug certificates (CN=Android Debug) are generated "
                        "automatically by Android build tools and must not be "
                        "used in production releases."
                    ),
                })

            # Self-signed (informational — completely normal for Android)
            if cert.get("is_self_signed"):
                findings.append({
                    "id": f"CERT_SELF_SIGNED_{i}",
                    "severity": "info",
                    "title": f"Self-signed certificate (scheme {scheme})",
                    "detail": (
                        f"Subject: {label}. "
                        "Android apps are routinely self-signed. "
                        "This is expected behaviour, noted here for completeness."
                    ),
                })

            # Expired certificate
            try:
                not_after_str = cert.get("not_after", "")
                not_after_dt = datetime.fromisoformat(not_after_str)
                if not_after_dt.tzinfo is None:
                    not_after_dt = not_after_dt.replace(tzinfo=timezone.utc)
                if now > not_after_dt:
                    findings.append({
                        "id": f"CERT_EXPIRED_{i}",
                        "severity": "medium",
                        "title": f"Certificate has expired (scheme {scheme})",
                        "detail": (
                            f"Subject: {label}. "
                            f"Certificate expired on {not_after_str}. "
                            "While Android does not revoke installation of apps "
                            "signed with expired certificates, signing with an "
                            "expired cert is a security hygiene issue."
                        ),
                    })
            except Exception:
                pass

            # Weak public key
            pk = cert.get("public_key", {})
            algo = pk.get("algorithm", "").upper()
            key_size = pk.get("key_size")
            if key_size is not None:
                weak = False
                if algo in ("RSA", "DSA") and key_size < 2048:
                    weak = True
                elif algo == "EC" and key_size < 256:
                    weak = True
                if weak:
                    findings.append({
                        "id": f"CERT_WEAK_KEY_{i}",
                        "severity": "high",
                        "title": (
                            f"Weak {algo} key ({key_size} bits) in scheme {scheme}"
                        ),
                        "detail": (
                            f"Subject: {label}. "
                            f"The {algo} public key is only {key_size} bits. "
                            "RSA/DSA keys should be at least 2048 bits; "
                            "EC keys at least 256 bits."
                        ),
                    })

            # Weak signature algorithm
            sig_algo = cert.get("signature_algorithm", "").upper()
            if "MD5" in sig_algo:
                findings.append({
                    "id": f"CERT_WEAK_SIG_MD5_{i}",
                    "severity": "high",
                    "title": f"MD5 signature algorithm in scheme {scheme}",
                    "detail": (
                        f"Subject: {label}. "
                        f"Signature algorithm: {cert.get('signature_algorithm')}. "
                        "MD5 is cryptographically broken and must not be used "
                        "for code signing."
                    ),
                })
            elif "SHA1" in sig_algo or "SHA-1" in sig_algo:
                findings.append({
                    "id": f"CERT_WEAK_SIG_SHA1_{i}",
                    "severity": "medium",
                    "title": f"SHA-1 signature algorithm in scheme {scheme}",
                    "detail": (
                        f"Subject: {label}. "
                        f"Signature algorithm: {cert.get('signature_algorithm')}. "
                        "SHA-1 is deprecated and collision-prone. "
                        "Migrate to SHA-256 or stronger."
                    ),
                })

            # Unusually long validity period (> 25 years)
            not_before_str = cert.get("not_before", "")
            not_after_str = cert.get("not_after", "")
            validity_years = _years_between(not_before_str, not_after_str)
            if validity_years is not None and validity_years > 25:
                findings.append({
                    "id": f"CERT_LONG_VALIDITY_{i}",
                    "severity": "low",
                    "title": (
                        f"Unusually long certificate validity "
                        f"({validity_years:.0f} years) in scheme {scheme}"
                    ),
                    "detail": (
                        f"Subject: {label}. "
                        f"The certificate is valid for approximately "
                        f"{validity_years:.0f} years "
                        f"({not_before_str} to {not_after_str}). "
                        "While common for Android (Google Play requires validity "
                        "past Oct 2033), extremely long periods are worth noting."
                    ),
                })

        # -------------------------------------------------------------------
        # Summary counters
        # -------------------------------------------------------------------
        severity_order = ("critical", "high", "medium", "low", "info")
        summary: dict[str, int] = {s: 0 for s in severity_order}
        for f in findings:
            sev = f.get("severity", "info")
            summary[sev] = summary.get(sev, 0) + 1
        summary["total"] = len(findings)

        return {
            "status": "ok",
            "data": {
                "findings": findings,
                "summary": summary,
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Certificate security check failed: {exc}",
            "suggestion": "Ensure the APK was loaded successfully.",
        }
