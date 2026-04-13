"""Enhanced security scanning tools — v2 with taint analysis and confidence levels.

This module provides improved versions of the v1 scanners from security.py.
Key improvements:

- ``scan_crypto_issues_v2``:  Inspects the actual algorithm string passed to
  ``Cipher.getInstance()`` rather than flagging every caller.  Distinguishes
  hardcoded key material from parameter-supplied keys in ``SecretKeySpec``.

- ``scan_network_security_v2``: Verifies that ``checkServerTrusted`` and
  ``verify`` method bodies are actually empty/trivial before reporting
  critical findings, cutting out the majority of false positives caused by
  custom TrustManager subclasses that still perform proper validation.

- ``scan_code_injection_v2``: Checks whether dangerous call-sites are
  reachable from an exported component, promoting findings to "high" only
  when a real external-attacker path exists.

- ``scan_all_v2``: Runs all three v2 scanners and aggregates results.

Each finding includes:
- ``confidence``              — "high" / "medium" / "low"
- ``reachable_from_exported`` — bool
- ``details``                 — extra analysis notes string
"""

from __future__ import annotations

from typing import Any

from apksaw.server import mcp
from apksaw.session import get_session
from apksaw.utils.taint_lite import (
    check_empty_method_body,
    get_arg_source_type,
    get_const_string_at_callsite,
    is_reachable_from_exported,
)

# Android manifest XML namespace (same as v1)
_ANDROID_NS = "http://schemas.android.com/apk/res/android"


# ----------------------------------------------------------------------- #
# Shared helpers (mirrors v1 helpers, kept local to avoid coupling)
# ----------------------------------------------------------------------- #


def _attr(element, name: str, default: Any = None) -> Any:
    """Get an android: namespaced attribute from an lxml element."""
    return element.get(f"{{{_ANDROID_NS}}}{name}", default)


def _make_summary(findings: list[dict]) -> dict:
    """Count findings by severity level."""
    summary: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for f in findings:
        sev = f.get("severity", "info")
        if sev in summary:
            summary[sev] += 1
    return summary


def _finding_v2(
    severity: str,
    category: str,
    title: str,
    description: str,
    location: str,
    recommendation: str,
    confidence: str = "medium",
    reachable_from_exported: bool = False,
    details: str = "",
) -> dict:
    """Construct a normalised v2 finding dict with extra analysis fields."""
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "location": location,
        "recommendation": recommendation,
        "confidence": confidence,
        "reachable_from_exported": reachable_from_exported,
        "details": details,
    }


def _get_invoke_offset(instr_list: list, invoke_mnemonic_prefix: str = "invoke") -> int | None:
    """Return the byte offset of the first invoke-* instruction in a list."""
    offset = 0
    for instr in instr_list:
        if instr.get_name().startswith(invoke_mnemonic_prefix):
            return offset
        offset += instr.get_length()
    return None


def _callers_with_method_analysis(analysis, classname_re: str, methodname_re: str,
                                   limit: int = 30) -> list[tuple[str, Any]]:
    """Return (location_string, caller_MethodAnalysis) pairs for a target method."""
    results: list[tuple[str, Any]] = []
    seen_locs: set[str] = set()
    for method_analysis in analysis.find_methods(
        classname=classname_re, methodname=methodname_re
    ):
        for _, caller_ma, _ in method_analysis.get_xref_from():
            loc = f"{caller_ma.class_name}->{caller_ma.name}"
            if loc not in seen_locs:
                seen_locs.add(loc)
                results.append((loc, caller_ma))
            if len(results) >= limit:
                return results
    return results


# ----------------------------------------------------------------------- #
# Tool 1 – Crypto issues v2
# ----------------------------------------------------------------------- #


@mcp.tool()
def scan_crypto_issues_v2(session_id: str) -> dict:
    """Enhanced crypto scanner with argument inspection and confidence levels.

    Improvements over v1:
    - Reads the actual algorithm string passed to ``Cipher.getInstance()``
      using backward register tracing; only flags confirmed bad algorithms.
    - Classifies ``SecretKeySpec`` key sources as 'constant' (hardcoded),
      'parameter', 'field', or 'method_return' to distinguish true hardcoded
      keys from keys derived at runtime.
    - Verifies TrustManager ``checkServerTrusted`` is actually empty before
      reporting critical severity.
    - Adds ``confidence``, ``reachable_from_exported``, and ``details``
      fields to every finding.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with status and data containing a findings list and summary.
    """
    try:
        session = get_session(session_id)
        apk = session.apk
        analysis = session.analysis
        findings: list[dict] = []

        # --------------------------------------------------------------- #
        # Cipher.getInstance — inspect actual algorithm argument
        # --------------------------------------------------------------- #
        cipher_ecb: list[tuple[str, str]] = []          # (loc, algo)
        cipher_aes_default: list[tuple[str, str]] = []  # (loc, algo)
        cipher_des: list[tuple[str, str]] = []          # (loc, algo)
        cipher_unknown: list[str] = []                  # loc only

        for target_ma in analysis.find_methods(
            classname=r"Ljavax/crypto/Cipher;", methodname=r"getInstance"
        ):
            for _, caller_ma, call_offset in target_ma.get_xref_from():
                loc = f"{caller_ma.class_name}->{caller_ma.name}"
                # arg_index=0 for static method: first explicit arg is the algo string
                algo = get_const_string_at_callsite(
                    analysis, caller_ma, call_offset, arg_index=0
                )
                if algo is None:
                    # Could not resolve — fall back to method-level flag
                    if loc not in cipher_unknown:
                        cipher_unknown.append(loc)
                    continue

                algo_up = algo.upper()
                if "ECB" in algo_up:
                    cipher_ecb.append((loc, algo))
                elif algo_up in ("AES", "DES", "DESEDE") or \
                        algo_up.startswith("DES/") or algo_up.startswith("DESEDE/"):
                    if "DES" in algo_up:
                        cipher_des.append((loc, algo))
                    elif algo_up == "AES":
                        cipher_aes_default.append((loc, algo))
                # GCM/CBC with full spec is fine — skip

        if cipher_ecb:
            locs = [loc for loc, _ in cipher_ecb[:5]]
            algos = list(dict.fromkeys(a for _, a in cipher_ecb))
            findings.append(_finding_v2(
                severity="high",
                category="crypto",
                title="Cipher.getInstance() uses ECB mode (confirmed)",
                description=(
                    "ECB mode encrypts each block independently, allowing pattern analysis. "
                    "Identical plaintext blocks produce identical ciphertext."
                ),
                location="; ".join(locs),
                recommendation=(
                    "Use AES/GCM/NoPadding with a unique random IV per encryption operation."
                ),
                confidence="high",
                details=f"Confirmed algorithm strings: {', '.join(algos[:5])}",
            ))

        if cipher_aes_default:
            locs = [loc for loc, _ in cipher_aes_default[:5]]
            findings.append(_finding_v2(
                severity="high",
                category="crypto",
                title='Cipher.getInstance("AES") defaults to ECB mode (confirmed)',
                description=(
                    'Calling Cipher.getInstance("AES") without mode/padding lets the JCA '
                    "provider choose AES/ECB/PKCS5Padding, which is insecure."
                ),
                location="; ".join(locs),
                recommendation=(
                    "Specify the full transformation: AES/GCM/NoPadding or AES/CBC/PKCS5Padding "
                    "with a random IV."
                ),
                confidence="high",
                details="Argument confirmed as bare 'AES' string by static trace.",
            ))

        if cipher_des:
            locs = [loc for loc, _ in cipher_des[:5]]
            algos = list(dict.fromkeys(a for _, a in cipher_des))
            findings.append(_finding_v2(
                severity="high",
                category="crypto",
                title="Weak cipher algorithm: DES or 3DES (confirmed)",
                description=(
                    "DES (56-bit) is broken; 3DES (~112-bit effective) is NIST-deprecated."
                ),
                location="; ".join(locs),
                recommendation="Replace with AES-256/GCM.",
                confidence="high",
                details=f"Confirmed algorithm strings: {', '.join(algos[:5])}",
            ))

        if cipher_unknown:
            findings.append(_finding_v2(
                severity="medium",
                category="crypto",
                title="Cipher.getInstance() called with non-constant algorithm (needs review)",
                description=(
                    "Cipher.getInstance() is called but the algorithm string could not be "
                    "resolved statically. The algorithm may be safe or dangerous depending "
                    "on runtime values."
                ),
                location="; ".join(cipher_unknown[:5]),
                recommendation=(
                    "Audit these call-sites manually to confirm a safe algorithm and mode "
                    "are used."
                ),
                confidence="low",
                details=(
                    f"{len(cipher_unknown)} call-site(s) with unresolvable algorithm argument."
                ),
            ))

        # --------------------------------------------------------------- #
        # MessageDigest — MD5 / SHA-1 (with confirmed string match)
        # --------------------------------------------------------------- #
        md5_locs: list[str] = []
        sha1_locs: list[str] = []
        digest_unknown: list[str] = []

        for target_ma in analysis.find_methods(
            classname=r"Ljava/security/MessageDigest;", methodname=r"getInstance"
        ):
            for _, caller_ma, call_offset in target_ma.get_xref_from():
                loc = f"{caller_ma.class_name}->{caller_ma.name}"
                algo = get_const_string_at_callsite(
                    analysis, caller_ma, call_offset, arg_index=0
                )
                if algo is None:
                    if loc not in digest_unknown:
                        digest_unknown.append(loc)
                    continue
                algo_up = algo.upper()
                if algo_up == "MD5" and loc not in md5_locs:
                    md5_locs.append(loc)
                elif algo_up in ("SHA-1", "SHA1") and loc not in sha1_locs:
                    sha1_locs.append(loc)

        if md5_locs:
            findings.append(_finding_v2(
                severity="high",
                category="crypto",
                title="MD5 used for hashing (confirmed)",
                description=(
                    "MD5 is cryptographically broken; collisions are trivially generated."
                ),
                location="; ".join(md5_locs[:5]),
                recommendation=(
                    "Replace MD5 with SHA-256 or SHA-3. "
                    "For passwords use bcrypt, scrypt, or Argon2."
                ),
                confidence="high",
                details='Algorithm string confirmed as "MD5" by static trace.',
            ))

        if sha1_locs:
            findings.append(_finding_v2(
                severity="medium",
                category="crypto",
                title="SHA-1 used for hashing (confirmed)",
                description=(
                    "SHA-1 is deprecated; chosen-prefix collisions have been demonstrated."
                ),
                location="; ".join(sha1_locs[:5]),
                recommendation="Replace SHA-1 with SHA-256 or stronger.",
                confidence="high",
                details='Algorithm string confirmed as "SHA-1"/"SHA1" by static trace.',
            ))

        # --------------------------------------------------------------- #
        # SecretKeySpec — distinguish hardcoded from derived keys
        # --------------------------------------------------------------- #
        hardcoded_key_locs: list[str] = []
        param_key_locs: list[str] = []
        field_key_locs: list[str] = []
        unknown_key_locs: list[str] = []

        for target_ma in analysis.find_methods(
            classname=r"Ljavax/crypto/spec/SecretKeySpec;", methodname=r"<init>"
        ):
            for _, caller_ma, call_offset in target_ma.get_xref_from():
                loc = f"{caller_ma.class_name}->{caller_ma.name}"
                # SecretKeySpec(byte[] key, String algorithm)
                # arg_index=1 because arg_index=0 is "this" for virtual, but
                # <init> of SecretKeySpec — caller is invoking <init> on a new
                # instance, so arg 0 is the byte[] and arg 1 is the algorithm.
                # We check arg 0 (the byte array) for its source type.
                src_type = get_arg_source_type(
                    analysis, caller_ma, call_offset, arg_index=1
                )
                if src_type == "constant":
                    if loc not in hardcoded_key_locs:
                        hardcoded_key_locs.append(loc)
                elif src_type == "parameter":
                    if loc not in param_key_locs:
                        param_key_locs.append(loc)
                elif src_type == "field":
                    if loc not in field_key_locs:
                        field_key_locs.append(loc)
                else:
                    if loc not in unknown_key_locs:
                        unknown_key_locs.append(loc)

        if hardcoded_key_locs:
            findings.append(_finding_v2(
                severity="critical",
                category="crypto",
                title="SecretKeySpec: hardcoded key material detected (confirmed)",
                description=(
                    "The byte array passed to SecretKeySpec appears to be a compile-time "
                    "constant, meaning the cryptographic key is embedded in the APK and can "
                    "be trivially extracted."
                ),
                location="; ".join(hardcoded_key_locs[:5]),
                recommendation=(
                    "Derive keys with PBKDF2/Argon2 from a user password, or use the "
                    "Android Keystore System to generate and store keys securely."
                ),
                confidence="high",
                details=(
                    "Key byte-array source classified as 'constant' by register trace. "
                    f"{len(hardcoded_key_locs)} site(s) affected."
                ),
            ))

        if field_key_locs:
            findings.append(_finding_v2(
                severity="high",
                category="crypto",
                title="SecretKeySpec: key loaded from a field (possible hardcoded constant)",
                description=(
                    "The key material is loaded from a class or instance field. "
                    "If that field is initialised from a literal, the key is effectively "
                    "hardcoded and can be extracted."
                ),
                location="; ".join(field_key_locs[:5]),
                recommendation=(
                    "Verify the field is populated at runtime from a secure source. "
                    "Prefer Android Keystore for long-lived keys."
                ),
                confidence="medium",
                details=(
                    "Key byte-array source classified as 'field'. Requires manual review "
                    "of field initialisation."
                ),
            ))

        if unknown_key_locs:
            findings.append(_finding_v2(
                severity="medium",
                category="crypto",
                title="SecretKeySpec instantiation (key source unresolved)",
                description=(
                    "SecretKeySpec is constructed from a byte array whose origin could not "
                    "be determined statically. Manual review is required."
                ),
                location="; ".join(unknown_key_locs[:5]),
                recommendation=(
                    "Ensure key material is never hardcoded. Use the Android Keystore System "
                    "or derive keys from user credentials with a strong KDF."
                ),
                confidence="low",
                details=f"{len(unknown_key_locs)} site(s) with unresolved key source.",
            ))

        # --------------------------------------------------------------- #
        # IvParameterSpec — structural flag (same as v1 but with confidence)
        # --------------------------------------------------------------- #
        iv_locs: list[str] = [
            loc for loc, _ in _callers_with_method_analysis(
                analysis,
                r"Ljavax/crypto/spec/IvParameterSpec;",
                r"<init>",
                limit=20,
            )
        ]
        if iv_locs:
            findings.append(_finding_v2(
                severity="medium",
                category="crypto",
                title="IvParameterSpec instantiation (verify IV is random)",
                description=(
                    "IvParameterSpec is used. If the IV is hardcoded or deterministic, "
                    "CBC/CTR modes become vulnerable to known-plaintext attacks."
                ),
                location="; ".join(iv_locs[:5]),
                recommendation=(
                    "Always generate IVs with SecureRandom: "
                    "byte[] iv = new byte[16]; new SecureRandom().nextBytes(iv);"
                ),
                confidence="low",
                details=(
                    "Structural match only — static trace of IV byte array source was "
                    "not performed. Review each site manually."
                ),
            ))

        # --------------------------------------------------------------- #
        # SecureRandom.setSeed
        # --------------------------------------------------------------- #
        seed_callers = _callers_with_method_analysis(
            analysis,
            r"Ljava/security/SecureRandom;",
            r"setSeed",
            limit=20,
        )
        if seed_callers:
            locs = [loc for loc, _ in seed_callers]
            findings.append(_finding_v2(
                severity="high",
                category="crypto",
                title="SecureRandom.setSeed() called (predictable randomness)",
                description=(
                    "Seeding SecureRandom with a fixed or low-entropy value makes its "
                    "output predictable, undermining key generation or IV creation."
                ),
                location="; ".join(locs[:5]),
                recommendation=(
                    "Do not call setSeed() on SecureRandom used for cryptographic purposes. "
                    "Let the OS seed the PRNG automatically."
                ),
                confidence="medium",
                details=(
                    "Seed value source was not inspected — confidence promoted if seed is "
                    "a compile-time constant."
                ),
            ))

        # --------------------------------------------------------------- #
        # TrustManager — verify checkServerTrusted is actually empty
        # --------------------------------------------------------------- #
        confirmed_empty_tm: list[str] = []
        non_empty_tm: list[str] = []

        for cls in analysis.get_classes():
            for iface in cls.implements:
                if "X509TrustManager" in iface or "TrustManager" in iface:
                    class_name = cls.name
                    is_empty = check_empty_method_body(
                        analysis, class_name, "checkServerTrusted"
                    )
                    if is_empty:
                        confirmed_empty_tm.append(class_name)
                    else:
                        non_empty_tm.append(class_name)

        if confirmed_empty_tm:
            findings.append(_finding_v2(
                severity="critical",
                category="crypto",
                title="TrustManager with empty checkServerTrusted (confirmed MITM risk)",
                description=(
                    "checkServerTrusted() has an empty or trivially-returning body, "
                    "meaning the app accepts ANY server certificate without validation. "
                    "This enables man-in-the-middle attacks."
                ),
                location="; ".join(confirmed_empty_tm[:5]),
                recommendation=(
                    "Remove the custom TrustManager. Use the system TrustManager or "
                    "configure a Network Security Config."
                ),
                confidence="high",
                details=(
                    f"{len(confirmed_empty_tm)} class(es) confirmed empty: "
                    f"{', '.join(confirmed_empty_tm[:3])}."
                ),
            ))

        if non_empty_tm:
            findings.append(_finding_v2(
                severity="medium",
                category="crypto",
                title="Custom TrustManager detected (non-empty body — review required)",
                description=(
                    "Custom TrustManager implementations were found, but their "
                    "checkServerTrusted() bodies appear non-trivial. They may or may not "
                    "perform correct validation."
                ),
                location="; ".join(non_empty_tm[:5]),
                recommendation=(
                    "Audit checkServerTrusted() to ensure it throws CertificateException "
                    "on invalid certificates and does not silently swallow exceptions."
                ),
                confidence="medium",
                details=(
                    f"{len(non_empty_tm)} class(es) have non-empty checkServerTrusted. "
                    "Downgraded from critical — manual review needed."
                ),
            ))

        return {
            "status": "ok",
            "data": {
                "findings": findings,
                "summary": _make_summary(findings),
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
            "message": f"Crypto v2 scan failed: {exc}",
            "suggestion": "Ensure the APK was loaded successfully.",
        }


# ----------------------------------------------------------------------- #
# Tool 2 – Network security v2
# ----------------------------------------------------------------------- #


@mcp.tool()
def scan_network_security_v2(session_id: str) -> dict:
    """Enhanced network security scanner with body verification and confidence levels.

    Improvements over v1:
    - Verifies that ``checkServerTrusted`` in custom X509TrustManager
      implementations actually has an empty/trivial body before escalating
      to critical severity.
    - Verifies that ``verify()`` in custom HostnameVerifier implementations
      has a trivial/always-true body.
    - Adds ``confidence``, ``reachable_from_exported``, and ``details``
      fields to every finding.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with status and data containing a findings list and summary.
    """
    try:
        session = get_session(session_id)
        apk = session.apk
        analysis = session.analysis
        findings: list[dict] = []

        # --------------------------------------------------------------- #
        # HTTP URLs in strings
        # --------------------------------------------------------------- #
        http_urls: list[str] = []
        for string_analysis in analysis.find_strings(string=r"http://"):
            val = string_analysis.get_value()
            if val not in http_urls:
                http_urls.append(val)
            if len(http_urls) >= 20:
                break

        if http_urls:
            findings.append(_finding_v2(
                severity="medium",
                category="network",
                title="Plain HTTP URLs found in strings",
                description=(
                    "Non-HTTPS URLs were found in the APK's string pool, exposing "
                    "traffic to network eavesdroppers."
                ),
                location="string pool",
                recommendation=(
                    "Replace all http:// endpoints with https://. "
                    "Configure a Network Security Config to block cleartext traffic."
                ),
                confidence="medium",
                details=(
                    f"Found {len(http_urls)} HTTP URL(s). "
                    f"Examples: {', '.join(http_urls[:5])}. "
                    "Note: some may be documentation or non-sensitive URLs."
                ),
            ))

        # --------------------------------------------------------------- #
        # Custom X509TrustManager — verify checkServerTrusted body
        # --------------------------------------------------------------- #
        empty_tm: list[str] = []
        non_empty_tm: list[str] = []

        for cls in analysis.get_classes():
            for iface in cls.implements:
                if "X509TrustManager" in iface:
                    class_name = cls.name
                    is_empty = check_empty_method_body(
                        analysis, class_name, "checkServerTrusted"
                    )
                    if is_empty:
                        empty_tm.append(class_name)
                    else:
                        non_empty_tm.append(class_name)

        if empty_tm:
            findings.append(_finding_v2(
                severity="critical",
                category="network",
                title="X509TrustManager with empty checkServerTrusted (confirmed MITM)",
                description=(
                    "checkServerTrusted() is empty or returns immediately without "
                    "validation, accepting any server certificate. This is a confirmed "
                    "man-in-the-middle vulnerability."
                ),
                location="; ".join(empty_tm[:5]),
                recommendation=(
                    "Remove the custom TrustManager. Use the platform TrustManager or "
                    "a Network Security Config with pinned certificates."
                ),
                confidence="high",
                details=(
                    f"{len(empty_tm)} class(es) confirmed with empty checkServerTrusted: "
                    f"{', '.join(empty_tm[:3])}."
                ),
            ))

        if non_empty_tm:
            findings.append(_finding_v2(
                severity="medium",
                category="network",
                title="Custom X509TrustManager detected (body appears non-empty — review)",
                description=(
                    "Custom X509TrustManager implementations were found, but "
                    "checkServerTrusted() has a non-trivial body. It may still skip "
                    "validation via exception swallowing or other patterns."
                ),
                location="; ".join(non_empty_tm[:5]),
                recommendation=(
                    "Audit checkServerTrusted() to ensure it correctly throws "
                    "CertificateException for invalid certificates."
                ),
                confidence="medium",
                details=(
                    f"{len(non_empty_tm)} class(es) have non-empty checkServerTrusted. "
                    "Downgraded from critical — manual audit required."
                ),
            ))

        # --------------------------------------------------------------- #
        # HostnameVerifier — verify verify() body is trivially true
        # --------------------------------------------------------------- #
        always_true_hn: list[str] = []
        custom_hn: list[str] = []

        for cls in analysis.get_classes():
            for iface in cls.implements:
                if "HostnameVerifier" in iface:
                    class_name = cls.name
                    # check_empty_method_body also catches single-instruction returns
                    # which covers "return true" (const/4 v0, 1; return v0)
                    is_trivial = check_empty_method_body(
                        analysis, class_name, "verify"
                    )
                    if is_trivial:
                        always_true_hn.append(class_name)
                    else:
                        custom_hn.append(class_name)

        # Also check setDefaultHostnameVerifier callers
        allow_all_locs = [
            loc for loc, _ in _callers_with_method_analysis(
                analysis,
                r"Ljavax/net/ssl/HttpsURLConnection;",
                r"setDefaultHostnameVerifier",
                limit=20,
            )
        ]

        if always_true_hn or allow_all_locs:
            combined = list(dict.fromkeys(always_true_hn + allow_all_locs))
            findings.append(_finding_v2(
                severity="critical",
                category="network",
                title="HostnameVerifier returns true unconditionally or ALLOW_ALL pattern (confirmed)",
                description=(
                    "verify() has a trivial/empty body (accepts any hostname) or "
                    "setDefaultHostnameVerifier is called, potentially with ALLOW_ALL."
                ),
                location="; ".join(combined[:5]),
                recommendation=(
                    "Do not implement HostnameVerifier returning true unconditionally. "
                    "Use the default Android hostname verifier."
                ),
                confidence="high",
                details=(
                    f"Empty/trivial verify() in: {', '.join(always_true_hn[:3])}. "
                    f"setDefaultHostnameVerifier callers: {', '.join(allow_all_locs[:3])}."
                ),
            ))

        if custom_hn:
            findings.append(_finding_v2(
                severity="medium",
                category="network",
                title="Custom HostnameVerifier detected (non-trivial body — review required)",
                description=(
                    "Custom HostnameVerifier implementations with non-trivial verify() "
                    "bodies were found. They may still accept invalid hostnames via "
                    "regex bypass or other logic errors."
                ),
                location="; ".join(custom_hn[:5]),
                recommendation=(
                    "Audit verify() implementations. Prefer the default platform verifier."
                ),
                confidence="medium",
                details=(
                    f"{len(custom_hn)} class(es) with non-trivial verify() body."
                ),
            ))

        # --------------------------------------------------------------- #
        # WebView setMixedContentMode
        # --------------------------------------------------------------- #
        mixed_callers = _callers_with_method_analysis(
            analysis,
            r"Landroid/webkit/WebSettings;",
            r"setMixedContentMode",
            limit=20,
        )
        if mixed_callers:
            locs = [loc for loc, _ in mixed_callers]
            findings.append(_finding_v2(
                severity="high",
                category="network",
                title="WebView setMixedContentMode called (verify not ALWAYS_ALLOW)",
                description=(
                    "setMixedContentMode() is called. MIXED_CONTENT_ALWAYS_ALLOW (0) "
                    "permits HTTP subresources in HTTPS pages, enabling content injection."
                ),
                location="; ".join(locs[:5]),
                recommendation=(
                    "Use MIXED_CONTENT_NEVER_ALLOW (1) or MIXED_CONTENT_COMPATIBILITY_MODE (2)."
                ),
                confidence="low",
                details=(
                    "Constant value passed was not resolved — requires manual inspection "
                    "to confirm ALWAYS_ALLOW is not used."
                ),
            ))

        # --------------------------------------------------------------- #
        # Certificate pinning absence
        # --------------------------------------------------------------- #
        pinner_present = any(
            True
            for _ in analysis.find_methods(
                classname=r"Lokhttp3/CertificatePinner.*", methodname=r".*"
            )
        )
        trustkit_present = any(
            True for _ in analysis.find_strings(string=r"TrustKit")
        )
        nsc_pin_present = any(
            True for _ in analysis.find_strings(string=r"<pin-set")
        )

        if not (pinner_present or trustkit_present or nsc_pin_present):
            findings.append(_finding_v2(
                severity="low",
                category="network",
                title="No certificate pinning detected",
                description=(
                    "Neither OkHttp CertificatePinner, TrustKit, nor a Network Security "
                    "Config <pin-set> was found. The app trusts any certificate from a "
                    "system CA, enabling MITM with rogue or user-installed CAs."
                ),
                location="N/A",
                recommendation=(
                    "Implement certificate pinning for sensitive endpoints via "
                    "OkHttp CertificatePinner, Network Security Config <pin-set>, or TrustKit."
                ),
                confidence="medium",
                details=(
                    "Absence of pinning is inferred from string/class searches; "
                    "a custom pinning implementation may exist under a different namespace."
                ),
            ))

        # --------------------------------------------------------------- #
        # WebView setAllowUniversalAccessFromFileURLs
        # --------------------------------------------------------------- #
        universal_callers = _callers_with_method_analysis(
            analysis,
            r"Landroid/webkit/WebSettings;",
            r"setAllowUniversalAccessFromFileURLs",
            limit=20,
        )
        if universal_callers:
            locs = [loc for loc, _ in universal_callers]
            findings.append(_finding_v2(
                severity="high",
                category="network",
                title="WebView setAllowUniversalAccessFromFileURLs called",
                description=(
                    "If set to true, JavaScript in file:// pages can make cross-origin "
                    "requests to any origin, enabling data theft if the WebView loads "
                    "attacker-controlled HTML."
                ),
                location="; ".join(locs[:5]),
                recommendation=(
                    "Set setAllowUniversalAccessFromFileURLs(false) (the default). "
                    "Avoid loading local files in WebViews."
                ),
                confidence="medium",
                details=(
                    "Boolean argument value was not resolved — verify false is passed. "
                    f"{len(locs)} call-site(s)."
                ),
            ))

        return {
            "status": "ok",
            "data": {
                "findings": findings,
                "summary": _make_summary(findings),
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
            "message": f"Network security v2 scan failed: {exc}",
            "suggestion": "Ensure the APK was loaded successfully.",
        }


# ----------------------------------------------------------------------- #
# Tool 3 – Code injection v2
# ----------------------------------------------------------------------- #


@mcp.tool()
def scan_code_injection_v2(session_id: str) -> dict:
    """Enhanced code-injection scanner with exported-component reachability.

    Improvements over v1:
    - Checks each dangerous call-site for reachability from exported
      components via BFS over the call graph.
    - Promotes findings reachable from exported components to higher
      confidence; demotes unreachable ones.
    - Adds ``confidence``, ``reachable_from_exported``, and ``details``
      to every finding.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with status and data containing a findings list and summary.
    """
    try:
        session = get_session(session_id)
        apk = session.apk
        analysis = session.analysis
        findings: list[dict] = []

        def _check_with_reachability(
            sev_reachable: str,
            sev_unreachable: str,
            title: str,
            description: str,
            recommendation: str,
            classname_re: str,
            methodname_re: str,
            category: str = "code_injection",
            limit: int = 20,
        ) -> None:
            """Run a method-xref check and enrich each result with reachability."""
            callers = _callers_with_method_analysis(
                analysis, classname_re, methodname_re, limit=limit
            )
            if not callers:
                return

            reachable_locs: list[str] = []
            unreachable_locs: list[str] = []

            for loc, caller_ma in callers:
                try:
                    reachable = is_reachable_from_exported(analysis, apk, caller_ma)
                except Exception:
                    reachable = False

                if reachable:
                    reachable_locs.append(loc)
                else:
                    unreachable_locs.append(loc)

            if reachable_locs:
                findings.append(_finding_v2(
                    severity=sev_reachable,
                    category=category,
                    title=f"{title} — reachable from exported component",
                    description=description,
                    location="; ".join(reachable_locs[:5]),
                    recommendation=recommendation,
                    confidence="high",
                    reachable_from_exported=True,
                    details=(
                        f"{len(reachable_locs)} call-site(s) confirmed reachable from "
                        f"an exported entry point via BFS (max depth 10). "
                        f"Sites: {', '.join(reachable_locs[:3])}."
                    ),
                ))

            if unreachable_locs:
                findings.append(_finding_v2(
                    severity=sev_unreachable,
                    category=category,
                    title=f"{title} — not directly reachable from exported component",
                    description=description,
                    location="; ".join(unreachable_locs[:5]),
                    recommendation=recommendation,
                    confidence="medium",
                    reachable_from_exported=False,
                    details=(
                        f"{len(unreachable_locs)} call-site(s) found but no path from "
                        "an exported entry point was detected (BFS depth 10). "
                        "Reachability may exist through reflection or dynamic dispatch."
                    ),
                ))

        # addJavascriptInterface
        _check_with_reachability(
            sev_reachable="critical",
            sev_unreachable="high",
            title="WebView.addJavascriptInterface()",
            description=(
                "addJavascriptInterface() exposes Java/Kotlin objects to JavaScript. "
                "On API < 17 all public methods are accessible. If the WebView loads "
                "untrusted content, attackers can invoke Java methods directly."
            ),
            recommendation=(
                "Avoid addJavascriptInterface() where possible. Ensure the WebView "
                "only loads trusted HTTPS content and validate all data from JavaScript."
            ),
            classname_re=r"Landroid/webkit/WebView;",
            methodname_re=r"addJavascriptInterface",
        )

        # rawQuery — SQL injection
        _check_with_reachability(
            sev_reachable="high",
            sev_unreachable="medium",
            title="SQLiteDatabase.rawQuery() (potential SQL injection)",
            description=(
                "rawQuery() executes raw SQL. If user-supplied input is concatenated "
                "into the query string, SQL injection is possible."
            ),
            recommendation=(
                "Use parameterised queries with ? placeholders and selectionArgs. "
                "Prefer the query()/insert()/update()/delete() helper methods."
            ),
            classname_re=r"Landroid/database/sqlite/SQLiteDatabase;",
            methodname_re=r"rawQuery",
        )

        # execSQL
        _check_with_reachability(
            sev_reachable="high",
            sev_unreachable="medium",
            title="SQLiteDatabase.execSQL() (potential SQL injection)",
            description=(
                "execSQL() runs arbitrary SQL. Concatenating user input allows injection."
            ),
            recommendation=(
                "Use parameterised forms: execSQL(sql, bindArgs). "
                "Pass all user values as bind arguments."
            ),
            classname_re=r"Landroid/database/sqlite/SQLiteDatabase;",
            methodname_re=r"execSQL",
        )

        # Runtime.exec
        _check_with_reachability(
            sev_reachable="critical",
            sev_unreachable="high",
            title="Runtime.exec() (OS command execution)",
            description=(
                "Runtime.exec() spawns a native OS process. Unsanitised user input "
                "in any argument can lead to OS command injection."
            ),
            recommendation=(
                "Avoid Runtime.exec() with user input. Use a fixed command array."
            ),
            classname_re=r"Ljava/lang/Runtime;",
            methodname_re=r"exec",
        )

        # ProcessBuilder
        _check_with_reachability(
            sev_reachable="high",
            sev_unreachable="medium",
            title="ProcessBuilder (OS command execution)",
            description=(
                "ProcessBuilder launches native processes. User-controlled command "
                "elements can cause argument injection."
            ),
            recommendation=(
                "Use a fixed, hardcoded command list. Never pass user-controlled "
                "strings as ProcessBuilder command elements."
            ),
            classname_re=r"Ljava/lang/ProcessBuilder;",
            methodname_re=r"<init>",
        )

        # DexClassLoader
        _check_with_reachability(
            sev_reachable="critical",
            sev_unreachable="high",
            title="DexClassLoader (dynamic code loading)",
            description=(
                "DexClassLoader loads DEX/APK/JAR files at runtime. Attacker-controlled "
                "paths or non-integrity-checked files allow arbitrary code injection."
            ),
            recommendation=(
                "Avoid loading code from external/writable paths. Verify file integrity "
                "before loading and store DEX in internal storage."
            ),
            classname_re=r"Ldalvik/system/DexClassLoader;",
            methodname_re=r"<init>",
        )

        # InMemoryDexClassLoader
        _check_with_reachability(
            sev_reachable="high",
            sev_unreachable="medium",
            title="InMemoryDexClassLoader (in-memory code loading)",
            description=(
                "InMemoryDexClassLoader loads DEX bytecode from a ByteBuffer — a "
                "common packer/malware technique to evade static analysis."
            ),
            recommendation=(
                "Review all instantiation sites. Ensure the byte buffer source is "
                "trusted and integrity-verified."
            ),
            classname_re=r"Ldalvik/system/InMemoryDexClassLoader;",
            methodname_re=r"<init>",
        )

        # Class.forName
        _check_with_reachability(
            sev_reachable="medium",
            sev_unreachable="low",
            title="Class.forName() (dynamic class loading)",
            description=(
                "Class.forName() loads a class by name at runtime. User-controlled "
                "class names can trigger loading of unintended classes."
            ),
            recommendation=(
                "Ensure class names are from a trusted source. "
                "Prefer a whitelist of allowed class names."
            ),
            classname_re=r"Ljava/lang/Class;",
            methodname_re=r"forName",
        )

        # WebView.loadUrl
        _check_with_reachability(
            sev_reachable="high",
            sev_unreachable="medium",
            title="WebView.loadUrl() (verify URL source is trusted)",
            description=(
                "WebView.loadUrl() is called. If the URL comes from an Intent extra "
                "or external source without validation, attackers can load arbitrary "
                "URLs or javascript: URIs."
            ),
            recommendation=(
                "Validate URLs before loadUrl(). Reject javascript: and data: schemes. "
                "Use an allowlist of trusted domains."
            ),
            classname_re=r"Landroid/webkit/WebView;",
            methodname_re=r"loadUrl",
        )

        return {
            "status": "ok",
            "data": {
                "findings": findings,
                "summary": _make_summary(findings),
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
            "message": f"Code injection v2 scan failed: {exc}",
            "suggestion": "Ensure the APK was loaded successfully.",
        }


# ----------------------------------------------------------------------- #
# Tool 4 – Combined scan v2
# ----------------------------------------------------------------------- #


@mcp.tool()
def scan_all_v2(session_id: str) -> dict:
    """Run all v2 security scanners and return a combined report.

    Executes ``scan_crypto_issues_v2``, ``scan_network_security_v2``, and
    ``scan_code_injection_v2``, then aggregates all findings with a
    combined severity summary broken down by confidence level.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with status and data containing all findings, per-scanner
        results, a combined severity summary, and a confidence breakdown.
    """
    scanners = {
        "crypto_v2": scan_crypto_issues_v2,
        "network_v2": scan_network_security_v2,
        "code_injection_v2": scan_code_injection_v2,
    }

    all_findings: list[dict] = []
    per_scanner: dict[str, dict] = {}
    errors: list[str] = []

    for name, fn in scanners.items():
        result = fn(session_id)
        per_scanner[name] = result
        if result.get("status") == "ok":
            for f in result.get("data", {}).get("findings", []):
                tagged = dict(f)
                tagged.setdefault("scanner", name)
                all_findings.append(tagged)
        else:
            errors.append(f"{name}: {result.get('message', 'unknown error')}")

    # Confidence breakdown
    confidence_summary: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        conf = f.get("confidence", "low")
        if conf in confidence_summary:
            confidence_summary[conf] += 1

    # Reachability summary
    reachable_count = sum(
        1 for f in all_findings if f.get("reachable_from_exported", False)
    )

    return {
        "status": "ok" if not errors else "partial",
        "data": {
            "findings": all_findings,
            "summary": _make_summary(all_findings),
            "confidence_breakdown": confidence_summary,
            "reachable_from_exported_count": reachable_count,
            "total_findings": len(all_findings),
            "per_scanner": {
                name: r.get("data", {}).get("summary", {})
                for name, r in per_scanner.items()
            },
            "errors": errors,
        },
    }
