"""Automated security scanning tools for Android APK analysis."""

from typing import Any

from apksaw.server import mcp
from apksaw.session import get_session

# Android manifest XML namespace
_ANDROID_NS = "http://schemas.android.com/apk/res/android"


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


def _finding(
    severity: str,
    category: str,
    title: str,
    description: str,
    location: str,
    recommendation: str,
) -> dict:
    """Construct a normalised finding dict."""
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "location": location,
        "recommendation": recommendation,
    }


def _callers_of(analysis, classname_re: str, methodname_re: str, limit: int = 20) -> list[str]:
    """Return a deduplicated list of 'ClassName->methodName' caller locations."""
    locations: list[str] = []
    for method_analysis in analysis.find_methods(classname=classname_re, methodname=methodname_re):
        for _, caller, _ in method_analysis.get_xref_from():
            loc = f"{caller.class_name}->{caller.name}"
            if loc not in locations:
                locations.append(loc)
            if len(locations) >= limit:
                return locations
    return locations


# ---------------------------------------------------------------------------
# Tool 1 – Manifest security
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_manifest_security(session_id: str) -> dict:
    """Scan AndroidManifest.xml for security misconfigurations.

    Checks include: debuggable flag, backup allowed, cleartext traffic,
    missing network security config, exported components without permissions,
    implicit exports for low targetSdk, task-affinity / launch-mode risks,
    and dangerously low minSdkVersion.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with status and data containing a findings list and severity summary.
    """
    try:
        session = get_session(session_id)
        apk = session.apk
        manifest_elem = apk.get_android_manifest_xml()

        target_sdk_raw = apk.get_target_sdk_version()
        min_sdk_raw = apk.get_min_sdk_version()
        try:
            target_sdk = int(target_sdk_raw) if target_sdk_raw else 0
        except (ValueError, TypeError):
            target_sdk = 0
        try:
            min_sdk = int(min_sdk_raw) if min_sdk_raw else 0
        except (ValueError, TypeError):
            min_sdk = 0

        findings: list[dict] = []
        app_elem = manifest_elem.find("application")

        # ------------------------------------------------------------------ #
        # Application-level checks
        # ------------------------------------------------------------------ #
        if app_elem is not None:
            # android:debuggable
            debuggable = _attr(app_elem, "debuggable", "false")
            if debuggable.lower() in ("true", "1"):
                findings.append(_finding(
                    severity="critical",
                    category="manifest",
                    title="Application is debuggable",
                    description=(
                        "android:debuggable=\"true\" allows attackers with physical or ADB "
                        "access to attach a debugger, inspect memory, and extract secrets."
                    ),
                    location="AndroidManifest.xml <application>",
                    recommendation=(
                        "Set android:debuggable=\"false\" or omit the attribute. "
                        "Ensure release builds are never signed with debuggable=true."
                    ),
                ))

            # android:allowBackup
            allow_backup = _attr(app_elem, "allowBackup")
            if allow_backup is None or allow_backup.lower() in ("true", "1"):
                findings.append(_finding(
                    severity="medium",
                    category="manifest",
                    title="Application data backup enabled",
                    description=(
                        "android:allowBackup is true (or not set, which defaults to true). "
                        "This lets any user with USB debugging extract app data via "
                        "\"adb backup\" without root access."
                    ),
                    location="AndroidManifest.xml <application>",
                    recommendation=(
                        "Set android:allowBackup=\"false\" unless backup is intentionally "
                        "required. If backup is needed, configure android:fullBackupContent "
                        "rules to exclude sensitive files."
                    ),
                ))

            # android:usesCleartextTraffic
            cleartext = _attr(app_elem, "usesCleartextTraffic")
            if cleartext is not None and cleartext.lower() in ("true", "1"):
                findings.append(_finding(
                    severity="high",
                    category="manifest",
                    title="Cleartext (HTTP) traffic permitted",
                    description=(
                        "android:usesCleartextTraffic=\"true\" allows the application to "
                        "send unencrypted HTTP traffic, exposing data to network eavesdroppers."
                    ),
                    location="AndroidManifest.xml <application>",
                    recommendation=(
                        "Remove android:usesCleartextTraffic or set it to false. "
                        "Migrate all endpoints to HTTPS and configure a "
                        "Network Security Config file."
                    ),
                ))

            # Missing android:networkSecurityConfig
            nsc = _attr(app_elem, "networkSecurityConfig")
            if nsc is None:
                findings.append(_finding(
                    severity="low",
                    category="manifest",
                    title="No Network Security Config defined",
                    description=(
                        "android:networkSecurityConfig is not set. Without a Network Security "
                        "Config the app relies on platform defaults, which may allow cleartext "
                        "traffic on older API levels and provides no certificate-pinning."
                    ),
                    location="AndroidManifest.xml <application>",
                    recommendation=(
                        "Create a res/xml/network_security_config.xml and reference it with "
                        "android:networkSecurityConfig. Define domain-specific rules and "
                        "consider adding certificate pins for sensitive domains."
                    ),
                ))

            # ---------------------------------------------------------------- #
            # Component-level checks
            # ---------------------------------------------------------------- #
            component_tags = ("activity", "service", "receiver", "provider")

            for tag in component_tags:
                for elem in app_elem.findall(tag):
                    comp_name = _attr(elem, "name", "<unknown>")
                    location_str = f"AndroidManifest.xml <{tag}> {comp_name}"

                    exported_raw = _attr(elem, "exported")
                    has_intent_filters = bool(elem.findall("intent-filter"))

                    # Determine effective export status
                    if exported_raw is not None:
                        is_exported = exported_raw.lower() in ("true", "1")
                        explicit_export = True
                    else:
                        explicit_export = False
                        # Pre-API-31: having an intent-filter implicitly exports the component
                        is_exported = has_intent_filters and target_sdk < 31

                    # Exported without permission
                    if is_exported:
                        permission = _attr(elem, "permission")
                        read_perm = _attr(elem, "readPermission") if tag == "provider" else None
                        write_perm = _attr(elem, "writePermission") if tag == "provider" else None
                        no_permission = (
                            permission is None
                            and (tag != "provider" or (read_perm is None and write_perm is None))
                        )
                        if no_permission:
                            findings.append(_finding(
                                severity="high",
                                category="manifest",
                                title=f"Exported {tag} without permission requirement",
                                description=(
                                    f"The {tag} '{comp_name}' is exported but has no "
                                    f"android:permission attribute. Any application on the "
                                    f"device can interact with it."
                                ),
                                location=location_str,
                                recommendation=(
                                    f"Add android:permission to the <{tag}> element with a "
                                    f"signature-level or custom permission, or set "
                                    f"android:exported=\"false\" if external access is not required."
                                ),
                            ))

                    # Implicit export (no explicit exported attribute) with intent-filter
                    if not explicit_export and has_intent_filters and target_sdk < 31:
                        findings.append(_finding(
                            severity="medium",
                            category="manifest",
                            title=f"Implicitly exported {tag} (targetSdk < 31)",
                            description=(
                                f"The {tag} '{comp_name}' has intent-filters but no explicit "
                                f"android:exported attribute. On targetSdk < 31 this implicitly "
                                f"exports the component. Android 12+ (API 31) changed this "
                                f"default, but the app targets SDK {target_sdk}."
                            ),
                            location=location_str,
                            recommendation=(
                                f"Explicitly set android:exported=\"true\" or \"false\" on "
                                f"every <{tag}> that has intent-filters. Target SDK 31+ to "
                                f"benefit from the safer default."
                            ),
                        ))

                    # Activity-specific: empty taskAffinity on exported activities
                    if tag == "activity" and is_exported:
                        task_affinity = _attr(elem, "taskAffinity")
                        if task_affinity == "":
                            findings.append(_finding(
                                severity="medium",
                                category="manifest",
                                title="Exported activity with empty taskAffinity",
                                description=(
                                    f"Activity '{comp_name}' is exported and has "
                                    f"android:taskAffinity set to an empty string. "
                                    f"Combined with certain launch modes this can allow "
                                    f"UI-spoofing or task-hijacking attacks."
                                ),
                                location=location_str,
                                recommendation=(
                                    "Remove the empty taskAffinity or set it to the application "
                                    "package name. Review the activity's launchMode."
                                ),
                            ))

                        # singleTask launch mode on exported activities
                        launch_mode = _attr(elem, "launchMode", "")
                        if launch_mode == "singleTask":
                            findings.append(_finding(
                                severity="medium",
                                category="manifest",
                                title="Exported activity with singleTask launchMode (task hijacking risk)",
                                description=(
                                    f"Activity '{comp_name}' is exported and uses "
                                    f"android:launchMode=\"singleTask\". A malicious app can "
                                    f"start this activity in its own task and then position a "
                                    f"spoofed UI on top (task hijacking)."
                                ),
                                location=location_str,
                                recommendation=(
                                    "Use standard or singleTop launchMode for exported activities "
                                    "where possible. If singleTask is required, add a permission "
                                    "check or verify the calling package."
                                ),
                            ))

        # ------------------------------------------------------------------ #
        # minSdkVersion check
        # ------------------------------------------------------------------ #
        if min_sdk > 0 and min_sdk < 21:
            findings.append(_finding(
                severity="high",
                category="manifest",
                title=f"Supports pre-Lollipop Android (minSdkVersion={min_sdk})",
                description=(
                    f"The app declares minSdkVersion={min_sdk}, meaning it must run on "
                    f"Android versions before 5.0 (Lollipop / API 21). These versions lack "
                    f"many security improvements: no full-disk encryption requirement, "
                    f"older TLS stacks, no verified boot, and numerous unpatched CVEs."
                ),
                location="AndroidManifest.xml <uses-sdk>",
                recommendation=(
                    "Raise minSdkVersion to at least 21 (Android 5.0) to benefit from "
                    "modern security features. Evaluate whether supporting older devices "
                    "is necessary."
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
        return {"status": "error", "message": str(exc),
                "suggestion": "Call load_apk first to create a session."}
    except Exception as exc:
        return {"status": "error", "message": f"Manifest scan failed: {exc}",
                "suggestion": "Ensure the APK was loaded successfully."}


# ---------------------------------------------------------------------------
# Tool 2 – Cryptographic issues
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_crypto_issues(session_id: str) -> dict:
    """Scan the APK for cryptographic vulnerabilities in bytecode and strings.

    Checks for ECB mode, weak algorithms (DES, MD5, SHA-1), hardcoded keys/IVs,
    seeded SecureRandom, and insecure TrustManager implementations.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with status and data containing a findings list and severity summary.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis
        findings: list[dict] = []

        def _add_method_finding(sev, title, description, recommendation,
                                classname_re, methodname_re, category="crypto"):
            locs = _callers_of(analysis, classname_re, methodname_re)
            if locs:
                findings.append(_finding(
                    severity=sev,
                    category=category,
                    title=title,
                    description=description + f" Found in: {', '.join(locs[:5])}.",
                    location="; ".join(locs[:5]),
                    recommendation=recommendation,
                ))

        # ------------------------------------------------------------------ #
        # Cipher.getInstance checks
        # ------------------------------------------------------------------ #
        # Collect all Cipher.getInstance calls and inspect string arguments
        cipher_ecb_locs: list[str] = []
        cipher_aes_default_locs: list[str] = []
        cipher_des_locs: list[str] = []

        for method_analysis in analysis.find_methods(
            classname=r"Ljavax/crypto/Cipher;", methodname=r"getInstance"
        ):
            for _, caller, _ in method_analysis.get_xref_from():
                # Try to read the constant string argument from the caller's instructions
                caller_loc = f"{caller.class_name}->{caller.name}"
                try:
                    for instr in caller.get_method().get_instructions():
                        mnemonic = instr.get_name()
                        if mnemonic in ("const-string", "const-string/jumbo"):
                            val = instr.get_output().strip().strip("'\"")
                            val_upper = val.upper()
                            if "ECB" in val_upper:
                                if caller_loc not in cipher_ecb_locs:
                                    cipher_ecb_locs.append(caller_loc)
                            elif val_upper in ("AES", "DES", "DESEDE") or val_upper.startswith("DES/") or val_upper.startswith("DESEDE/"):
                                if "DES" in val_upper and caller_loc not in cipher_des_locs:
                                    cipher_des_locs.append(caller_loc)
                                elif val_upper == "AES" and caller_loc not in cipher_aes_default_locs:
                                    cipher_aes_default_locs.append(caller_loc)
                except Exception:
                    pass

        if cipher_ecb_locs:
            findings.append(_finding(
                severity="high",
                category="crypto",
                title="Cipher uses ECB mode",
                description=(
                    "ECB (Electronic Codebook) mode encrypts each block independently, "
                    "making it vulnerable to pattern analysis. Identical plaintext blocks "
                    "produce identical ciphertext blocks."
                ),
                location="; ".join(cipher_ecb_locs[:5]),
                recommendation=(
                    "Replace ECB with an authenticated encryption mode such as AES/GCM/NoPadding "
                    "and use a unique random IV per encryption operation."
                ),
            ))

        if cipher_aes_default_locs:
            findings.append(_finding(
                severity="high",
                category="crypto",
                title="Cipher.getInstance(\"AES\") defaults to ECB mode",
                description=(
                    "Calling Cipher.getInstance(\"AES\") without a mode/padding string "
                    "causes the JCA provider to use AES/ECB/PKCS5Padding by default, "
                    "which is insecure."
                ),
                location="; ".join(cipher_aes_default_locs[:5]),
                recommendation=(
                    "Always specify the full transformation: use AES/GCM/NoPadding for "
                    "authenticated encryption or AES/CBC/PKCS5Padding with a random IV at minimum."
                ),
            ))

        if cipher_des_locs:
            findings.append(_finding(
                severity="high",
                category="crypto",
                title="Weak cipher algorithm: DES or 3DES",
                description=(
                    "DES has a 56-bit key and is broken. Triple-DES (3DES/DESede) has "
                    "an effective security level of ~112 bits and is deprecated by NIST "
                    "(SP 800-131A). Both are significantly weaker than AES."
                ),
                location="; ".join(cipher_des_locs[:5]),
                recommendation=(
                    "Replace DES/3DES with AES-256 in GCM mode. "
                    "Migrate existing encrypted data if possible."
                ),
            ))

        # ------------------------------------------------------------------ #
        # MessageDigest – MD5 / SHA-1
        # ------------------------------------------------------------------ #
        md5_locs: list[str] = []
        sha1_locs: list[str] = []
        for method_analysis in analysis.find_methods(
            classname=r"Ljava/security/MessageDigest;", methodname=r"getInstance"
        ):
            for _, caller, _ in method_analysis.get_xref_from():
                caller_loc = f"{caller.class_name}->{caller.name}"
                try:
                    for instr in caller.get_method().get_instructions():
                        if instr.get_name() in ("const-string", "const-string/jumbo"):
                            val = instr.get_output().strip().strip("'\"").upper()
                            if val == "MD5" and caller_loc not in md5_locs:
                                md5_locs.append(caller_loc)
                            elif val in ("SHA-1", "SHA1") and caller_loc not in sha1_locs:
                                sha1_locs.append(caller_loc)
                except Exception:
                    pass

        if md5_locs:
            findings.append(_finding(
                severity="high",
                category="crypto",
                title="MD5 used for hashing",
                description=(
                    "MD5 is cryptographically broken and must not be used for security "
                    "purposes (password hashing, integrity verification, digital signatures). "
                    "Collisions can be generated in seconds."
                ),
                location="; ".join(md5_locs[:5]),
                recommendation=(
                    "Replace MD5 with SHA-256 or SHA-3 for integrity checks. "
                    "For password storage use bcrypt, scrypt, or Argon2."
                ),
            ))

        if sha1_locs:
            findings.append(_finding(
                severity="medium",
                category="crypto",
                title="SHA-1 used for hashing",
                description=(
                    "SHA-1 is deprecated for cryptographic use. Chosen-prefix collision "
                    "attacks have been demonstrated (SHAttered, 2017). It should not be "
                    "used for security-critical hashing."
                ),
                location="; ".join(sha1_locs[:5]),
                recommendation=(
                    "Replace SHA-1 with SHA-256 or stronger. "
                    "SHA-1 may be acceptable for non-security checksums only."
                ),
            ))

        # ------------------------------------------------------------------ #
        # SecretKeySpec – potential hardcoded key
        # ------------------------------------------------------------------ #
        _add_method_finding(
            sev="high",
            title="SecretKeySpec instantiation (possible hardcoded key)",
            description=(
                "SecretKeySpec is constructed directly from a byte array. "
                "If the key material is a hardcoded literal, it can be extracted "
                "by static analysis or bytecode inspection."
            ),
            recommendation=(
                "Derive keys from user passwords with PBKDF2/Argon2, or use the Android "
                "Keystore System to generate and store keys securely."
            ),
            classname_re=r"Ljavax/crypto/spec/SecretKeySpec;",
            methodname_re=r"<init>",
        )

        # ------------------------------------------------------------------ #
        # IvParameterSpec – possible static IV
        # ------------------------------------------------------------------ #
        _add_method_finding(
            sev="medium",
            title="IvParameterSpec instantiation (verify IV is random)",
            description=(
                "IvParameterSpec is used to supply an Initialisation Vector. "
                "If the IV is hardcoded or derived deterministically, CBC/CTR modes "
                "become vulnerable to known-plaintext and other attacks."
            ),
            recommendation=(
                "Always generate IVs with SecureRandom: "
                "byte[] iv = new byte[16]; new SecureRandom().nextBytes(iv);"
            ),
            classname_re=r"Ljavax/crypto/spec/IvParameterSpec;",
            methodname_re=r"<init>",
        )

        # ------------------------------------------------------------------ #
        # SecureRandom.setSeed – seeded PRNG
        # ------------------------------------------------------------------ #
        _add_method_finding(
            sev="high",
            title="SecureRandom.setSeed() called (predictable randomness)",
            description=(
                "Calling setSeed() on a SecureRandom instance with a fixed or low-entropy "
                "value makes its output predictable, undermining any cryptographic operation "
                "that relies on it for key generation or IV creation."
            ),
            recommendation=(
                "Do not call setSeed() on SecureRandom used for cryptographic purposes. "
                "Let the OS seed the PRNG automatically."
            ),
            classname_re=r"Ljava/security/SecureRandom;",
            methodname_re=r"setSeed",
        )

        # ------------------------------------------------------------------ #
        # TrustManager implementations
        # ------------------------------------------------------------------ #
        tm_locs: list[str] = []
        for cls in analysis.get_classes():
            for iface in cls.implements:
                if "TrustManager" in iface or "X509TrustManager" in iface:
                    loc = cls.name
                    if loc not in tm_locs:
                        tm_locs.append(loc)
        if tm_locs:
            findings.append(_finding(
                severity="critical",
                category="crypto",
                title="Custom TrustManager implementation detected",
                description=(
                    "One or more classes implement TrustManager/X509TrustManager. "
                    "Custom implementations frequently skip certificate validation "
                    "(empty checkServerTrusted), enabling MITM attacks. "
                    f"Affected classes: {', '.join(tm_locs[:5])}."
                ),
                location="; ".join(tm_locs[:5]),
                recommendation=(
                    "Remove custom TrustManager implementations. "
                    "Use the system's default TrustManager or configure a "
                    "Network Security Config with pinned certificates."
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
        return {"status": "error", "message": str(exc),
                "suggestion": "Call load_apk first to create a session."}
    except Exception as exc:
        return {"status": "error", "message": f"Crypto scan failed: {exc}",
                "suggestion": "Ensure the APK was loaded successfully."}


# ---------------------------------------------------------------------------
# Tool 3 – Network security
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_network_security(session_id: str) -> dict:
    """Scan the APK for network security vulnerabilities.

    Checks for HTTP URLs, custom HostnameVerifier / TrustManager implementations,
    WebView mixed content and universal file access, and absence of certificate pinning.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with status and data containing a findings list and severity summary.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis
        findings: list[dict] = []

        # ------------------------------------------------------------------ #
        # HTTP URLs in strings
        # ------------------------------------------------------------------ #
        http_urls: list[str] = []
        for string_analysis in analysis.find_strings(string=r"http://"):
            val = string_analysis.get_value()
            if val not in http_urls:
                http_urls.append(val)
            if len(http_urls) >= 20:
                break

        if http_urls:
            findings.append(_finding(
                severity="medium",
                category="network",
                title="Plain HTTP URLs found in strings",
                description=(
                    f"The following non-HTTPS URLs were found in the APK's string pool: "
                    f"{', '.join(http_urls[:10])}{'...' if len(http_urls) > 10 else ''}. "
                    f"HTTP traffic is unencrypted and subject to interception."
                ),
                location="string pool",
                recommendation=(
                    "Replace all http:// endpoints with https://. "
                    "Configure a Network Security Config to block cleartext traffic."
                ),
            ))

        # ------------------------------------------------------------------ #
        # Custom X509TrustManager (cert validation bypass)
        # ------------------------------------------------------------------ #
        custom_tm: list[str] = []
        for cls in analysis.get_classes():
            for iface in cls.implements:
                if "X509TrustManager" in iface:
                    custom_tm.append(cls.name)

        if custom_tm:
            findings.append(_finding(
                severity="critical",
                category="network",
                title="Custom X509TrustManager implementation",
                description=(
                    "Classes implementing X509TrustManager were found. "
                    "These frequently override checkServerTrusted() with an empty body "
                    "or catch block, disabling TLS certificate validation entirely and "
                    "enabling MITM attacks. "
                    f"Classes: {', '.join(custom_tm[:5])}."
                ),
                location="; ".join(custom_tm[:5]),
                recommendation=(
                    "Remove custom TrustManager implementations. "
                    "Use the platform TrustManager or a Network Security Config with pinned certs."
                ),
            ))

        # ------------------------------------------------------------------ #
        # HostnameVerifier (ALLOW_ALL pattern)
        # ------------------------------------------------------------------ #
        hn_locs: list[str] = []
        for cls in analysis.get_classes():
            for iface in cls.implements:
                if "HostnameVerifier" in iface:
                    hn_locs.append(cls.name)

        # Also search for ALLOW_ALL_HOSTNAME_VERIFIER field references
        allow_all_locs = _callers_of(
            analysis,
            r"Ljavax/net/ssl/HttpsURLConnection;",
            r"setDefaultHostnameVerifier",
        )

        all_hn = list(dict.fromkeys(hn_locs + allow_all_locs))  # deduplicate
        if all_hn:
            findings.append(_finding(
                severity="critical",
                category="network",
                title="Custom HostnameVerifier or ALLOW_ALL pattern detected",
                description=(
                    "HostnameVerifier implementations or setDefaultHostnameVerifier calls "
                    "were found. If verify() always returns true, any server certificate "
                    "hostname is accepted, enabling MITM attacks. "
                    f"Locations: {', '.join(all_hn[:5])}."
                ),
                location="; ".join(all_hn[:5]),
                recommendation=(
                    "Do not implement HostnameVerifier returning true unconditionally. "
                    "Let the default Android hostname verifier handle validation."
                ),
            ))

        # ------------------------------------------------------------------ #
        # WebView setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)
        # ------------------------------------------------------------------ #
        mixed_locs = _callers_of(
            analysis,
            r"Landroid/webkit/WebSettings;",
            r"setMixedContentMode",
        )
        if mixed_locs:
            findings.append(_finding(
                severity="high",
                category="network",
                title="WebView setMixedContentMode called (verify it is not ALWAYS_ALLOW)",
                description=(
                    "setMixedContentMode() is called on a WebSettings object. "
                    "If the constant MIXED_CONTENT_ALWAYS_ALLOW (0) is passed, the WebView "
                    "will load HTTP subresources in HTTPS pages, enabling content injection. "
                    f"Callers: {', '.join(mixed_locs[:5])}."
                ),
                location="; ".join(mixed_locs[:5]),
                recommendation=(
                    "Use MIXED_CONTENT_NEVER_ALLOW (1) or MIXED_CONTENT_COMPATIBILITY_MODE (2). "
                    "Audit all setMixedContentMode call sites for the constant value passed."
                ),
            ))

        # ------------------------------------------------------------------ #
        # Certificate pinning – absence of OkHttp CertificatePinner
        # ------------------------------------------------------------------ #
        pinner_locs: list[str] = []
        for method_analysis in analysis.find_methods(
            classname=r"Lokhttp3/CertificatePinner.*", methodname=r".*"
        ):
            loc = method_analysis.get_method().class_name
            if loc not in pinner_locs:
                pinner_locs.append(loc)

        trustkit_locs: list[str] = []
        for string_analysis in analysis.find_strings(string=r"TrustKit"):
            trustkit_locs.append(string_analysis.get_value())

        if not pinner_locs and not trustkit_locs:
            findings.append(_finding(
                severity="low",
                category="network",
                title="No certificate pinning detected",
                description=(
                    "Neither OkHttp CertificatePinner nor TrustKit usage was found. "
                    "Without pinning, the app trusts any certificate chaining to a "
                    "system-trusted CA, making it vulnerable to MITM attacks using "
                    "rogue CAs or user-installed certificates."
                ),
                location="N/A",
                recommendation=(
                    "Implement certificate pinning for sensitive endpoints using "
                    "OkHttp CertificatePinner, Network Security Config <pin-set>, or TrustKit."
                ),
            ))

        # ------------------------------------------------------------------ #
        # WebView setAllowUniversalAccessFromFileURLs
        # ------------------------------------------------------------------ #
        universal_access_locs = _callers_of(
            analysis,
            r"Landroid/webkit/WebSettings;",
            r"setAllowUniversalAccessFromFileURLs",
        )
        if universal_access_locs:
            findings.append(_finding(
                severity="high",
                category="network",
                title="WebView setAllowUniversalAccessFromFileURLs called",
                description=(
                    "setAllowUniversalAccessFromFileURLs() is called. If set to true, "
                    "JavaScript in file:// pages can make cross-origin requests to any "
                    "origin including content:// and https:// URIs, enabling data theft "
                    "if the WebView loads attacker-controlled HTML. "
                    f"Callers: {', '.join(universal_access_locs[:5])}."
                ),
                location="; ".join(universal_access_locs[:5]),
                recommendation=(
                    "Set setAllowUniversalAccessFromFileURLs(false) (the default). "
                    "Avoid loading local files in WebViews; use assets served via "
                    "a local web server or Android asset protocol instead."
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
        return {"status": "error", "message": str(exc),
                "suggestion": "Call load_apk first to create a session."}
    except Exception as exc:
        return {"status": "error", "message": f"Network security scan failed: {exc}",
                "suggestion": "Ensure the APK was loaded successfully."}


# ---------------------------------------------------------------------------
# Tool 4 – Code injection
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_code_injection(session_id: str) -> dict:
    """Scan the APK for code injection and dynamic execution vulnerabilities.

    Checks for addJavascriptInterface, raw SQL queries, Runtime.exec,
    dynamic class loading (DexClassLoader), and WebView.loadUrl usage.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with status and data containing a findings list and severity summary.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis
        findings: list[dict] = []

        def _check(sev, title, description, recommendation, classname_re, methodname_re,
                   category="code_injection"):
            locs = _callers_of(analysis, classname_re, methodname_re)
            if locs:
                findings.append(_finding(
                    severity=sev,
                    category=category,
                    title=title,
                    description=description + f" Callers: {', '.join(locs[:5])}.",
                    location="; ".join(locs[:5]),
                    recommendation=recommendation,
                ))

        # addJavascriptInterface
        _check(
            sev="critical",
            title="WebView.addJavascriptInterface() usage",
            description=(
                "addJavascriptInterface() exposes Java/Kotlin objects to JavaScript in the "
                "WebView. On API < 17 all public methods are accessible; on API >= 17 only "
                "@JavascriptInterface-annotated ones. If the WebView loads untrusted content, "
                "attackers can call Java methods directly."
            ),
            recommendation=(
                "Avoid addJavascriptInterface() if possible. If required, ensure the WebView "
                "only loads trusted HTTPS content, use @JavascriptInterface only on necessary "
                "methods, and validate all data received from JavaScript."
            ),
            classname_re=r"Landroid/webkit/WebView;",
            methodname_re=r"addJavascriptInterface",
        )

        # rawQuery
        _check(
            sev="high",
            title="SQLiteDatabase.rawQuery() usage (potential SQL injection)",
            description=(
                "rawQuery() executes a raw SQL statement. If user-supplied input is "
                "concatenated into the query string rather than bound as a parameterised "
                "argument, SQL injection is possible."
            ),
            recommendation=(
                "Use parameterised queries: rawQuery(query, selectionArgs) with ? placeholders, "
                "or use the query()/insert()/update()/delete() helper methods."
            ),
            classname_re=r"Landroid/database/sqlite/SQLiteDatabase;",
            methodname_re=r"rawQuery",
        )

        # execSQL
        _check(
            sev="high",
            title="SQLiteDatabase.execSQL() usage (potential SQL injection)",
            description=(
                "execSQL() executes arbitrary SQL. Concatenating user input into the "
                "statement string allows SQL injection."
            ),
            recommendation=(
                "Use parameterised forms: execSQL(sql, bindArgs) and ensure all "
                "user-controlled values are passed as bind arguments, not string-concatenated."
            ),
            classname_re=r"Landroid/database/sqlite/SQLiteDatabase;",
            methodname_re=r"execSQL",
        )

        # Runtime.exec
        _check(
            sev="critical",
            title="Runtime.exec() usage (OS command execution)",
            description=(
                "Runtime.exec() spawns a native OS process. If any argument contains "
                "user-supplied data without sanitisation, OS command injection is possible."
            ),
            recommendation=(
                "Avoid Runtime.exec() with user input. If process execution is necessary, "
                "use a fixed command array (not shell interpolation) and validate all arguments."
            ),
            classname_re=r"Ljava/lang/Runtime;",
            methodname_re=r"exec",
        )

        # ProcessBuilder
        _check(
            sev="high",
            title="ProcessBuilder usage (OS command execution)",
            description=(
                "ProcessBuilder is used to launch native processes. Unsanitised user input "
                "in the command list can lead to argument injection or command execution."
            ),
            recommendation=(
                "Use a fixed, hardcoded command list. Never pass user-controlled strings "
                "as ProcessBuilder command elements."
            ),
            classname_re=r"Ljava/lang/ProcessBuilder;",
            methodname_re=r"<init>",
        )

        # DexClassLoader
        _check(
            sev="critical",
            title="DexClassLoader usage (dynamic code loading)",
            description=(
                "DexClassLoader loads DEX/APK/JAR files from the filesystem at runtime. "
                "If the path is attacker-controlled or the loaded file is not integrity-checked, "
                "arbitrary code can be injected into the application process."
            ),
            recommendation=(
                "Avoid loading code from external/writable paths. If dynamic loading is "
                "required, verify the DEX file's integrity (cryptographic signature or hash) "
                "before loading and store it in the app's internal storage."
            ),
            classname_re=r"Ldalvik/system/DexClassLoader;",
            methodname_re=r"<init>",
        )

        # PathClassLoader
        _check(
            sev="high",
            title="PathClassLoader usage (dynamic code loading)",
            description=(
                "PathClassLoader loads classes from filesystem paths at runtime. "
                "Loading code from untrusted or world-writable locations can lead to "
                "code injection."
            ),
            recommendation=(
                "Restrict loaded paths to the application's internal storage. "
                "Verify the integrity of any externally sourced DEX/JAR files."
            ),
            classname_re=r"Ldalvik/system/PathClassLoader;",
            methodname_re=r"<init>",
        )

        # InMemoryDexClassLoader (API 26+)
        _check(
            sev="high",
            title="InMemoryDexClassLoader usage (in-memory code loading)",
            description=(
                "InMemoryDexClassLoader loads DEX bytecode directly from a ByteBuffer. "
                "This is a common technique used by packers and malware to evade static "
                "analysis by loading obfuscated or encrypted payloads at runtime."
            ),
            recommendation=(
                "Legitimate use cases are rare. Review all InMemoryDexClassLoader "
                "instantiation sites and ensure the source of the byte buffer is trusted "
                "and integrity-verified."
            ),
            classname_re=r"Ldalvik/system/InMemoryDexClassLoader;",
            methodname_re=r"<init>",
        )

        # Class.forName
        _check(
            sev="medium",
            title="Class.forName() usage (dynamic class loading)",
            description=(
                "Class.forName() loads a class by name at runtime. If the class name "
                "is derived from user input or an external source, an attacker may be "
                "able to trigger loading of unintended classes."
            ),
            recommendation=(
                "Ensure the class name passed to Class.forName() is from a trusted, "
                "controlled source. Prefer a whitelist of allowed class names."
            ),
            classname_re=r"Ljava/lang/Class;",
            methodname_re=r"forName",
        )

        # WebView.loadUrl
        _check(
            sev="high",
            title="WebView.loadUrl() usage (verify input is trusted)",
            description=(
                "WebView.loadUrl() is called. If the URL is derived from an Intent extra "
                "or another external source without validation, an attacker can direct the "
                "WebView to load arbitrary URLs or javascript: URIs."
            ),
            recommendation=(
                "Validate URLs before passing to loadUrl(). Reject javascript: and data: "
                "schemes. Use an allowlist of trusted domains. Never pass raw Intent data "
                "to loadUrl() without sanitisation."
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
        return {"status": "error", "message": str(exc),
                "suggestion": "Call load_apk first to create a session."}
    except Exception as exc:
        return {"status": "error", "message": f"Code injection scan failed: {exc}",
                "suggestion": "Ensure the APK was loaded successfully."}


# ---------------------------------------------------------------------------
# Tool 5 – Insecure data storage
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_data_storage(session_id: str) -> dict:
    """Scan the APK for insecure data storage practices.

    Checks for world-readable/writable file modes, sensitive data in SharedPreferences,
    external storage usage, unencrypted SQLite databases, and sensitive data in logs.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with status and data containing a findings list and severity summary.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis
        findings: list[dict] = []

        def _check(sev, title, description, recommendation, classname_re, methodname_re,
                   category="data_storage"):
            locs = _callers_of(analysis, classname_re, methodname_re)
            if locs:
                findings.append(_finding(
                    severity=sev,
                    category=category,
                    title=title,
                    description=description + f" Callers: {', '.join(locs[:5])}.",
                    location="; ".join(locs[:5]),
                    recommendation=recommendation,
                ))

        # ------------------------------------------------------------------ #
        # MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE
        # ------------------------------------------------------------------ #
        # These are integer constants (1 and 2). Check string pool for the
        # literal names and look for openFileOutput / getSharedPreferences calls.
        world_readable_locs: list[str] = []
        world_writable_locs: list[str] = []

        # Search for the constant names in strings (proguard may strip, but often present)
        for string_analysis in analysis.find_strings(string=r"MODE_WORLD_READABLE"):
            world_readable_locs.append(string_analysis.get_value())
        for string_analysis in analysis.find_strings(string=r"MODE_WORLD_WRITEABLE"):
            world_writable_locs.append(string_analysis.get_value())

        # Also look for openFileOutput callers (may use integer 1 or 2)
        open_file_output_locs = _callers_of(
            analysis,
            r"Landroid/content/Context;",
            r"openFileOutput",
        )
        # Heuristic: flag all openFileOutput callers as worth inspecting
        if open_file_output_locs or world_readable_locs:
            findings.append(_finding(
                severity="high",
                category="data_storage",
                title="Potential use of MODE_WORLD_READABLE file mode",
                description=(
                    "openFileOutput() or MODE_WORLD_READABLE was found. "
                    "Creating files with MODE_WORLD_READABLE allows any application on "
                    "the device to read the file, exposing its contents. "
                    f"Callers: {', '.join(open_file_output_locs[:5])}."
                ),
                location="; ".join(open_file_output_locs[:5]) or "string pool",
                recommendation=(
                    "Use MODE_PRIVATE (0) for file creation. "
                    "Sensitive files should be created in the app's internal storage "
                    "and never shared via world-readable permissions."
                ),
            ))

        if world_writable_locs:
            findings.append(_finding(
                severity="high",
                category="data_storage",
                title="MODE_WORLD_WRITEABLE detected",
                description=(
                    "MODE_WORLD_WRITEABLE allows any application to overwrite the file, "
                    "enabling data tampering or injection attacks."
                ),
                location="string pool",
                recommendation=(
                    "Use MODE_PRIVATE (0). Never create files with world-writable permissions."
                ),
            ))

        # ------------------------------------------------------------------ #
        # SharedPreferences with sensitive key names
        # ------------------------------------------------------------------ #
        sensitive_keywords = ("password", "passwd", "token", "secret", "key",
                              "credential", "auth", "private", "pin", "cvv", "ssn")
        sp_sensitive: list[str] = []
        for string_analysis in analysis.find_strings(string=r"(?i)(password|passwd|token|secret|credential|auth_key|private_key|api_key|access_token|pin)"):
            val = string_analysis.get_value().lower()
            if any(kw in val for kw in sensitive_keywords):
                if val not in sp_sensitive:
                    sp_sensitive.append(string_analysis.get_value())
            if len(sp_sensitive) >= 20:
                break

        sp_locs = _callers_of(
            analysis,
            r"Landroid/content/SharedPreferences.*",
            r"putString|putInt|putBoolean|putFloat|putLong",
        )
        if sp_sensitive:
            findings.append(_finding(
                severity="high",
                category="data_storage",
                title="Sensitive keywords found in strings (possible SharedPreferences keys)",
                description=(
                    "Strings matching sensitive data patterns (password, token, secret, key, etc.) "
                    "were found in the APK. These may be SharedPreferences keys used to store "
                    "sensitive data in plaintext. "
                    f"Examples: {', '.join(sp_sensitive[:8])}."
                ),
                location=f"string pool; SharedPreferences callers: {'; '.join(sp_locs[:3])}",
                recommendation=(
                    "Avoid storing sensitive data in SharedPreferences in plaintext. "
                    "Use EncryptedSharedPreferences (Jetpack Security library) or the "
                    "Android Keystore to protect secrets at rest."
                ),
            ))

        # ------------------------------------------------------------------ #
        # External storage
        # ------------------------------------------------------------------ #
        ext_locs = _callers_of(
            analysis,
            r"Landroid/os/Environment;",
            r"getExternalStorageDirectory",
        )
        ext_files_locs = _callers_of(
            analysis,
            r"Landroid/content/Context;",
            r"getExternalFilesDir",
        )
        all_ext = list(dict.fromkeys(ext_locs + ext_files_locs))
        if all_ext:
            findings.append(_finding(
                severity="medium",
                category="data_storage",
                title="External storage used for file operations",
                description=(
                    "getExternalStorageDirectory() or getExternalFilesDir() is called. "
                    "Data written to external storage is accessible to other applications "
                    "with READ_EXTERNAL_STORAGE permission and to the user via USB. "
                    f"Callers: {', '.join(all_ext[:5])}."
                ),
                location="; ".join(all_ext[:5]),
                recommendation=(
                    "Do not store sensitive data on external storage. "
                    "Use the app's internal data directory (getFilesDir(), getCacheDir()) "
                    "for private data. Encrypt any data that must go to external storage."
                ),
            ))

        # ------------------------------------------------------------------ #
        # SQLite without SQLCipher
        # ------------------------------------------------------------------ #
        sqlite_locs = _callers_of(
            analysis,
            r"Landroid/database/sqlite/SQLiteOpenHelper;",
            r"<init>",
        )
        sqlcipher_locs: list[str] = []
        for string_analysis in analysis.find_strings(string=r"net.sqlcipher"):
            sqlcipher_locs.append(string_analysis.get_value())

        if sqlite_locs and not sqlcipher_locs:
            findings.append(_finding(
                severity="medium",
                category="data_storage",
                title="SQLite database used without encryption (no SQLCipher)",
                description=(
                    "SQLiteOpenHelper is used but no SQLCipher dependency was detected. "
                    "SQLite databases are stored in plaintext at data/data/<package>/databases/ "
                    "and can be read by root users or via adb backup. "
                    f"SQLiteOpenHelper subclasses: {', '.join(sqlite_locs[:5])}."
                ),
                location="; ".join(sqlite_locs[:5]),
                recommendation=(
                    "Use SQLCipher for Android to encrypt the database, or use "
                    "EncryptedFile (Jetpack Security) to wrap an existing SQLite file. "
                    "At minimum, ensure sensitive columns are encrypted at the application level."
                ),
            ))

        # ------------------------------------------------------------------ #
        # Sensitive data in logs
        # ------------------------------------------------------------------ #
        log_methods = ("d", "i", "v", "w", "e", "wtf")
        log_sensitive_locs: list[str] = []

        for log_method in log_methods:
            for method_analysis in analysis.find_methods(
                classname=r"Landroid/util/Log;", methodname=f"^{log_method}$"
            ):
                for _, caller, _ in method_analysis.get_xref_from():
                    caller_loc = f"{caller.class_name}->{caller.name}"
                    try:
                        instructions = list(caller.get_method().get_instructions())
                        for instr in instructions:
                            if instr.get_name() in ("const-string", "const-string/jumbo"):
                                val = instr.get_output().strip().strip("'\"").lower()
                                if any(kw in val for kw in sensitive_keywords):
                                    if caller_loc not in log_sensitive_locs:
                                        log_sensitive_locs.append(caller_loc)
                    except Exception:
                        pass
                    if len(log_sensitive_locs) >= 20:
                        break

        if log_sensitive_locs:
            findings.append(_finding(
                severity="high",
                category="data_storage",
                title="Sensitive data may be written to logcat",
                description=(
                    "Log.d/i/v/w/e calls with string arguments matching sensitive keywords "
                    "(password, token, secret, key, etc.) were found. Logcat output is "
                    "accessible to any app with READ_LOGS permission on older API levels "
                    "and to adb. "
                    f"Callers: {', '.join(log_sensitive_locs[:5])}."
                ),
                location="; ".join(log_sensitive_locs[:5]),
                recommendation=(
                    "Remove all Log calls that output sensitive data before release. "
                    "Use a logging facade that strips sensitive fields in production builds, "
                    "or disable logging via ProGuard/R8 rules."
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
        return {"status": "error", "message": str(exc),
                "suggestion": "Call load_apk first to create a session."}
    except Exception as exc:
        return {"status": "error", "message": f"Data storage scan failed: {exc}",
                "suggestion": "Ensure the APK was loaded successfully."}


# ---------------------------------------------------------------------------
# Tool 6 – Combined scan
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_all(session_id: str) -> dict:
    """Run all security scans and return a combined report.

    Executes scan_manifest_security, scan_crypto_issues, scan_network_security,
    scan_code_injection, and scan_data_storage, then aggregates findings.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with status and data containing all findings, per-scanner results,
        and a combined severity summary.
    """
    scanners = {
        "manifest": scan_manifest_security,
        "crypto": scan_crypto_issues,
        "network": scan_network_security,
        "code_injection": scan_code_injection,
        "data_storage": scan_data_storage,
    }

    all_findings: list[dict] = []
    per_scanner: dict[str, dict] = {}
    errors: list[str] = []

    for name, fn in scanners.items():
        result = fn(session_id)
        per_scanner[name] = result
        if result.get("status") == "ok":
            scanner_findings = result.get("data", {}).get("findings", [])
            # Tag each finding with its scanner name for traceability
            for f in scanner_findings:
                tagged = dict(f)
                tagged.setdefault("scanner", name)
                all_findings.append(tagged)
        else:
            errors.append(f"{name}: {result.get('message', 'unknown error')}")

    combined_summary = _make_summary(all_findings)

    return {
        "status": "ok" if not errors else "partial",
        "data": {
            "findings": all_findings,
            "summary": combined_summary,
            "total_findings": len(all_findings),
            "per_scanner": {
                k: {
                    "status": v.get("status"),
                    "summary": v.get("data", {}).get("summary", {}),
                    "count": len(v.get("data", {}).get("findings", [])),
                }
                for k, v in per_scanner.items()
            },
            "errors": errors if errors else None,
        },
    }
