# Certificate Tools

Tools for inspecting APK signing certificates.

## `get_signing_info`

Return structured data about the APK's signing certificate(s).

```
get_signing_info(session_id="abc123")
→ {
    "v1_signed": true,
    "v2_signed": true,
    "v3_signed": false,
    "certificates": [
      {
        "subject": "CN=Example Corp, O=Example Inc, C=US",
        "issuer": "CN=Example Corp, O=Example Inc, C=US",
        "serial": "0x1a2b3c",
        "not_before": "2020-01-01",
        "not_after": "2045-01-01",
        "sha256_fingerprint": "AA:BB:CC:...",
        "algorithm": "SHA256withRSA",
        "key_size": 2048
      }
    ]
  }
```

## `check_certificate_security`

Audit the signing certificate for security issues:

| Check | Description |
|---|---|
| Key size | RSA < 2048 bits or EC < 224 bits flagged |
| Algorithm | MD5/SHA1 signatures flagged as weak |
| Validity | Expired or expiring within 90 days |
| Debug certificate | Detects the Android debug keystore subject |
| Self-signed | Notes when issuer == subject |
| Signature schemes | V1-only signing is vulnerable to Janus (CVE-2017-13156) |

```
check_certificate_security(session_id="abc123")
→ {"findings": [{"severity": "MEDIUM", "issue": "V1-only signing", ...}]}
```
