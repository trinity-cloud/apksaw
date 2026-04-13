# Security Tools

Automated security scanners that check for common Android vulnerabilities.

## `scan_all`

Run all security scanners in one call and return consolidated findings.

```
scan_all(session_id="abc123")
→ {
    "summary": {"high": 3, "medium": 5, "low": 2},
    "findings": [
      {"id": "INSECURE_NETWORK", "severity": "HIGH", "detail": "..."},
      ...
    ]
  }
```

## `scan_manifest_security`

Check the manifest for dangerous misconfigurations:
- Exported components without permissions
- `android:debuggable="true"`
- `android:allowBackup="true"`
- Overly broad intent filters

## `scan_network_security`

Inspect the Network Security Config and manifest for cleartext traffic, certificate pinning bypass, and custom CA trust.

## `scan_code_injection`

Look for dynamic code execution patterns: `DexClassLoader`, `Runtime.exec`, `ProcessBuilder`, `Reflection`, `JavaScript.eval`.

## `scan_crypto_issues`

Detect weak cryptography: ECB mode, hardcoded IVs, MD5/SHA1 hashes for security purposes, insecure `SecureRandom` seeding.

## `scan_data_storage`

Flag insecure storage patterns: world-readable files, unencrypted SharedPreferences with sensitive keys, external storage writes, SQLite DBs with sensitive column names.

## `extract_secrets`

Targeted extraction of hardcoded secrets using pattern matching and entropy analysis:
- API keys (Google, AWS, Stripe, Firebase, etc.)
- Private keys and certificates embedded in resources
- JWT tokens and OAuth credentials
