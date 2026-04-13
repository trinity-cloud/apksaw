# Security Policy

## Scope

This policy covers security vulnerabilities **in apksaw itself** — its code, dependencies, and the MCP server it exposes. It does not cover vulnerabilities discovered *by* apksaw in third-party Android applications.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

If you believe you have found a security vulnerability in apksaw, please do **not** open a public GitHub issue. Instead, use one of the following channels:

### GitHub Security Advisories (preferred)

Open a [private security advisory](https://github.com/trinity-cloud/apksaw/security/advisories/new) on GitHub. This lets us collaborate on a fix before any public disclosure and automatically creates a CVE if one is warranted.

### Email

Send a report to `security@trinity-cloud.io` with the subject line `[apksaw] Security Report`. Include:

- A description of the vulnerability and its potential impact.
- Step-by-step reproduction instructions.
- Any proof-of-concept code or screenshots.
- Your preferred disclosure timeline (we aim for 90 days from report to fix).

## What to expect

- We will acknowledge your report within 3 business days.
- We will provide a status update within 14 days.
- We will credit you in the release notes and advisory unless you prefer to remain anonymous.

## Out of scope

- Vulnerabilities in the APK or device being analysed (those should be reported to the respective app vendor).
- Issues that require physical access to the analyst's machine.
- Denial-of-service via very large APK files (tracked as a known limitation).
