# Case Study: Hinge (co.hinge.app) Security Audit

> **Disclosure status.** This audit was performed on a publicly distributed release build for security research. Live credentials and other sensitive identifiers have been **redacted** in this writeup. These findings have **not yet been disclosed** to the vendor — they are published to document apksaw's workflow, not as a coordinated advisory. If you audit an app you do not own, follow the vendor's responsible-disclosure or bug-bounty process before publishing anything. apksaw is designed first for auditing apps **you own**, where this question doesn't arise.

**Target:** Hinge v9.116.0 (build 168200970), Android dating app by Match Group
**Device:** Pixel 10a, Android 16, non-rooted
**Time:** Approximately 3 hours from APK pull to final report

## Objective

Audit the Hinge Android app using apksaw to assess what an AI agent can find through static analysis and device-local testing. Hinge handles sensitive user data: precise location, religion, ethnicity, sexual orientation, political views, private messages, and photos.

## How apksaw was used

### Phase 1: Automated triage (minutes)

apksaw pulled the APK directly from the Pixel 10a (handling Hinge's split APK format automatically), loaded it into an analysis session, and ran all automated scanners in parallel:

```
> Pull the Hinge app from my phone and run a full security scan.
```

The scanner produced **20 initial findings**: 3 critical, 12 high, 5 medium. This gave the AI agent a starting point — but not a finished assessment.

### Phase 2: Manual verification (hours)

The AI agent spun up 10 parallel investigation threads, each using apksaw tools to decompile specific classes, trace cross-references, and verify whether each finding was real or a false positive.

**The results were humbling.** Of the 20 scanner findings:
- **13 were false positives** (65% false positive rate)
- **7 were true vulnerabilities**

Examples of false positives the agent caught by reading decompiled code:

| Scanner said | Agent found after decompilation |
|---|---|
| "Hardcoded SecretKeySpec" | RFC 8439 test vectors for JCE availability probe — not real keys |
| "SQL injection via rawQuery" | All queries parameterized, no exported ContentProviders |
| "Runtime.exec() — command injection" | Hardcoded `getprop` for device fingerprinting (FaceTec, Incognia SDKs) |
| "Custom HostnameVerifier — TLS bypass" | Standard OkHttp verifier + Google Places SDK, strict equality checks |
| "MODE_WORLD_READABLE" | Actually called with mode 0 (PRIVATE) |

### Phase 3: Exploitation and proof (hours)

For confirmed findings, the agent tested exploitability:

**Hardcoded API keys.** `extract_secrets` found 3 Google API keys and a Braze SDK key. The agent tested each with `curl`:
- **Google Geocoding key** (`AIzaSyCgxo…[redacted]`): unrestricted, returns geocoding results from any client — billable to Hinge's Google Cloud account
- **Braze SDK key** (`1d3dfa7b-…[redacted]`): valid, the SDK config endpoint returned 160 internal user attributes and 52 tracked event names
- **AppsFlyer dev key** (`XkJd…[redacted]`): accepted spoofed S2S attribution events
- **Two Google Places keys**: properly restricted to the Android package signature (not exploitable from outside the app)

**Deep link testing.** `get_manifest` and `get_components` identified exported activities with `hinge://` scheme handlers. The agent mapped 50+ internal routes via `search_strings`, then used ADB to demonstrate forced navigation to sensitive screens (data export, profile editor, dating preferences). Screenshots were captured showing successful navigation.

**Braze API key exploration.** The agent probed the Braze SDK API further and determined the key is an **SDK app identifier, not a REST API key**. It cannot read individual user data or send push notifications. It can leak the internal attribute schema and write anonymous device profiles — a real finding, but not a data breach.

## What apksaw provided vs. what the agent provided

| apksaw | AI agent |
|---|---|
| Decompiled 33,000 classes on demand | Read the code and understood what it does |
| Found API keys via regex patterns | Tested each key with `curl` to determine exploitability |
| Flagged `addJavascriptInterface` as critical | Traced the code to find the JS bridge is gated by Braze server control |
| Listed 183 HTTPS URLs | Distinguished API endpoints from XML namespaces |
| Identified exported components | Determined which ones have CSRF protection (Firebase OAuth) vs which don't |
| Flagged `SecretKeySpec` as hardcoded key | Identified RFC 8439 test vectors — not real cryptographic material |

## Findings (confirmed with evidence)

1. **Braze SDK key is valid and leaks internal data model** — 160 user attributes (including `Latitude`, `Longitude`, `Instagram Handle`, `FBID`, `Likes Remaining`, predictive model names like `$predict_grade - Ghosted Prediction`) and 52 tracked events. The key also accepts anonymous profile writes. However, it cannot read individual user data or send notifications.
2. **Google Geocoding API key is unrestricted** — works from any client without Android package restriction. Enables quota abuse against Hinge's billing account.
3. **AppsFlyer dev key accepts spoofed events** — the S2S API returned `ok` for fabricated attribution events, enabling marketing analytics pollution.
4. **Deep link UI redress** — any app can force-navigate a logged-in Hinge user to internal screens including data export, profile editor, dating preferences, and paywall. Confirmed via ADB with screenshots.
5. **Unencrypted SQLite database** stores full user PII including protected characteristics (religion, ethnicity, sexual orientation) in plaintext Room tables. Requires root to access.
6. **No certificate pinning** — OkHttp's `CertificatePinner` is present but configured with an empty pin set.
7. **No Braze SDK Authentication** — the `changeUser()` JS bridge method and the SDK config endpoint operate without JWT validation.

## What we could NOT prove

- **Data breach via Braze key**: The key leaks the schema but cannot read individual user profiles, messages, or location data.
- **Account takeover**: Without the user's Bearer token (which requires root or MITM to extract), we could not access the production API at `prod-api.hingeaws.net`.
- **Deep link data exfiltration**: Navigation to sensitive screens works, but the actual data on those screens requires server-side authentication that the deep link cannot bypass.

## Lessons learned

1. **Automated scanners produce noise.** The 65% false positive rate means an analyst is essential. apksaw found the candidates; the agent separated signal from noise.

2. **API key findings need validation.** Finding a key in an APK is trivial. Understanding what it actually grants access to — SDK-level config vs REST API vs nothing — requires testing.

3. **The most impactful finding came from probing, not scanning.** The Braze internal schema disclosure (predictive model names, test artifacts like `chipotle_barcode` and `gdpr_conesnted`) was discovered by the agent calling the Braze API, not by apksaw's pattern matcher.

4. **Hinge has reasonable security for a dating app.** The app is not debuggable, disables backup, uses system-only CA trust, and properly restricts 2 of 3 Google API keys. The main gaps are the unrestricted Geocoding key, missing certificate pinning, and missing Braze SDK Authentication.
