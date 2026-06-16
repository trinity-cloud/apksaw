# Case Study: Kimi AI (com.moonshot.kimichat) Security Audit

> **Disclosure status.** This audit was performed on a publicly distributed release build for security research. Hardcoded keys and other sensitive identifiers have been **redacted** in this writeup. These findings have **not yet been disclosed** to the vendor — they are published to document apksaw's workflow, not as a coordinated advisory. If you audit an app you do not own, follow the vendor's responsible-disclosure or bug-bounty process before publishing anything. apksaw is designed first for auditing apps **you own**, where this question doesn't arise.

**Target:** Kimi v2.6.7 (build 322), Android AI chat app by Moonshot AI
**Device:** Pixel 10a, Android 16, non-rooted, Canadian SIM
**Time:** Approximately 4 hours from APK pull to final report

## Objective

Audit the Kimi Android app using apksaw to assess security posture and third-party SDK data practices. Kimi is an AI assistant built by Moonshot AI, a Chinese AI company. Users share personal questions, documents, code, and files with the AI — making data handling practices especially relevant.

## How apksaw was used

### Phase 1: Initial scan

```
> Pull the Kimi app from my phone. Run a full security scan,
  extract all URLs, and check for hardcoded secrets.
```

apksaw produced **36 findings** (5 critical, 24 high, 7 medium) and extracted 301 URLs. The secrets scanner returned 18,125 hits — but analysis revealed all were false positives from the entropy detector matching Java class names like `ActivityResultRegistry` and `AES/CBC/PKCS7Padding`. Zero real API keys or credentials were embedded.

This was itself a notable finding: unlike Hinge (which had hardcoded API keys), Kimi properly keeps credentials server-side.

### Phase 2: Deep investigation with 10 parallel agents

Each agent used apksaw to decompile and analyze a specific attack surface:

1. **WebView exploit chain** — The scanner flagged `setAllowUniversalAccessFromFileURLs` as critical. `decompile_class` on `KimiWebView` revealed it was actually called with `false` (0), not `true`. The scanner matched the method name but didn't check the boolean argument. **False positive corrected.**

2. **TLS bypass in JiGuang push SDK** — `decompile_class` on 3 custom TrustManagers and 5 HostnameVerifiers. Only 2 TrustManagers were actually vulnerable (one with an empty `checkServerTrusted` body, one that catches and swallows all validation exceptions). All 5 HostnameVerifiers implemented strict equality checks. **2 of 8 classes vulnerable.**

3. **Deep link attack surface** — `search_strings` mapped 35 `kimi://` routes. `decompile_class` on `ExternalLinkActivity` and the router classes revealed multiple vectors: a potential token leak via WeChat Mini Program deep links (code-confirmed but requires WeChat to test), an auth bypass via null caller check on `AuthActivity3`, and open WebView navigation. **Multiple findings, partially testable.**

4. **Third-party SDK inventory** — `list_classes` with package filters identified 12 SDKs with network access: Volcengine analytics (ByteDance infrastructure), JPush/JiGuang, Alipay, WeChat Pay, three Chinese carrier auth SDKs (China Mobile, Unicom, Telecom), Tencent LiteAV audio, Xiaohongshu sharing, AppsFlyer, Firebase, and Google Play Billing.

5. **MCP server discovery** — `search_strings` found `http://localhost:8931/mcp`. `decompile_class` on the surrounding code (`xa.B`, `xa.F`, `td.A`) revealed a complete MCP (Model Context Protocol) client/server implementation using the `2025-06-18` protocol version, gated by a hardcoded `false` flag (`y8.e.e()` always returns 0). The client code has no authentication — the API key from SharedPreferences is never sent in HTTP headers. **Disabled but shipping in production.**

### Phase 3: Validation on device

The agent tested findings on the live Pixel 10a:

- **WebView URL injection: confirmed** — `kimi://page/webview?url=http://attacker.com` opens arbitrary URLs in Kimi's WebView. The JS bridge (`ipc`) is NOT attached for non-Kimi domains (domain allowlist works correctly). This is phishing/UI spoofing, not code execution.
- **Token theft via WeChat Mini Program: could not test** — the `kimi://action/wxminiprogram?path=<url>&need_access_token=true` route requires WeChat to be installed. Our test device (Canadian SIM, no WeChat) could not trigger the code path.
- **Payment bypass: disproven** — all three payment systems (Google Play Billing, Alipay, WeChat Pay) have server-side verification via gRPC `GetSubscription`. No client-side-only payment bypass exists.
- **File SEND to Kimi: confirmed** — any app can send a `content://` URI via `ACTION_SEND` to `ExternalLinkActivity`, which uploads the file to Kimi's servers. Limited by Android's scoped storage (attacker app can only share files it already has access to).

## What apksaw provided vs. what the agent provided

### What apksaw made possible

Kimi has 30,000+ classes with heavy R8 obfuscation. Without apksaw, the AI agent cannot read binary DEX bytecode. apksaw translated classes on demand into Java pseudocode the agent could reason about.

The `find_method_usage` and `get_xrefs_from` tools were critical. When the scanner flagged `addJavascriptInterface`, the agent traced cross-references to find the JS bridge is gated by `dc.N.c(url)` — a domain allowlist check. That chain of tool calls (find call site, decompile caller, check arguments, trace data source) is what separates a useful finding from noise.

### What apksaw got wrong

The scanner's most prominent false positive was the WebView finding. Flagging `setAllowUniversalAccessFromFileURLs` as critical without checking the boolean argument is a fundamental limitation of pattern-based scanning. This was the "headline critical" that turned out to be nothing. The v2 scanner with taint-lite argument inspection was built specifically to address this class of false positive.

### What the agent provided beyond apksaw

- **Correcting the tool's mistakes**: The scanner's "critical WebView exploit chain" was a false positive. The agent caught this by reading the decompiled constructor and seeing the `0` argument.
- **Business context**: Understanding that Volcengine analytics classes in the app represent Moonshot AI's choice of analytics provider (ByteDance's cloud infrastructure), not a corporate relationship between the two companies.
- **Geographic threat modeling**: Recognizing that Chinese carrier auth SDK findings apply only to users with Chinese SIM cards. The CMIC SDK checks MCC/MNC and exits immediately for non-Chinese operators.
- **Nuanced privacy assessment**: Documenting what data flows where without overstating the implications. Volcengine analytics collects device identifiers — so does every analytics SDK. The relevant question is scope and consent, not mere presence.

## Findings (confirmed with evidence)

### Security findings (code-confirmed)

1. **JiGuang VerifySDK TLS bypass** — `cn.jiguang.verifysdk.i.o$1.checkServerTrusted()` accepts any certificate (checks non-null only, no chain validation). `cn.jiguang.verifysdk.i.t` catches and swallows all TrustManager exceptions. Affects phone number verification flow. Exploitable via network MITM.

2. **Hardcoded AES key** (`yuNt…[redacted]`) in class `LP/k` — used as a fallback key for AES/ECB/PKCS5Padding decryption of WebView JavaScript assets. The key is in the APK and the algorithm is ECB mode.

3. **AuthActivity3 null-caller bypass** — `getCallingActivity()` returns null when started via `startActivity()` (not `startActivityForResult()`), and the null check returns `true`, bypassing certificate verification of the calling app.

4. **11 exported components without permission guards** — including payment result callbacks (`PayResultActivity`, `AlipayResultActivity`), dev artifacts (`SampleActivity`, `PreviewActivity`), and JPush activities with empty `taskAffinity`.

5. **Unencrypted chat database** — `DBChatMessage` table stores conversation history (user prompts and AI responses) in plaintext SQLite. No SQLCipher. Requires root to access.

6. **Auth tokens in plaintext SharedPreferences** — `x-auth-token`, `access_token`, `refresh_token` stored without EncryptedSharedPreferences or Android Keystore. Requires root.

7. **Voice recordings on external storage** — Tencent LiteAV SDK writes PCM/WAV audio files to external storage, readable by any app with storage permission.

8. **Deprecated SHA1PRNG with low-entropy re-seeding** — nonce generator periodically seeds with `System.currentTimeMillis()` delta (~30s intervals).

9. **Dev endpoints in production binary** — `kimi-api-228-2293-default.dev.kimi.team`, `kimi-apiv2.dev.kimi.team`, `kimi-out.msh.team`, and `http://localhost:8931/mcp`.

### Privacy observations (documented, not claimed as vulnerabilities)

10. **12 third-party SDKs with network access** embedded in the app, including Volcengine analytics (ByteDance's cloud platform), JPush, Alipay, WeChat, three Chinese carrier SDKs, Tencent audio, and Xiaohongshu.

11. **Volcengine analytics collects device identifiers globally** — IMEI, ICCID, MAC address, device serial, OAID, GPS coordinates, WiFi BSSID. Collection runs regardless of SIM country. The `forbid_report_phone_detail_info` flag defaults to `false`.

12. **Crash dumps uploaded to Volcengine Singapore servers** (`apmplus.ap-southeast-1.volces.com`) — core dumps and heap dumps may contain in-memory conversation fragments. No redaction mechanism was observed in the upload code.

13. **Disabled MCP feature** — complete MCP client/server with protocol version `2025-06-18` ships in the production APK, gated by `y8.e.e()=false`. The client implementation has no authentication (API key from SharedPreferences is never included in HTTP requests).

### What we could NOT prove

- **Token theft via `need_access_token=true`**: The code path exists in the decompiled router but requires WeChat to be installed. Could not test on our device.
- **Conversation data exfiltration**: The chat database is encrypted by Android's app sandbox. Without root, we could not read conversation contents.
- **Volcengine receiving conversation content**: We confirmed device identifiers are collected. We did NOT confirm that conversation text is sent to Volcengine — only that crash dumps (which could contain conversation fragments in memory) are uploaded.

### Disproven findings

- **WebView universal file access**: `setAllowUniversalAccessFromFileURLs(false)` — scanner false positive
- **Runtime.exec() command injection**: All 5 call sites execute hardcoded `getprop` for ROM detection
- **Payment bypass**: All three payment systems server-verified via gRPC
- **5 of 8 TLS-related classes**: Properly implemented (strict hostname verification, real certificate pinning in JGTrustManager)
- **Hardcoded API keys**: Zero found — Moonshot properly keeps credentials server-side

## Lessons learned

1. **False positives matter as much as true positives.** Reporting the WebView finding as "critical" without verification would have been wrong. The tool found the method call; the agent read the argument. This distinction is the entire value proposition of pairing automated scanning with AI-driven analysis.

2. **Geographic context changes the threat model.** The TLS bypass in JiGuang's carrier verification SDK is critical for users authenticating via Chinese mobile operators. For a Canadian user on Rogers, the code path never executes — the SDK checks MCC/MNC and returns error `200010` ("unable to identify SIM card") immediately.

3. **Privacy findings require precision.** Moonshot AI chose to use ByteDance's Volcengine as their analytics and APM provider. This is a business decision — the same way a US company might choose Google Analytics or Datadog. Documenting what data flows to Volcengine is legitimate and useful. Implying that "Kimi sends your data to ByteDance" as if there's a surveillance relationship would be inaccurate.

4. **Disabled features are still findings.** The MCP client/server code with no authentication is harmless today but becomes a local privilege escalation the moment the feature flag is flipped. Shipping it in the production binary — with `2025-06-18` protocol version — signals an imminent launch.

5. **No hardcoded API keys is a positive finding worth noting.** Unlike many apps, Kimi keeps its backend credentials entirely server-side. This is good security practice and means the primary attack surface is the app's component architecture (exported activities, deep links) rather than embedded secrets.
