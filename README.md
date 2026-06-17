<p align="center">
  <img src="docs/apksaw-logo.png" alt="Logo" width="500">
</p>

<p align="center">
  <h1 align="center">apksaw</h1>
  <p align="center"><strong>Audit your Android app's security — in plain English.</strong></p>
  <p align="center">113 MCP tools. Point any MCP coding agent at your APK and ask it to find the bugs.</p>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#what-you-can-do">What You Can Do</a> &bull;
  <a href="#how-it-works">How It Works</a> &bull;
  <a href="#for-security-engineers">For Security Engineers</a> &bull;
  <a href="#case-studies">Case Studies</a>
</p>

---

**apksaw** is an [MCP](https://modelcontextprotocol.io/) server that turns any MCP-capable coding agent — Claude Code, Cursor, Cline, Windsurf, Claude Desktop, and others — into a mobile security auditor. You talk to it in natural language; it decompiles your app, scans for vulnerabilities, **verifies which findings are real**, and tells you how to fix them.

It exists because of two hard facts:

- **Mobile security expertise is scarce and expensive.** Most teams ship an Android app without anyone who can audit it — until an app-store rejection, a customer security questionnaire, or a breach forces the issue.
- **An LLM literally cannot read Android bytecode.** Your agent is a strong reasoner that's blind to compiled DEX. apksaw is the eyes and hands: it translates the APK into decompiled Java, cross-reference graphs, and structured data the agent can actually reason about — then runs the scanners, fuzzers, and proofs.

You bring the app and the questions. The agent brings the reasoning. apksaw bridges the gap.

### Who it's for

**You build Android apps.** Run a real security audit on your own app before someone else does — no specialist to hire, no toolchain to assemble. Ask *"find the security bugs in my app,"* fix what's real, and confirm the fix actually closed the hole. Because it's **your** app, you have authorization by definition, and you bring the one thing an outside auditor never has: you know what your code is *supposed* to do. That makes verification faster and the results more trustworthy.

**You do security for a living.** It's the full offensive toolkit — JADX, Frida, app-aware fuzzing, patch-diffing, YARA, native analysis — wired into one agent loop so the agent verifies its own findings instead of handing you a wall of raw alerts. [Jump to the details ↓](#for-security-engineers)

> **apksaw is a force multiplier, not a replacement for judgment.** In real-world testing the automated scanner produced a **65% false-positive rate**. The difference is that the agent doesn't stop at the scanner — it decompiles the surrounding code, checks the actual argument values, and traces data flow to tell you which findings are real. You get *verified* results, not noise. apksaw is the microscope; the agent (paired with your knowledge of your own code) is the pathologist.

---

## Quick Start

```bash
git clone https://github.com/trinity-cloud/apksaw.git
cd apksaw
uv sync
```

Add it to your agent over MCP's stdio transport. **Claude Code:**

```bash
claude mcp add apksaw -- uv run --directory /path/to/apksaw apksaw
```

**Any other MCP client** (Cursor, Cline, Windsurf, Claude Desktop): point it at the stdio command `uv run --directory /path/to/apksaw apksaw`. See [Installation](docs/installation.md) for per-client config snippets.

Restart your agent — all 113 tools appear automatically. Then just talk to it:

```
> Pull my app from the connected device, run a full security scan,
  and verify each finding by decompiling the relevant code.
```

## What You Can Do

Every example below is plain English you type to your agent. The pattern that matters: **find → confirm it's real → fix → prove it's closed.**

#### Audit your own app
```
> Pull com.myco.app from my phone and run a full security scan.
  For each finding, decompile the relevant code and tell me whether
  it's a real bug or a false positive — and why.
```

#### Prove your fix actually worked
```
> I fixed the exported-activity issue and rebuilt. Diff the new APK
  against the old one and confirm the vulnerability is really gone.
```

#### See the real impact, on your own device
```
> This finding says my deep link can be hijacked. Build a proof-of-concept,
  run it on my test device, and screenshot what actually happens.
```

#### Audit your secrets and dependencies
```
> Extract every API key, endpoint, and third-party SDK from my APK.
  Tell me which keys are exposed and what each SDK can access.
```

#### Reconstruct what a security patch fixed
```
> Here are v1.0 and v2.0 of my app. Find what security patches v2.0 added,
  then tell me which of those bugs are still exploitable in v1.0.
```

#### Check your hardening
```
> Detect what anti-tampering and SSL-pinning defenses my app has,
  show me how they'd be bypassed, and tell me what's missing.
```

## How It Works

```
You (natural language)
  │
  ▼
Your coding agent  (Claude Code · Cursor · Cline · Windsurf · …)
  │   MCP stdio transport
  ▼
apksaw MCP Server
  │
  ├─ Androguard ──> DEX parsing, decompilation, cross-references
  ├─ JADX ────────> High-quality Java decompilation
  ├─ LIEF ────────> Native .so ELF analysis
  ├─ Capstone ────> ARM/ARM64 disassembly
  ├─ YARA ────────> Pattern-based detection
  ├─ ADB ─────────> Device interaction, APK extraction
  ├─ apktool ─────> Gadget injection and repackaging
  └─ Frida ───────> Runtime hooks and evidence capture
```

The 113 tools split into two kinds:

- **Infrastructure tools give the agent hands.** Decompiled Java, cross-references, parsed manifests — the structured data the agent reads and reasons about. (An LLM can't read DEX bytecode; this is how it sees.)
- **Automation tools do the work.** The fuzzer fires malformed intents and watches logcat; the scanners run taint analysis; the diff engine reverse-engineers what a patch fixed. One call, a conclusion — not raw data to interpret.

📖 **Full inventory:** [Tool Reference](docs/tool-reference.md) (all 113 tools) · **Internals:** [Architecture](docs/architecture.md)

## For Security Engineers

Yes — under the hood this is JADX + apktool + Frida + a fuzzer + YARA, tools you already own. The wedge isn't the tools; it's that the agent drives them in **one loop and verifies its own findings**. The scanner flags `addJavascriptInterface` as critical; the agent traces the xref, decompiles the caller, reads the argument, and finds it's gated by a domain allowlist — without you switching windows. That verification step is exactly the 65%-false-positive problem, automated.

What's in the box beyond the basics:

- **App-aware fuzzing v2** — per-APK grammars derived from bytecode + manifest; blind-SQLi autominer across boolean / UNION / error / time oracles
- **Patch-diffing → n-day reconstruction** — `analyze_security_patches`, `find_vulnerability_window`, `poc_old_version` replay PoCs against the old build with on-device evidence
- **Runtime on non-rooted devices** — Frida gadget repackaging, live Bearer-token / crypto-key capture, targeted SSL-pinning bypass generation
- **Anti-analysis** — detection across 7 defense categories with targeted bypass-script generation
- **Native + API surface** — `.so` analysis (LIEF + Capstone), protobuf/gRPC schema reconstruction, endpoint and auth-interceptor mapping
- **Native exploit pipeline (self-audit only)** — ROP gadget discovery over `.text` (`find_rop_gadgets`), JNI hook generation from `Java_*` exports (`generate_jni_hook`), and on-device Frida execution (`execute_native_hook`) with a confirm-gated dry-run posture. The compose chain `analyze_native_lib → generate_jni_hook → execute_native_hook` closes the static→dynamic verify loop for apps that push auth, crypto, and license validation into native `.so` code.

See the [Tool Reference](docs/tool-reference.md) for all 113 tools and [Architecture](docs/architecture.md) for the module layout.

## Case Studies

apksaw has been used in real security research. These document findings, false positives, and the limits of automation.

> These audits were run against **publicly distributed third-party apps** for research. Live credentials are redacted and each writeup carries a disclosure note. When you audit an app **you own**, none of that applies.

### [Hinge (co.hinge.app)](docs/case-studies/hinge-audit.md)

Match Group's dating app. Scanner produced 20 findings — **13 were false positives** (65%). The agent verified each by decompiling the surrounding code, then tested the survivors. The scanner found candidates; the agent separated signal from noise.

### [Kimi AI (com.moonshot.kimichat)](docs/case-studies/kimi-audit.md)

Moonshot AI's chat assistant. Scanner flagged a "critical WebView exploit" — the agent decompiled the constructor and found the dangerous flag was actually `false`. The scanner matched the method name; it didn't read the argument. That single catch is the entire value proposition.

## Requirements

- Python 3.10+
- ADB installed and on `$PATH`
- Java 11+ (for JADX/apktool)
- Android build tools (`zipalign`, `apksigner`) for runtime gadget repackaging
- A connected Android device or an APK file
- Frida Python packages and `libfrida-gadget.so` for runtime execution

JADX and apktool are **downloaded automatically** on first use to `~/.apksaw/tools/`.

## Philosophy

1. **Audit what you own.** apksaw is built first for developers auditing their own apps — where you have authorization and the context to verify findings fast.
2. **Verified results, not noise.** The scanner is wrong 65% of the time. The agent reads the code and tells you which findings are real. That loop *is* the product.
3. **Honest about limitations.** The false-positive rate is documented in the case studies, not hidden. apksaw is the microscope, not the pathologist.

## License

MIT
