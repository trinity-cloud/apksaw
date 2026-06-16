# Fuzzing Tools (v1 + v2)

Two parallel modules that exercise exported Android components against
malformed inputs. **v1** (`fuzzer.py`) drives a static 13-row payload
dictionary for components, deep links, and content providers. **v2**
(`fuzzer_v2.py`) turns the same ideas into **per-APK grammars** harvested
from bytecode + AndroidManifest analysis, and adds a headline blind-SQLi
autominer that drives four oracle modes against content providers whose
queries / updates / inserts / deletes are reachable from any exported
activity.

Together these six tools follow the session-first pattern (`session_id` as
the first argument) and return structured `{"status": ..., "data": ...,
"consent_required": true}` dicts.

## Target posture

Confirmable, logcat-aware, redact-friendly fuzzing on a **non-rooted**
target (e.g. a Pixel 10a with USB debugging enabled). Two
structurally-identical execution pipelines (`fuzzer.py:_run_test` and
`fuzzer_v2.py:run_adb_with_evidence`) loop the device:

```
  clear_logcat → adb shell <one probe> → sleep(N) → capture_logcat → classify
```

The classification oracle (**`_check_logcat_for_crash`**) is *strict in two
ways* to avoid the false-positive trap that the v1 naïve matcher caught:

1. **Relevance filter.** A line counts only if it (a) contains the target
   `package` name *or* (b) matches the panic-prefix regex
   `FATAL EXCEPTION|ANR in |Force finishing`. Synthetic `SecurityException`
   lines that don't mention the package get filtered as `no_crash`. The
   realistic ActivityManager format
   (`Permission Denial: opening provider com.foo.bad ... java.lang.SecurityException`)
   is correctly classified because it carries the package name.

2. **Severity mapping.** Each classified result maps to a severity label
   (`crash → critical`, `anr → high`, `exception → high`,
   `security_exception → medium`, `no_crash → info`).

3. **Redaction.** `redact_text()` masks `Authorization: Bearer`, JWTs, and
   Google `AIza…` API keys in stdout so they never land verbatim in chat
   logs; the function is applied to all returned adb output.

Confirm-gate contract — same as `exploit_gen.py`:

* `drive=True` (or `execute=True`), `confirm=False` → `{"status":
  "requires_consent", "consent_required": true, "data": {"plan_only":
  true}}` with **zero side effects**.
* `drive=True`, `confirm=True` AND a connected device → real execution
  through `run_adb_with_evidence` returning `{command_exit_code,
  adb_stdout, adb_stderr, result, severity, crash_log, screenshot}`.
* `confirm=True` with no device → `"status": "error"`,
  `"message": "No ADB device connected."`.

## v1 → v2: what changed

| Surface                 | v1 (static)                                              | v2 (app-aware)                                                     |
|-------------------------|----------------------------------------------------------|--------------------------------------------------------------------|
| Intent extras           | 13-row string-key dictionary (`--es cmd`, `--es token`) | Per-component bytecode walk: `getStringExtra` / `getIntExtra` / `getParcelableExtra` call-sites, const-string key recovered from the immediately preceding `const-string` instruction |
| Deep-link URIs          | 13-row scheme dictionary (`https`, `geo:`, `intent:`, …) | Manifest `<intent-filter> <data android:scheme="…" android:host="…" />` + `getQueryParameter` keys from dex |
| ContentProvider probes  | Boolean tautology probe only (`1=1`, `1=1 OR 1=1`, …) | Blind-SQLi autominer with **4 oracle modes** (boolean / UNION / error / time) over **real table + column** names harvested from `SQLiteDatabase.rawQuery`/`execSQL`/`query`/`update`/`insert`/`delete` call-sites and `CREATE TABLE` strings |

The headline deliverable across the v1→v2 jump is that payloads now
reference **the app's own surface**, not a generic dictionary — so a
boolean oracle payload against a Hinge-derived APK says `WHERE users.email
= '…'` instead of the v1 static `'1=1 OR 1=1'`.

## Tool inventory

| Tool                            | Module | Confirm | Drives                                          | Notes                                                    |
|---------------------------------|--------|---------|-------------------------------------------------|----------------------------------------------------------|
| `fuzz_exported_components`      | v1     | always  | Intent fuzzing (static 13-row extras)           |                                                          |
| `fuzz_deep_links`               | v1     | always  | Deep-link fuzzing (static 13-row URI schemes)   |                                                          |
| `fuzz_content_providers`        | v1     | always  | Content provider probe (static SQLi patterns)   |                                                          |
| `fuzz_exported_components_v2`   | v2     | required| Intent fuzzing (bytecode-derived extras)        | tool-table grows from one to one-per-component          |
| `fuzz_deep_links_v2`            | v2     | required| Deep-link fuzzing (manifest-derived URIs)       | tool-table grows from one to one-per-filter             |
| `automine_blind_sqli`           | v2     | required| Blind SQLi autominer                            | **headline**: boolean / union / error / time oracles    |

Both `fuzzed_*_v2` and `automine_blind_sqli` honour the same consent gate
that `exploit_gen.py` does — `_require_consent(drive, execute, confirm)` is
shared (re-implemented, not imported, per project convention).

## v1 tools

### `fuzz_exported_components`

Send malformed `am start` / `service call` / `am broadcast` commands to
every exported activity / service / receiver and classify each on logcat.

```
fuzz_exported_components(session_id="...", package_name="com.foo.app")
→ {"status": "ok", "data": {"tests_run": N, "crashes": [...],
                            "exceptions": [...], "anrs": [...]}}
```

Automatically requires a connected ADB device — `_require_device()` raises
on disconnect.

### `fuzz_deep_links`

Walk every activity's `<intent-filter>` and probe each registered URI
scheme / host / path with a static dictionary of well-known
deep-link patterns.

```
fuzz_deep_links(session_id="...", package_name="com.foo.app")
→ {"status": "ok", "data": {"links_probed": N, "crashes": [...], ...}}
```

### `fuzz_content_providers`

Walk every exported provider, build a `_build_provider_tests` table of
boolean tautologies, `SELECT … FROM sqlite_master--`, path-traversal,
oversized URIs, and one insert / update / delete variant.  Each probe is
fired through adb shell `content query|insert|update|delete` and
classified on logcat.

```
fuzz_content_providers(session_id="...", package_name="com.foo.app")
→ {"status": "ok", "data": {"total_tests": N,
                            "results": [...],
                            "vulnerable_components": [...]}}
```

If `output` contains `Row:` text from `content query`, the v1 result type
is escalated to `data_exposed`/`high` — a heuristic that v2 replaces with
real per-table inference (see below).

## v2 tools

### `fuzz_exported_components_v2`

For each exported activity / service / receiver, walk the class methods
looking for `getStringExtra` / `getIntExtra` / `getParcelableExtra`
call-sites. Recover the const-string key from the immediately preceding
`const-string` bytecode instruction. Each discovered key becomes a `--es`
/ `--ei` / `--ez` token in the `am start` command, keyed to the
component's *own semantics* — never a generic string-key dictionary.

```
# Dry-run: zero side effects, returns the grammar-derived plan
fuzz_exported_components_v2(session_id="abc123",
                           component_name="com.foo.app.MainActivity",
                           max_payloads=8)

→ {
    "status": "ok",
    "consent_required": true,
    "data": {
      "payloads": [
        {
          "name": "primary_am_start::com.foo.app.MainActivity",
          "component": "com.foo.app.MainActivity",
          "tokens": ["shell", "am", "start", "-n",
                     "com.foo.app/com.foo.app.MainActivity",
                     "--es", "cmd", "apksaw_cmd",
                     "--es", "token", "apksaw_token"],
          "technique": "bytecode-derived-extras",
          "extras": [
            {"key": "cmd", "value": "apksaw_cmd", "type": "string"},
            {"key": "token", "value": "apksaw_token", "type": "string"},
          ]
        }
      ],
      "executed": []
    }
}
```

Falls back to one place-holder `am start` payload per exported
component when no extras are detectable, so plan-mode is **never empty**.

### `fuzz_deep_links_v2`

Reads every exported activity's `<intent-filter> <data>` blocks plus the
activity's own `getQueryParameter` call-sites to derive the URI scheme /
host / path / expected query parameters. Each URI suite gets appended
placeholder query parameters and a `VIEW` action.

```
# Dry-run: zero side effects, returns manifest-derived URI suites
fuzz_deep_links_v2(session_id="abc123", max_payloads=8)

→ {
    "status": "ok",
    "consent_required": true,
    "data": {
      "suites": [
        {
          "component": "com.foo.app.MainActivity",
          "uri": "https://deeplink.example.com/v1/foo?id=apksaw_id",
          "tokens": ["shell", "am", "start",
                     "-a", "android.intent.action.VIEW",
                     "-d", "https://deeplink.example.com/v1/foo?id=apksaw_id",
                     "-n", "com.foo.app/com.foo.app.MainActivity"],
          "scheme": "https",
          "host": "deeplink.example.com",
          "query_keys": ["id"],
          "technique": "manifest-derived-deeplink"
        }
      ],
      "executed": []
    }
}
```

When no custom `<data>` block is present (only the default LAUNCHER
filter), the tool emits a single fallback URI using the package as host
and `/` as path. Plan-mode is therefore **never empty**, matching the v2
graceful-fallback invariant.

### `automine_blind_sqli` — **headline Phase 3 tool**

Walk the dex / string pool for SQL-relevant strings, assemble a coarse
schema (tables + columns), apply the
`apksaw.utils.taint_lite.is_reachable_from_exported` reachability filter,
and emit payloads keyed to the **app's actual surface**.

Four oracle modes — every one is reachable from the same
`extract_provider_schema` output (Phase 8 SARIF seeds off this too):

| `oracle`  | What it emits                                                                                       | Notes                                                                                                                            |
|-----------|-----------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| `boolean` | `WHERE <table>.<col> = '<inj>'` per reachable column                                                | always ≥1 payload — graceful fallback (`?<inj>=?<inj>`) when schema is empty                                                    |
| `union`   | `1=0 UNION SELECT <col1>, <col2>, … FROM <table>--`                                                | capped at 6 columns per SQLite's `UNION SELECT` limit (a 7th column is silently dropped by `sqlite3_step`)                      |
| `time`    | Heavy-computation via `RANDOMBLOB(200000)` / `LIKE '%'`/`GLOB`                                      | **rejects `SLEEP()` and `BENCHMARK()`** (MySQL only — silently no-op on Android); uses SQLite-compatible primitives only       |
| `error`   | `CAST((SELECT <col> FROM <table> LIMIT 1) AS INT)`                                                  | forces a typed-cast exception whose message reveals the column / table name in logcat                                            |

```
# Dry-run against the first exported ContentProvider — no ADB calls
automine_blind_sqli(session_id="abc123", authority="",
                    oracle="boolean", max_payloads=8)

→ {
    "status": "ok",
    "consent_required": true,
    "data": {
      "provider": "com.foo.app.provider",
      "oracle":   "boolean",
      "schema":   {"tables": [{"name": "users",
                                "columns": ["id", "email", "password"]}],
                   "columns": ["id", "email", "password"],
                   "source": "static_analysis"},
      "payloads": [
        {
          "name": "bool_users_id",
          "oracle": "boolean",
          "where_clause": "users.id = '<inj>'",
          "cmd": ["shell", "content", "query",
                  "--uri", "content://com.foo.app.provider/users",
                  "--where", "users.id = '<inj>'"],
        },
        ...
      ],
      "executed": []
    }
}
```

| Method-sink enumeration (for `extract_provider_schema`'s reachability filter)                                                 |
|-----------------------------------------------------------------------------------------------------------------------------|
| `SQLiteDatabase.rawQuery`                                                                                                    |
| `SQLiteDatabase.execSQL`                                                                                                     |
| `SQLiteDatabase.query` / `update` / `insert` / `delete`                                                                      |
| `ContentProvider.query` / `update` / `insert` / `delete`                                                                     |
| String-pool `SELECT … FROM`, `INSERT INTO`, `UPDATE`, `DELETE FROM`, `CREATE TABLE`, `CREATE TRIGGER` / `CREATE VIEW` patterns |
| `adb_create_table` / `db_create_table` strings in the string pool                                                            |

Unknown `oracle=` → `"status": "error"`,
`"message": "Unknown oracle … Choose one of ['boolean', 'error', 'time', 'union']."`. Plan is
**never emitted** for unknown oracles.

### Confirm-mode execution envelope

When both `drive=True` AND `confirm=True` (and a device is connected),
every payload's `cmd` is fired through `run_adb_with_evidence(cmd_tokens,
package=pkg, timeout_s=20, screenshot_label=..., workspace=...)`.
The returned `data.executed[i]` looks like:

```
{
  "command": "adb shell content query --uri ... --where users.email = '<inj>'",
  "command_exit_code": 0,
  "adb_stdout":  "",
  "adb_stderr":  "",
  "result":     "no_crash",                  # or "crash" / "exception" / etc.
  "severity":   "info",                       # mapped from SEVERITY_MAP
  "crash_log":  "",
  "screenshot": "/…/workspace/screenshots/sqli_boolean_00.png"
}
```

## Using the v2 grammar extractors directly

The internal extractors are addressable for the Phase 8 SARIF / reporting
pipeline (and for tests):

| Function                     | Returns                                                                                                                  |
|------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `extract_provider_schema`    | `{"tables":[{"name","columns"}], "columns":[...], "source":"static_analysis"}`; honours `is_reachable_from_exported`    |
| `extract_extras_for_component` | `[{"key","value","type"}, ...]` — bytecode-derived extras for an FQN activity / receiver; `[]` if class is missing      |
| `extract_deeplink_params`    | `{"scheme","host","path","actions","categories", ...}` — first `<intent-filter>` `<data>` block for an FQN                |

`extract_provider_schema` is the foundation that turns the 13-row static
table into a 5-row dynamic table the oracles drive; the same output is
fed into Phase 6 (`api_key_validator`) and Phase 8 (`sarif_report`).

## Crash-oracle classification table

| `result_type`        | Severity   | Trigger regex (case-insensitive)                             |
|----------------------|-----------|--------------------------------------------------------------|
| `crash`              | `critical`| `FATAL EXCEPTION` / `Process.*has died` / `Force finishing`  |
| `anr`                | `high`    | `ANR in ` / `Application Not Responding`                      |
| `exception`          | `high`    | `java.lang.(NullPointer\|ClassCast\|IllegalArgument\|IllegalState\|Runtime\|NetworkOnMainThread)Exception` |
| `security_exception` | `medium`  | `java.lang.SecurityException`                                |
| `no_crash`           | `info`    | nothing matched (and not panicking)                          |

Lines pulled into the matcher must (a) mention the `package` name *or*
(b) match the panic-prefix regex
`FATAL EXCEPTION|ANR in |Force finishing`. The `_check_logcat_for_crash`
test fixtures use realistic ActivityManager `Permission Denial: opening
provider …` lines for `security_exception` — synthetic lines that
substitute the package name with a generic "totally unrelated" string
are rejected as `no_crash` (the relevance filter guard).

## Redaction patterns applied to all returned text

| Pattern                                              | Replaced with        |
|------------------------------------------------------|----------------------|
| `Authorization\s*:\s*bearer\s+<…>` (case-insensitive)| `[REDACTED]`         |
| `bearer\s+<…>` (loose, case-insensitive)              | `[REDACTED]`         |
| JWT triple `<header>.<payload>.<signature>`         | `[JWT_REDACTED]`     |
| `AIza[0-9A-Za-z_\-]{35}` (Google API keys)            | `[GOOGLE_KEY_REDACTED]` |

## Relationship to the other modules

| Module       | Role                                                      |
|--------------|-----------------------------------------------------------|
| `exploit_gen`| **PoC replay / synthesis** against the *exploit* stage    |
| `frida_gen`  | **Generates** Frida scripts as `.js` text files           |
| **v1 fuzzer**| **Static-table fuzzing** of components, links, providers  |
| **v2 fuzzer**| **App-aware fuzzing** + **blind-SQLi autominer** (4 oracles) |

The typical end-to-end flow is:

```
load_apk → scan_all_v2
  → repackage_with_gadget(confirm=True)            (Phase 1, runtime)
  → automine_blind_sqli        (drive=False, schema feed; drive=True, oracle loop)
  → fuzz_exported_components_v2 (drive=True, on-device intents)
  → fuzz_deep_links_v2         (drive=True, on-device deep links)
```

v2 is implemented in `src/apksaw/tools/fuzzer_v2.py`; the v1 module
remains alongside it for one release cycle. The headline change — payloads
sourced from per-APK bytecode + manifest analysis rather than a static
dictionary — is the single largest drop in false-positive rate across the
fuzzing surface introduced since Phase 1.
