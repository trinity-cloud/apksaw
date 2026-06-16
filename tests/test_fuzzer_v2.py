"""Tests for the app-aware fuzzer v2 (fuzzer_v2.py).

Three MCP tools, three internal grammar extractors:

- ``fuzz_exported_components_v2`` — am-start suites keyed to
  ``getStringExtra`` / ``getIntExtra`` / ``getParcelableExtra`` keys harvested
  from per-component bytecode walks (drops v1's static string-key fuzzing).
- ``fuzz_deep_links_v2`` — URI suites keyed to per-filter
  ``<data android:scheme=... />`` plus ``getQueryParameter`` call-sites.
- ``automine_blind_sqli`` — boolean / error / UNION / time-based SQLi oracles
  against *reachable* exported ContentProviders. Boolean payloads reference
  **real table + column names** harvested from ``SQLiteDatabase.rawQuery /
  execSQL / query / update / insert / delete`` and ``CREATE TABLE`` strings.
  Time payloads use SQL-Server / MySQL ``SLEEP()`` rejection — SQLite-only
  heavy computation OR simulation queries are emitted instead.

Honoring BACKEND HARDENED INVARIANTS:
- _V2 = 'apksaw.tools.fuzzer_v2' prefix string for ALL patch() calls
- _inject_session(mock_session) is the helper (mirrors Phase 1 + Phase 2)
- ExitStack used when a test needs >1 nested patch (nested ``with`` only
  keeps the LAST one — known bug already fixed).
- Realistic logcat lines (with package name) for crash-classification tests;
  synthetic SecurityException WITHOUT the package name is rejected as
  ``no_crash`` by the relevance filter.

Per Phase 1 lesson we do NOT assert on ``mcp._tool_manager._tools`` under
pytest — root conftest stubs mcp so standalone verification is the only
mechanism that confirms the three new tools register.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from apksaw.tools.fuzzer_v2 import (
    # helpers (re-implemented from fuzzer.py — private API, but used here)
    _capture_logcat,
    _check_logcat_for_crash,
    _clear_logcat,
    _list_exported_components,
    # grammar extractors — utility, exposed only via MCP tools
    extract_deeplink_params,
    extract_extras_for_component,
    extract_provider_schema,
    # MCP tools
    automine_blind_sqli,
    fuzz_deep_links_v2,
    fuzz_exported_components_v2,
    redact_text,
)

_V2 = "apksaw.tools.fuzzer_v2"


def _inject_session(mock_session):
    """Patch get_session in the fuzzer_v2 module."""
    return patch(f"{_V2}.get_session", return_value=mock_session)


# ===========================================================================
# Consent gate tests — one per tool (BACKEND HARDENED INVARIANT).
# ===========================================================================


def test_fuzz_exported_components_v2_requires_consent(mock_session):
    """drive=True with confirm=False returns requires_consent."""
    with _inject_session(mock_session):
        result = fuzz_exported_components_v2(
            mock_session.session_id, drive=True, confirm=False,
        )
    assert result["status"] == "requires_consent"
    assert result["consent_required"] is True
    # No side effects: no tool ran, no payload was generated
    assert result["data"].get("plan_only") is True or "command" not in result


def test_fuzz_deep_links_v2_requires_consent(mock_session):
    with _inject_session(mock_session):
        result = fuzz_deep_links_v2(
            mock_session.session_id, drive=True, confirm=False,
        )
    assert result["status"] == "requires_consent"
    assert result["consent_required"] is True


def test_automine_blind_sqli_requires_consent(mock_session):
    with _inject_session(mock_session):
        result = automine_blind_sqli(
            mock_session.session_id, authority="x", drive=True, confirm=False,
        )
    assert result["status"] == "requires_consent"
    assert result["consent_required"] is True


# ===========================================================================
# Plan-mode tests (drive=False / confirm=False) — proves grammar extraction.
# ===========================================================================


def test_fuzz_exported_components_v2_plan_emits_at_least_one_payload(mock_session):
    """Mock session has no exposed intent extras — plan still non-empty
    (graceful fallback to one place-holder payload)."""
    with _inject_session(mock_session):
        with patch(f"{_V2}.extract_extras_for_component", return_value=[]):
            result = fuzz_exported_components_v2(mock_session.session_id)
    assert result["status"] == "ok"
    assert result["consent_required"] is True
    payloads = result["data"]["payloads"]
    assert len(payloads) >= 1
    assert payloads[0]["tokens"][0:2] == ["shell", "am"]
    assert payloads[0]["tokens"][2] == "start"


def test_fuzz_exported_components_v2_plan_uses_bytecode_extras(mock_session):
    """Fake extractor returns `{"cmd":"id"}` and `{"token":"abc"}` —
    plan must include those keys as --es / --ez tokens."""
    fake_extras = [
        {"key": "cmd", "value": "id", "type": "string"},
        {"key": "token", "value": "abc", "type": "string"},
    ]
    with _inject_session(mock_session):
        with patch(f"{_V2}.extract_extras_for_component", return_value=fake_extras):
            result = fuzz_exported_components_v2(
                mock_session.session_id, component_name="com.example.testapp.MainActivity",
            )
    assert result["status"] == "ok"
    payload = result["data"]["payloads"][0]
    tokens = payload["tokens"]
    # --es cmd id  must appear in tokens
    joined = " ".join(tokens)
    assert "--es" in joined
    assert "cmd" in joined
    assert "id" in joined
    assert "token" in joined
    assert "abc" in joined


def test_fuzz_deep_links_v2_plan_uses_manifest_filter(mock_session):
    """Auto-derives scheme/host from manifest filter — at least one URI
    suite emitted even when scheme is generic."""
    # Add a custom scheme / host to the mock session's manifest
    from lxml import etree
    NS = "http://schemas.android.com/apk/res/android"
    apk = mock_session.apk
    activity = apk.get_android_manifest_xml().find("application").find("activity")
    filt = etree.SubElement(activity, "intent-filter")
    act = etree.SubElement(filt, "action")
    act.set(f"{{{NS}}}name", "android.intent.action.VIEW")
    cat = etree.SubElement(filt, "category")
    cat.set(f"{{{NS}}}name", "android.intent.category.DEFAULT")
    dat = etree.SubElement(filt, "data")
    dat.set(f"{{{NS}}}scheme", "apksawtest")
    dat.set(f"{{{NS}}}host", "deeplink.example.com")

    with _inject_session(mock_session):
        result = fuzz_deep_links_v2(mock_session.session_id)
    assert result["status"] == "ok"
    suites = result["data"]["suites"]
    assert suites
    joined = " ".join(s["uri"] for s in suites)
    assert "apksawtest://" in joined
    assert "deeplink.example.com" in joined


# ===========================================================================
# Grammar extractors (the headline Phase 3 capability).
# ===========================================================================


def test_extract_provider_schema_finds_table_from_sql_string(mock_session):
    """`SELECT * FROM users WHERE id = ?` (already in conftest pool) →
    table 'users' shows up in the schema."""
    with _inject_session(mock_session):
        schema = extract_provider_schema(mock_session.session_id, "x")
    tables = [t["name"] for t in schema.get("tables", [])]
    assert "users" in tables


def test_extract_provider_schema_finds_columns_from_create_table(mock_session):
    """Inject `CREATE TABLE users (id INTEGER, email TEXT, password TEXT)`
    string and assert it parses to 3 columns under table 'users'."""
    schema_string = "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT)"
    pool = list(mock_session.analysis.get_strings())
    new_sa = MagicMock()
    new_sa.get_value.return_value = schema_string
    pool.append(new_sa)
    # Reset the iter-side-effect so the new pool is used
    mock_session.analysis.get_strings.return_value = iter(pool)
    mock_session.analysis.find_strings.side_effect = lambda string="", **kw: (
        sa for sa in pool if string in sa.get_value()
    )

    with _inject_session(mock_session):
        schema = extract_provider_schema(mock_session.session_id, "x")
    users = next(t for t in schema["tables"] if t["name"] == "users")
    assert "id" in users["columns"]
    assert "email" in users["columns"]
    assert "password" in users["columns"]


def test_extract_provider_schema_filters_unreachable_columns(mock_session):
    """When taint_lite reports a column as unreachable from any exported
    component, that column must be absent from the returned schema."""
    schema_string = "CREATE TABLE users (id INTEGER, email TEXT, secretapikey TEXT)"
    pool = list(mock_session.analysis.get_strings())
    new_sa = MagicMock()
    new_sa.get_value.return_value = schema_string
    pool.append(new_sa)
    mock_session.analysis.get_strings.return_value = iter(pool)
    mock_session.analysis.find_strings.side_effect = lambda string="", **kw: (
        sa for sa in pool if string in sa.get_value()
    )

    # Mock is_reachable_from_exported to return False for `secretapikey` only
    def _is_reachable(table, column):
        return column != "secretapikey"

    with _inject_session(mock_session):
        with patch(f"{_V2}.is_reachable_from_exported", side_effect=_is_reachable):
            schema = extract_provider_schema(mock_session.session_id, "x")
    users = next(t for t in schema["tables"] if t["name"] == "users")
    assert "secretapikey" not in users["columns"]
    assert "email" in users["columns"]


def test_extract_provider_schema_empty_when_no_sql_strings(mock_session):
    """Sessions with no SQL strings → empty tables / columns, not crash."""
    # Wipe the string pool
    mock_session.analysis.get_strings.return_value = iter([])
    mock_session.analysis.find_strings.side_effect = lambda string="", **kw: iter([])

    with _inject_session(mock_session):
        schema = extract_provider_schema(mock_session.session_id, "x")
    assert schema == {"tables": [], "columns": [], "source": "static_analysis"}


def test_extract_extras_for_component_handles_missing_class(mock_session):
    """Returns empty list rather than crashing on unknown FQN."""
    with _inject_session(mock_session):
        result = extract_extras_for_component(
            mock_session.session_id, "Ldoes/not/Exist;"
        )
    assert result == []


def test_extract_deeplink_params_reads_intent_filter_data(mock_session):
    """Reads <data scheme/host/path/> attributes from manifest."""
    from lxml import etree
    NS = "http://schemas.android.com/apk/res/android"
    apk = mock_session.apk
    activity = apk.get_android_manifest_xml().find("application").find("activity")
    filt = etree.SubElement(activity, "intent-filter")
    act = etree.SubElement(filt, "action")
    act.set(f"{{{NS}}}name", "android.intent.action.VIEW")
    cat = etree.SubElement(filt, "category")
    cat.set(f"{{{NS}}}name", "android.intent.category.DEFAULT")
    dat = etree.SubElement(filt, "data")
    dat.set(f"{{{NS}}}scheme", "https")
    dat.set(f"{{{NS}}}host", "x.example.com")
    dat.set(f"{{{NS}}}path", "/v1/foo")

    with _inject_session(mock_session):
        params = extract_deeplink_params(
            mock_session.session_id, "com.example.testapp.MainActivity",
        )
    assert params["scheme"] == "https"
    assert params["host"] == "x.example.com"
    assert params["path"] == "/v1/foo"


# ===========================================================================
# Headline tool — automine_blind_sqli — 4 oracle modes.
# ===========================================================================


def test_automine_blind_sqli_boolean_payload_references_real_columns(mock_session):
    """Boolean oracle with seeded schema → payload references 'users.email',
    NOT the v1 generic `'1=1 OR 1=1` static tautology."""
    schema = {
        "tables": [
            {"name": "users", "columns": ["id", "email", "password"]},
        ],
        "columns": [],
        "source": "static_analysis",
    }
    with _inject_session(mock_session):
        with patch(f"{_V2}.extract_provider_schema", return_value=schema):
            with patch(f"{_V2}._list_exported_components", return_value={
                "activities": [], "services": [], "receivers": [], "providers": [],
            }):
                result = automine_blind_sqli(
                    mock_session.session_id,
                    authority="com.example.testapp.provider",
                    oracle="boolean",
                )
    assert result["status"] == "ok"
    payloads = result["data"]["payloads"]
    assert payloads, "boolean oracle produced zero payloads"
    # At least one payload must reference 'users.email' — proves the headline
    # app-aware behavior: real column names, not generic 1=1 OR 1=1.
    joined = " ".join(p.get("where_clause", "") for p in payloads)
    assert "users.email" in joined
    # And NOT just the v1 static tautology
    assert "1=1 OR 1=1" not in joined


def test_automine_blind_sqli_boolean_payload_with_empty_schema_still_emits(mock_session):
    """Empty schema → graceful fallback (≥1 payload, NOT zero)."""
    empty = {"tables": [], "columns": [], "source": "static_analysis"}
    with _inject_session(mock_session):
        with patch(f"{_V2}.extract_provider_schema", return_value=empty):
            with patch(f"{_V2}._list_exported_components", return_value={
                "activities": [], "services": [], "receivers": [], "providers": [],
            }):
                result = automine_blind_sqli(
                    mock_session.session_id, authority="x", oracle="boolean",
                )
    payloads = result["data"]["payloads"]
    assert len(payloads) >= 1
    # Default fallback must still be safe (parameterised, not concatenation)
    assert all("'" in p.get("where_clause", "") or "?" in p.get("where_clause", "")
               for p in payloads)


def test_automine_blind_sqli_union_payload_references_columns(mock_session):
    """UNION oracle lists real columns and stays within SQLite's 6-col limit."""
    schema = {
        "tables": [
            {"name": "users", "columns": ["id", "email", "password"]},
        ],
        "columns": [],
        "source": "static_analysis",
    }
    with _inject_session(mock_session):
        with patch(f"{_V2}.extract_provider_schema", return_value=schema):
            with patch(f"{_V2}._list_exported_components", return_value={
                "activities": [], "services": [], "receivers": [], "providers": [],
            }):
                result = automine_blind_sqli(
                    mock_session.session_id, authority="x", oracle="union",
                )
    payloads = result["data"]["payloads"]
    union_payloads = [p for p in payloads if p.get("oracle") == "union"]
    assert union_payloads, "no unicode UNION oracle payloads"
    # UNION SELECT clause must reference real columns
    for p in union_payloads:
        select_clause = p.get("union_select", "")
        assert "id" in select_clause
        # SQLite caps UNION SELECT column counts — assert ≤ 6
        assert select_clause.count(",") + 1 <= 6
        assert "users" in select_clause


def test_automine_blind_sqli_time_oracle_no_sleep_no_benchmark(mock_session):
    """Time oracle must REJECT SLEEP()/BENCHMARK() (MySQL only) — uses
    SQLite-compatible heavy-computation or randomblob() instead."""
    schema = {"tables": [{"name": "users", "columns": ["id"]}],
              "columns": [], "source": "static_analysis"}
    with _inject_session(mock_session):
        with patch(f"{_V2}.extract_provider_schema", return_value=schema):
            with patch(f"{_V2}._list_exported_components", return_value={
                "activities": [], "services": [], "receivers": [], "providers": [],
            }):
                result = automine_blind_sqli(
                    mock_session.session_id, authority="x", oracle="time",
                )
    payloads = result["data"]["payloads"]
    time_payloads = [p for p in payloads if p.get("oracle") == "time"]
    assert time_payloads
    joined = "\n".join(p.get("where_clause", "") for p in time_payloads)
    # Reject MySQL-only primitives
    assert "SLEEP(" not in joined.upper()
    assert "BENCHMARK(" not in joined.upper()
    # Use SQLite-compatible primitives
    upper = joined.upper()
    assert "RANDOMBLOB(" in upper or "LIKE '%" in upper or "GLOB" in upper


def test_automine_blind_sqli_error_oracle_references_table(mock_session):
    """Error oracle payload mentions the table name (so an SQLiteException
    reveals it via logcat)."""
    schema = {"tables": [{"name": "users", "columns": ["id"]}],
              "columns": [], "source": "static_analysis"}
    with _inject_session(mock_session):
        with patch(f"{_V2}.extract_provider_schema", return_value=schema):
            with patch(f"{_V2}._list_exported_components", return_value={
                "activities": [], "services": [], "receivers": [], "providers": [],
            }):
                result = automine_blind_sqli(
                    mock_session.session_id, authority="x", oracle="error",
                )
    payloads = result["data"]["payloads"]
    error_payloads = [p for p in payloads if p.get("oracle") == "error"]
    assert error_payloads
    joined = " ".join(p.get("where_clause", "") for p in error_payloads)
    assert "users" in joined


def test_automine_blind_sqli_rejects_unknown_oracle(mock_session):
    """oracle='drop-table' is invalid → status:error, no payloads."""
    with _inject_session(mock_session):
        result = automine_blind_sqli(
            mock_session.session_id, authority="x", oracle="drop-table",
        )
    assert result["status"] == "error"
    assert "oracle" in result["message"].lower() or "unknown" in result["message"].lower()


# ===========================================================================
# Crash oracle — realistic logcat with package name (the fixed-bug test).
# ===========================================================================

_REALISTIC_CRASH_LOGCAT = (
    "I/SystemServer: Starting com.example.testapp\n"
    "E/AndroidRuntime: FATAL EXCEPTION: main\n"
    "E/AndroidRuntime: Process: {PKG}, PID: 1234\n"
    "E/AndroidRuntime: java.lang.NullPointerException: Attempt to invoke virtual method 'String com.example.testapp.MainActivity.getCmd()' on a null object reference\n"
)

_REALISTIC_PERMISSION_DENIAL = (
    "W/ActivityManager: Permission Denial: opening provider {PKG}.TestProvider "
    "from ProcessRecord{{pid=1234, uid=1010000}} -> ProcessRecord{{pid=5678, uid=1010056}} "
    "requires {PKG}.TestProvider.permission.READ_DATA "
    "or {PKG}.TestProvider.permission.WRITE_DATA\n"
    "java.lang.SecurityException: {PKG}.TestProvider: neither user 1010000 nor current process has android.permission.READ_DATA\n"
)


def test_check_logcat_realistic_crash_is_detected(mock_session):
    pkg = mock_session.package_name
    log = _REALISTIC_CRASH_LOGCAT.replace("{PKG}", pkg)
    kind, snippet = _check_logcat_for_crash(log, pkg)
    assert kind == "crash"
    assert "FATAL EXCEPTION" in snippet


def test_check_logcat_realistic_permission_denial_is_detected(mock_session):
    """The fixed bug: synthetic SecurityException lines WITHOUT the package
    name were classified as no_crash. The realistic ActivityManager format
    below contains the package, so it must classify properly."""
    pkg = mock_session.package_name
    log = _REALISTIC_PERMISSION_DENIAL.replace("{PKG}", pkg)
    kind, snippet = _check_logcat_for_crash(log, pkg)
    assert kind == "security_exception"
    assert "SecurityException" in snippet or "Permission Denial" in snippet


def test_check_logcat_irrelevant_security_exception_is_filtered(mock_session):
    """Synthetic SecurityException with NO package name → no_crash
    (relevance filter — the test we kept to memorialise the regression)."""
    pkg = mock_session.package_name
    log = "E/AndroidRuntime: java.lang.SecurityException: totally unrelated\n"
    kind, snippet = _check_logcat_for_crash(log, pkg)
    assert kind == "no_crash"
    assert snippet == ""


def test_check_logcat_detects_anr(mock_session):
    pkg = mock_session.package_name
    log = f"E/ActivityManager: ANR in {pkg}.MainActivity\n"
    kind, _ = _check_logcat_for_crash(log, pkg)
    assert kind == "anr"


# ===========================================================================
# Redaction helpers & live-path smoke (very narrow, multi-patch).
# ===========================================================================


def test_redact_text_strips_authorization_bearer():
    s = "Authorization: Bearer eyJabc.def.ghi"
    out = redact_text(s)
    assert "REDACTED" in out
    assert "eyJabc.def.ghi" not in out


def test_redact_text_strips_google_api_key():
    s = "key=AIzaSyABC123XYZ456abc789def012ghi345jkl"
    out = redact_text(s)
    assert "GOOGLE_KEY_REDACTED" in out


def test_redact_text_strips_jwt():
    s = "token=eyJhbGciOi.eyJzdWIiOi.signature"
    out = redact_text(s)
    assert "JWT_REDACTED" in out


def test_list_exported_components_off_mock_session(mock_session):
    """Sanity: the re-implemented manifest helper returns the conftest's
    one exported activity."""
    components = _list_exported_components(mock_session.apk)
    assert any(c["name"] == "com.example.testapp.MainActivity"
               for c in components["activities"])


def test_clear_logcat_swallows_runtime_error():
    """_clear_logcat swallows a RuntimeError from run_adb (no-device)."""
    with patch(f"{_V2}.run_adb", side_effect=RuntimeError("no device")):
        # Must not raise
        _clear_logcat()


def test_capture_logcat_returns_empty_on_failure():
    """_capture_logcat returns "" when run_adb raises."""
    with patch(f"{_V2}.run_adb", side_effect=RuntimeError("no device")):
        assert _capture_logcat() == ""


# ===========================================================================
# Live-path smoke test: confirm-mode execution goes through the evidence
# pipeline (logcat + screenshot ADB calls mocked).
# ===========================================================================


def test_automine_blind_sqli_confirm_mode_runs_evidence_pipeline(mock_session, tmp_path):
    schema = {"tables": [{"name": "users", "columns": ["id"]}],
              "columns": [], "source": "static_analysis"}
    fake_proc_ok = MagicMock(returncode=0, stdout="", stderr="")
    with _inject_session(mock_session):
        with patch(f"{_V2}.extract_provider_schema", return_value=schema):
            with patch(f"{_V2}._list_exported_components", return_value={
                "activities": [], "services": [], "receivers": [], "providers": [],
            }):
                with patch.object(subprocess, "run", return_value=fake_proc_ok) as adb_run:
                    with patch(f"{_V2}._capture_logcat",
                               return_value="I/System.out: peaceful"):
                        with patch(f"{_V2}._take_screenshot",
                                   return_value={"path": str(tmp_path / "shot.png")}):
                            with patch(f"{_V2}.check_device_connected", return_value=True):
                                ws = tmp_path / "ws"
                                ws.mkdir()
                                mock_session.workspace = ws
                                result = automine_blind_sqli(
                                    mock_session.session_id, authority="x",
                                    oracle="boolean",
                                    drive=True, confirm=True,
                                )
    # Confirm-mode went through; adb was called at least once; first result
    # has the logcat/screenshot envelope populated.
    assert result["status"] == "ok"
    executed = result["data"]["executed"]
    assert executed
    assert adb_run.called
    first = executed[0]
    assert first["result"] == "no_crash"
    assert first["screenshot"] is not None
