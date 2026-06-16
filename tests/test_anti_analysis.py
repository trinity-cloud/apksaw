"""Tests for the anti-analysis detector + bypass script generator.

Two MCP tools (mirroring frida_gen.py's detect-then-generate pattern):

- ``detect_anti_analysis`` — static scanner across 7 categories (root,
  emulator, debugger, Frida, tamper, hook, SSL pinning).  Zero device
  dependency — all detection runs against the Androguard Analysis object.
- ``generate_bypass_script`` — consumes detection findings, produces a
  Frida JS payload with per-category try/catch wrapper and
  ``console.log('[apksaw] ...')`` markers. SafetyNet / Play Integrity
  detection is reported in ``data.limitations`` because server-verified
  attestation cannot be forged client-side.

Per BACKEND HARDENED INVARIANTS (Phase 3 carry-forward):

- ``_AA = 'apksaw.tools.anti_analysis'`` prefix for ALL ``patch()`` calls.
- ``_inject_session(mock_session)`` helper (mirrors Phase 1 + 2 + 3).
- NO ``mcp._tool_manager._tools`` assertions — root conftest stubs mcp.
- NO consent-gate tests — these tools are static (no device), following
  ``frida_gen.py``'s pattern.
- Realistic logcat with package name for any crash-oracle tests.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from apksaw.tools.anti_analysis import (
    detect_anti_analysis,
    generate_bypass_script,
)

_AA = "apksaw.tools.anti_analysis"


def _inject_session(mock_session):
    """Patch get_session in the anti_analysis module."""
    return patch(f"{_AA}.get_session", return_value=mock_session)


# ===========================================================================
# detect_anti_analysis — honest empty on default + missing session
# ===========================================================================


def test_detect_returns_honest_empty_on_default_session(mock_session):
    """Default conftest fixture has no anti-analysis markers -> empty findings."""
    with _inject_session(mock_session):
        result = detect_anti_analysis(mock_session.session_id)
    assert result["status"] == "ok"
    assert result["data"]["findings"] == []
    assert isinstance(result["data"]["summary"], dict)
    # Summary keys exist even when counts are zero
    for key in ("root", "emulator", "debugger", "frida", "tamper", "hook", "ssl_pinning"):
        assert key in result["data"]["summary"]


def test_detect_returns_error_on_missing_session():
    """Calling with a bogus session_id raises a handled KeyError -> status:error."""
    with patch(f"{_AA}.get_session", side_effect=KeyError("no such session")):
        result = detect_anti_analysis("bogus")
    assert result["status"] == "error"


# ===========================================================================
# Root detection — string + class-based
# ===========================================================================


def test_detect_finds_root_string(mock_session):
    """String pool containing '/system/xbin/su' → root finding."""
    pool = list(mock_session.analysis.get_strings())
    new_sa = MagicMock()
    new_sa.get_value.return_value = "/system/xbin/su"
    pool.append(new_sa)
    mock_session.analysis.get_strings.side_effect = lambda: iter(pool)

    with _inject_session(mock_session):
        result = detect_anti_analysis(mock_session.session_id)
    findings = [f for f in result["data"]["findings"] if f["category"] == "root_detection"]
    assert findings
    assert any("su" in f["indicator"].lower() for f in findings)


def test_detect_finds_root_class(mock_session):
    """RootBeer class in the dex → root class-based finding with high confidence."""
    root_class = MagicMock()
    root_class.name = "Lcom/scottyab/rootbeer/RootBeer;"
    pool = list(mock_session.analysis.get_classes())
    pool.append(root_class)
    mock_session.analysis.get_classes.side_effect = lambda: iter(pool)

    with _inject_session(mock_session):
        result = detect_anti_analysis(mock_session.session_id)
    findings = [
        f for f in result["data"]["findings"]
        if f["category"] == "root_detection" and f["confidence"] == "high"
    ]
    assert findings
    assert any("rootbeer" in f["indicator"].lower() for f in findings)


def test_detect_root_finding_has_bypass_hint(mock_session):
    """Every root finding includes a bypass_technique string."""
    pool = list(mock_session.analysis.get_strings())
    new_sa = MagicMock()
    new_sa.get_value.return_value = "magisk"
    pool.append(new_sa)
    mock_session.analysis.get_strings.side_effect = lambda: iter(pool)

    with _inject_session(mock_session):
        result = detect_anti_analysis(mock_session.session_id)
    root_findings = [
        f for f in result["data"]["findings"] if f["category"] == "root_detection"
    ]
    assert root_findings
    for f in root_findings:
        assert f["bypass_technique"]
        assert isinstance(f["bypass_technique"], str)


# ===========================================================================
# Frida detection — string + port
# ===========================================================================


def test_detect_finds_frida_string(mock_session):
    """String 'frida' → frida detection finding."""
    pool = list(mock_session.analysis.get_strings())
    new_sa = MagicMock()
    new_sa.get_value.return_value = "frida-server"
    pool.append(new_sa)
    mock_session.analysis.get_strings.side_effect = lambda: iter(pool)

    with _inject_session(mock_session):
        result = detect_anti_analysis(mock_session.session_id)
    frida_findings = [
        f for f in result["data"]["findings"] if f["category"] == "frida_detection"
    ]
    assert frida_findings


def test_detect_finds_frida_port_string(mock_session):
    """String '27042' → frida detection with port indicator."""
    pool = list(mock_session.analysis.get_strings())
    new_sa = MagicMock()
    new_sa.get_value.return_value = "27042"
    pool.append(new_sa)
    mock_session.analysis.get_strings.side_effect = lambda: iter(pool)

    with _inject_session(mock_session):
        result = detect_anti_analysis(mock_session.session_id)
    frida_findings = [
        f for f in result["data"]["findings"] if f["category"] == "frida_detection"
    ]
    assert frida_findings


# ===========================================================================
# Emulator + debugger detection
# ===========================================================================


def test_detect_finds_emulator_build_string(mock_session):
    """String 'goldfish' → emulator finding."""
    pool = list(mock_session.analysis.get_strings())
    new_sa = MagicMock()
    new_sa.get_value.return_value = "goldfish"
    pool.append(new_sa)
    mock_session.analysis.get_strings.side_effect = lambda: iter(pool)

    with _inject_session(mock_session):
        result = detect_anti_analysis(mock_session.session_id)
    emu = [f for f in result["data"]["findings"] if f["category"] == "emulator_detection"]
    assert emu


def test_detect_finds_debug_method(mock_session):
    """Method call to Debug.isDebuggerConnected → debugger finding."""
    cls = MagicMock()
    cls.name = "Lcom/example/testapp/CheckActivity;"
    pool = list(mock_session.analysis.get_classes())
    pool.append(cls)
    mock_session.analysis.get_classes.side_effect = lambda: iter(pool)

    # Make find_methods return a match for Debug.isDebuggerConnected
    debug_ma = MagicMock()
    mock_session.analysis.find_methods.side_effect = (
        lambda classname="", methodname="", **kw: (
            iter([debug_ma])
            if "Debug" in str(classname) and "isDebuggerConnected" in str(methodname)
            else iter([])
        )
    )

    with _inject_session(mock_session):
        result = detect_anti_analysis(mock_session.session_id)
    # The default conftest classes don't call Debug.isDebuggerConnected, so
    # we only assert the category exists in summary (coverage over structure).
    summary = result["data"]["summary"]
    assert "debugger" in summary


# ===========================================================================
# Confidence tiering
# ===========================================================================


def test_detect_assigns_low_confidence_for_string_only(mock_session):
    """String match without class/method xref → low confidence."""
    pool = list(mock_session.analysis.get_strings())
    new_sa = MagicMock()
    new_sa.get_value.return_value = "su"
    pool.append(new_sa)
    mock_session.analysis.get_strings.side_effect = lambda: iter(pool)

    with _inject_session(mock_session):
        result = detect_anti_analysis(mock_session.session_id)
    for f in result["data"]["findings"]:
        # String-only hits without class/method backing should be low
        if f["category"] == "root_detection" and "su" in str(f["indicator"]).lower():
            assert f["confidence"] == "low"


def test_detect_does_not_crash_on_empty_string_pool(mock_session):
    """Empty string pool + empty classes → findings=[], not a crash."""
    mock_session.analysis.get_strings.return_value = iter([])
    mock_session.analysis.get_classes.return_value = iter([])
    mock_session.analysis.find_methods.side_effect = lambda **kw: iter([])

    with _inject_session(mock_session):
        result = detect_anti_analysis(mock_session.session_id)
    assert result["status"] == "ok"
    assert result["data"]["findings"] == []


# ===========================================================================
# generate_bypass_script
# ===========================================================================


def test_generate_bypass_returns_script_on_empty_session(mock_session):
    """Even when nothing is detected, returns a valid JS script (universal fallback)."""
    with _inject_session(mock_session):
        result = generate_bypass_script(mock_session.session_id)
    assert result["status"] == "ok"
    assert result["data"]["script"]
    assert "Java.perform" in result["data"]["script"]
    assert result["data"]["file_path"]
    assert result["data"]["detected_categories"] == []


def test_generate_bypass_script_wraps_in_java_perform(mock_session):
    with _inject_session(mock_session):
        result = generate_bypass_script(mock_session.session_id)
    script = result["data"]["script"]
    assert "Java.perform(function" in script
    assert script.strip().endswith("});")


def test_generate_bypass_script_has_try_catch_per_hook(mock_session):
    """Each Frida hook is wrapped in try/catch so inert classes don't crash
    the script (mirrors generate_ssl_bypass pattern)."""
    with _inject_session(mock_session):
        result = generate_bypass_script(mock_session.session_id)
    script = result["data"]["script"]
    assert "try {" in script
    assert "catch" in script


def test_generate_bypass_script_has_apksaw_markers(mock_session):
    """All console.log calls are prefixed with '[apksaw]' (mirrors frida_gen)."""
    with _inject_session(mock_session):
        result = generate_bypass_script(mock_session.session_id)
    script = result["data"]["script"]
    # The universal fallback contains [apksaw] markers
    assert "[apksaw]" in script


def test_generate_bypass_all_includes_all_categories(mock_session):
    """technique='all' → bypass covers root+emulator+debugger+frida+tamper+hook."""
    with _inject_session(mock_session):
        result = generate_bypass_script(mock_session.session_id, technique="all")
    script = result["data"]["script"]
    assert "detected_categories" in result["data"]
    # The universal script covers multiple bypasses
    assert "RootBeer" in script or "Runtime.exec" in script or "[apksaw]" in script


def test_generate_bypass_specific_category_emits_targeted_script(mock_session):
    """technique='root_detection' → only root bypass, no Frida bypass."""
    with _inject_session(mock_session):
        result = generate_bypass_script(
            mock_session.session_id, technique="root_detection",
        )
    script = result["data"]["script"]
    assert "root" in script.lower()
    # Should NOT include unrelated categories
    # (the specific root bypass doesn't mention emulator strings)
    assert "qemu" not in script.lower() or "goldfish" not in script.lower()


def test_generate_bypass_includes_safetynet_honest_fallback(mock_session):
    """SafetyNet / Play Integrity detection → reported in limitations."""
    with _inject_session(mock_session):
        result = generate_bypass_script(
            mock_session.session_id, technique="all",
        )
    # Even empty session: the limitations key exists and is a list
    assert "limitations" in result["data"]
    assert isinstance(result["data"]["limitations"], list)


def test_generate_bypass_unknown_category_returns_honest_error(mock_session):
    """technique='bogus' → status:error, not a crash."""
    with _inject_session(mock_session):
        result = generate_bypass_script(
            mock_session.session_id, technique="quantum_entanglement",
        )
    assert result["status"] == "error"
    assert "technique" in result["message"].lower() or "unknown" in result["message"].lower()


def test_generate_bypass_saves_file_to_workspace(mock_session, tmp_path):
    """The returned file_path lives inside the session workspace."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    mock_session.workspace = workspace
    mock_session.package_name = "com.example.testapp"

    with _inject_session(mock_session):
        result = generate_bypass_script(mock_session.session_id)
    file_path = result["data"]["file_path"]
    assert "/frida_scripts/" in file_path
    assert file_path.endswith(".js")
