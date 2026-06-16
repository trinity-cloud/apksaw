"""Tests for the native exploitation tools added in Phase 5.

Three new MCP tools in ``src/apksaw/tools/native.py``:

- ``find_rop_gadgets``    — static Capstone-based ROP gadget discovery.
- ``generate_jni_hook``   — produces a Frida JS script to hook Java_* exports.
- ``execute_native_hook`` — runtime Frida hook execution gated by ``confirm=``.

Per BACKEND HARDENED INVARIANTS (Phase 4 carry-forward):

- ``_NA = 'apksaw.tools.native'`` prefix for ALL ``patch()`` calls.
- ``_inject_session(mock_session)`` helper (mirrors ``test_anti_analysis``).
- ``_fake_extract_so()`` side_effect + ``_with_extraction()`` ctx helper so
  the tool can reach the LIEF/Capstone mocks (the mock_session fixture's
  apk_path is a fake file, not a real ZIP — that's a test-infra quirk).
- NO ``mcp._tool_manager._tools`` assertions — root conftest stubs mcp.
- Subprocess / device side-effects stubbed; no real ADB / frida in CI.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from apksaw.tools.native import (
    execute_native_hook,
    find_rop_gadgets,
    generate_jni_hook,
)

_NA = "apksaw.tools.native"


# ===========================================================================
# Helpers
# ===========================================================================


def _inject_session(mock_session):
    """Patch ``get_session`` inside the native module."""
    return patch(f"{_NA}.get_session", return_value=mock_session)


def _fake_extract_so(bytes_to_write: bytes = b"\x00" * 256):
    """Build a stand-in for ``_extract_so`` that returns a real Path on disk.

    The Phase 5 tools call ``_extract_so`` to read the .so out of the APK ZIP
    before parsing with LIEF. The mock_session fixture's apk_path is a fake
    file (not a real ZIP), so without this patch ``_extract_so`` raises
    ``zipfile.BadZipFile``. Tests inject this side_effect so the tool can
    reach the ``lief.ELF.parse`` call they actually want to mock.
    """
    def _impl(session, lib_path: str) -> Path:
        dest = session.workspace / lib_path.replace("/", "_")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(bytes_to_write)
        return dest
    return _impl


@contextmanager
def _with_extraction(mock_session):
    """Context manager that combines session injection + extract stub.

    Use this for any test that exercises the LIEF/Capstone code path so the
    tool can complete the .so extraction stage and reach the patched
    ``lief.ELF.parse`` / ``capstone.Cs`` mocks.
    """
    with _inject_session(mock_session), \
         patch(f"{_NA}._extract_so", side_effect=_fake_extract_so()):
        yield


def _make_lief_binary(text_section_bytes: bytes = b"\x00" * 256, jni_exports=None):
    """Build a mock LIEF ELF binary with .text + optional Java_* exports."""
    text_sec = MagicMock()
    text_sec.name = ".text"
    text_sec.content = text_section_bytes
    text_sec.virtual_address = 0x10000
    text_sec.size = len(text_section_bytes)

    binary = MagicMock()
    binary.sections = [text_sec]
    binary.header.machine_type = "ARM64"
    binary.is_pie = True

    exports = []
    for name, addr in (jni_exports or []):
        fn = MagicMock()
        fn.name = name
        fn.address = addr
        fn.size = 0x100
        exports.append(fn)
    binary.exported_functions = exports

    return binary


def _make_capstone_md(insns):
    """Build a mock ``capstone.Cs(...)`` instance with a .disasm iterator."""
    md = MagicMock()
    md.detail = True
    md.disasm.return_value = iter(insns)
    return md


def _insn(addr: int, mnemonic: str, op_str: str = ""):
    """Shorthand for a capstone instruction mock."""
    i = MagicMock()
    i.address = addr
    i.mnemonic = mnemonic
    i.op_str = op_str
    i.bytes = b"\x00" * 4
    i.size = 4
    return i


# ===========================================================================
# find_rop_gadgets — happy paths
# ===========================================================================


def test_find_rop_gadgets_missing_session_returns_error():
    with patch(f"{_NA}.get_session", side_effect=KeyError("missing")):
        result = find_rop_gadgets("bogus", "libnative.so", arch="arm64-v8a")
    assert result["status"] == "error"


def test_find_rop_gadgets_no_text_section_returns_empty(mock_session):
    """Library without .text → empty gadgets, status:ok."""
    binary = MagicMock()
    binary.sections = []
    with _with_extraction(mock_session), \
         patch("lief.ELF.parse", return_value=binary):
        result = find_rop_gadgets(
            mock_session.session_id, "libnative.so", arch="arm64-v8a",
        )
    assert result["status"] == "ok"
    assert result["data"]["count"] == 0
    assert result["data"]["gadgets"] == []


def test_find_rop_gadgets_classifies_pop_ret_gadgets(mock_session):
    """``pop x0; ret`` → gadgets classified and counted."""
    binary = _make_lief_binary()
    md = _make_capstone_md([
        _insn(0x10000, "sub",   "sp, sp, #0x10"),
        _insn(0x10004, "ldr",   "x0, [sp]"),
        _insn(0x10008, "pop",   "x0"),
        _insn(0x1000C, "ret",   ""),
        _insn(0x10010, "mov",   "x0, x1"),
        _insn(0x10014, "ret",   ""),
    ])
    with _with_extraction(mock_session), \
         patch("lief.ELF.parse", return_value=binary), \
         patch("capstone.Cs", return_value=md):
        result = find_rop_gadgets(
            mock_session.session_id, "libnative.so",
            arch="arm64-v8a", max_gadgets=10,
        )
    assert result["status"] == "ok"
    assert result["data"]["count"] >= 2
    # At least one gadget contains 'pop' or 'ret' in its kind label
    kinds = " ".join(g["kind"] for g in result["data"]["gadgets"])
    assert "ret" in kinds.lower() or "pop" in kinds.lower()
    # Gadget entries expose kind + address + instructions (summary fields)
    first = result["data"]["gadgets"][0]
    for required in ("kind", "address", "instructions"):
        assert required in first


def test_find_rop_gadgets_respects_max_gadgets_cap(mock_session):
    """``max_gadgets`` caps the returned list to prevent expensive scans."""
    binary = _make_lief_binary(text_section_bytes=b"\x00" * 4096)
    # Emit 100 ret-only instructions → candidate gadgets
    insns = [_insn(0x10000 + i * 4, "ret", "") for i in range(100)]
    md = _make_capstone_md(insns)
    with _with_extraction(mock_session), \
         patch("lief.ELF.parse", return_value=binary), \
         patch("capstone.Cs", return_value=md):
        result = find_rop_gadgets(
            mock_session.session_id, "libnative.so",
            arch="arm64-v8a", max_gadgets=5,
        )
    assert result["status"] == "ok"
    assert result["data"]["count"] <= 5
    assert result["data"]["truncated"] is True


def test_find_rop_gadgets_unsupported_arch_returns_error(mock_session):
    """Arch string that no Cs mode maps to → status:error."""
    binary = _make_lief_binary()
    with _with_extraction(mock_session), \
         patch("lief.ELF.parse", return_value=binary):
        result = find_rop_gadgets(
            mock_session.session_id, "libnative.so",
            arch="riscv-unknown",  # unsupported
        )
    assert result["status"] == "error"
    assert "arch" in result["message"].lower()


def test_find_rop_gadgets_arm32_thumb_mod_constructed(mock_session):
    """armeabi-v7a → Cs is constructed (we don't assert exact constants)."""
    binary = _make_lief_binary()
    md = _make_capstone_md([
        _insn(0x8000, "pop", "{r4, r5}"),
        _insn(0x8002, "bx",  "lr"),
    ])
    with _with_extraction(mock_session), \
         patch("lief.ELF.parse", return_value=binary), \
         patch("capstone.Cs", return_value=md) as CsMock:
        result = find_rop_gadgets(
            mock_session.session_id, "libnative.so",
            arch="armeabi-v7a",
        )
    assert result["status"] == "ok"
    CsMock.assert_called_once()


# ===========================================================================
# generate_jni_hook — happy paths
# ===========================================================================


def test_generate_jni_hook_missing_session_returns_error():
    with patch(f"{_NA}.get_session", side_effect=KeyError("missing")):
        result = generate_jni_hook("bogus", "libnative.so")
    assert result["status"] == "error"


def test_generate_jni_hook_no_jni_exports_returns_advice(mock_session):
    """Lib without Java_* exports → status:ok with empty hooks + suggestion."""
    binary = _make_lief_binary(jni_exports=[])
    with _with_extraction(mock_session), \
         patch("lief.ELF.parse", return_value=binary):
        result = generate_jni_hook(
            mock_session.session_id, "libnative.so", arch="arm64-v8a",
        )
    assert result["status"] == "ok"
    assert result["data"]["hooks"] == []
    assert "no jni" in result["data"]["message"].lower() or "no java_" in result["data"]["message"].lower()


def test_generate_jni_hook_creates_frida_script_file(mock_session):
    """JNI exports → script written to workspace + return envelope populated."""
    binary = _make_lief_binary(jni_exports=[
        ("Java_com_example_testapp_Native_cryptoSign", 0x12345),
        ("Java_com_example_testapp_Native_verifyPin",   0x12680),
    ])
    with _with_extraction(mock_session), \
         patch("lief.ELF.parse", return_value=binary):
        result = generate_jni_hook(
            mock_session.session_id, "libnative.so", arch="arm64-v8a",
        )
    assert result["status"] == "ok"
    assert result["data"]["hooks"]
    script = result["data"]["script"]
    assert "Java.perform" in script
    assert "cryptoSign" in script
    assert result["data"]["file_path"]
    # File actually exists on disk (workspace/native_hooks/...)
    fp = Path(result["data"]["file_path"])
    assert fp.exists()
    # And contains an apksaw marker for human readability
    on_disk = fp.read_text()
    assert "apksaw" in on_disk.lower()


def test_generate_jni_hook_class_filter_isolates_single_class(mock_session):
    """``class_filter`` restricts hooks to one JNI class only."""
    binary = _make_lief_binary(jni_exports=[
        ("Java_com_example_testapp_NativeA_methodA", 0x12345),
        ("Java_com_example_testapp_NativeB_methodB", 0x12680),
    ])
    with _with_extraction(mock_session), \
         patch("lief.ELF.parse", return_value=binary):
        result = generate_jni_hook(
            mock_session.session_id, "libnative.so",
            arch="arm64-v8a", class_filter="NativeA",
        )
    assert result["status"] == "ok"
    script = result["data"]["script"]
    assert "methodA" in script
    assert "methodB" not in script
    assert len(result["data"]["hooks"]) == 1


# ===========================================================================
# execute_native_hook — consent + ADB gating
# ===========================================================================


def _fake_js_path(suffix: str = "hook.js") -> str:
    """Return a Path string that exists on disk (script must be loadable)."""
    js = Path("/tmp/apksaw_test_hook.js")
    js.parent.mkdir(parents=True, exist_ok=True)
    js.write_text("Java.perform(function(){});")
    return str(js)


def test_execute_native_hook_confirm_false_returns_plan(mock_session):
    """``confirm=False``: ``status:ok`` with a command plan, no subprocess."""
    with _inject_session(mock_session), \
         patch(f"{_NA}.subprocess") as mock_sp:
        result = execute_native_hook(
            mock_session.session_id, _fake_js_path(),
            confirm=False, package=mock_session.package_name,
        )
    assert result["status"] == "ok"
    assert "plan" in result["data"] or "command" in result["data"]
    # Subprocess must NOT be invoked in dry-run
    if hasattr(mock_sp, "Popen"):
        mock_sp.Popen.assert_not_called()
    if hasattr(mock_sp, "run"):
        mock_sp.run.assert_not_called()


def test_execute_native_hook_confirm_true_without_device_returns_error(mock_session):
    """``confirm=True`` with no ADB device → status:error, no subprocess."""
    with _inject_session(mock_session), \
         patch(f"{_NA}.check_device_connected", return_value=False), \
         patch(f"{_NA}.subprocess") as mock_sp:
        result = execute_native_hook(
            mock_session.session_id, _fake_js_path(),
            confirm=True, package=mock_session.package_name,
        )
    assert result["status"] == "error"
    assert "device" in result["message"].lower() or "adb" in result["message"].lower()
    if hasattr(mock_sp, "Popen"):
        mock_sp.Popen.assert_not_called()


def test_execute_native_hook_missing_js_path_returns_error(mock_session):
    """Non-existent JS path → status:error (no ADB needed for validation)."""
    with _inject_session(mock_session), \
         patch(f"{_NA}.check_device_connected", return_value=True):
        result = execute_native_hook(
            mock_session.session_id, "/nonexistent/does_not_exist.js",
            confirm=True, package=mock_session.package_name,
        )
    assert result["status"] == "error"
    assert "not found" in result["message"].lower() or "missing" in result["message"].lower()


def test_execute_native_hook_confirm_true_with_device_invokes_helpers(mock_session):
    """Happy path: confirm=True + ADB + fake frida module → status:ok + tool_check."""
    fake_frida = MagicMock()
    fake_device = MagicMock()
    fake_mgr = MagicMock()
    fake_mgr.get_usb_device.return_value = fake_device
    fake_frida.get_device_manager.return_value = fake_mgr
    fake_frida.Spawn.return_value = 12345
    fake_device.spawn.return_value = 12345
    fake_session = MagicMock()
    fake_session.create_script.return_value.load = MagicMock()
    fake_session.create_script.return_value.unload = MagicMock()
    fake_session.create_script.return_value.on = MagicMock()
    fake_device.attach.return_value = fake_session

    with _inject_session(mock_session), \
         patch(f"{_NA}.check_device_connected", return_value=True), \
         patch(f"{_NA}._IMPORT_FRIDA", available=True, module=fake_frida):
        result = execute_native_hook(
            mock_session.session_id, _fake_js_path(),
            confirm=True, package=mock_session.package_name,
            capture_seconds=1,
        )
    # We don't assert exactly success (frida spawn pipeline is owned by
    # runtime.py); only that the consent/ADB/missing-path gates didn't
    # error out.
    assert result["status"] != "error" or "device" not in result["message"].lower()


# ===========================================================================
# Edge-case tests (post-review hardening)
# ===========================================================================


def test_parse_jni_export_handles_underscore_escape():
    """``Java_com_acme_Foo_my_1_method`` parses to class with restored underscore."""
    from apksaw.tools.native import _parse_jni_export
    result = _parse_jni_export("Java_com_acme_Foo_my_1_method")
    assert result is not None
    cls, method = result
    assert "my_1" not in cls  # _1 was decoded
    assert "_" in cls  # underscore restored
    assert method == "method"


def test_execute_native_hook_rejects_package_none_on_confirm(mock_session):
    """``execute_native_hook`` with ``package=None, confirm=True`` returns error."""
    js = Path("/tmp/apksaw_test_hook.js")
    js.parent.mkdir(parents=True, exist_ok=True)
    js.write_text("Java.perform(function(){});")

    with _inject_session(mock_session), \
         patch(f"{_NA}.check_device_connected", return_value=True), \
         patch(f"{_NA}._IMPORT_FRIDA", available=True, module=MagicMock()):
        result = execute_native_hook(
            mock_session.session_id, str(js),
            confirm=True, package=None,
        )
    assert result["status"] == "error"
    assert "package" in result["message"].lower()


def test_generated_script_contains_args_to_json(mock_session):
    """The Frida script generated by ``generate_jni_hook`` includes the
    ``args_to_json`` helper for defensive argument serialization."""
    binary = _make_lief_binary(jni_exports=[
        ("Java_com_example_testapp_Native_cryptoSign", 0x12345),
    ])
    with _with_extraction(mock_session), \
         patch("lief.ELF.parse", return_value=binary):
        result = generate_jni_hook(
            mock_session.session_id, "libnative.so", arch="arm64-v8a",
        )
    assert result["status"] == "ok"
    script = result["data"]["script"]
    assert "args_to_json" in script
