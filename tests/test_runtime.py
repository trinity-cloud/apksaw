"""Tests for runtime Frida execution tools."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

# Pre-import tool functions at collection time (conftest.py stubs mcp/androguard)
from apksaw.tools.runtime import (
    repackage_with_gadget,
    run_frida_script,
    capture_runtime_secrets,
    _classify_payload,
    _redact_text,
    _patch_smali_text,
    _java_class_to_smali_relpath,
    _compose_capture_script,
)

_RT = "apksaw.tools.runtime"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _inject_session(mock_session):
    """Patch get_session in the runtime module to return mock_session."""
    return patch(f"{_RT}.get_session", return_value=mock_session)


# ---------------------------------------------------------------------------
# repackage_with_gadget — consent gate
# ---------------------------------------------------------------------------


def test_repackage_requires_consent(mock_session):
    """repackage_with_gadget returns requires_consent when confirm=False."""
    with _inject_session(mock_session):
        result = repackage_with_gadget(mock_session.session_id, confirm=False)

    assert result["status"] == "requires_consent"
    assert result["consent_required"] is True
    assert "plan" not in result["data"] or "tool_check" in result["data"]
    assert "tool_check" in result["data"]


def test_repackage_bad_session_returns_error():
    """repackage_with_gadget returns error for unknown session."""
    with patch(f"{_RT}.get_session", side_effect=KeyError("not found")):
        result = repackage_with_gadget("bad", confirm=False)

    assert result["status"] == "error"
    assert "suggestion" in result


# ---------------------------------------------------------------------------
# repackage_with_gadget — plan structure
# ---------------------------------------------------------------------------


def test_repackage_plan_has_abis(mock_session):
    """The dry-run plan includes ABI detection."""
    with _inject_session(mock_session):
        result = repackage_with_gadget(mock_session.session_id, confirm=False)

    data = result["data"]
    assert "abis" in data
    assert isinstance(data["abis"], list)
    assert "package_name" in data
    assert data["package_name"] == "com.example.testapp"


def test_repackage_plan_has_tool_check(mock_session):
    """The dry-run plan includes tool availability status."""
    with _inject_session(mock_session):
        result = repackage_with_gadget(mock_session.session_id, confirm=False)

    tool_check = result["data"]["tool_check"]
    assert "apktool" in tool_check
    assert "zipalign" in tool_check
    assert "apksigner" in tool_check
    assert "frida_gadget_so" in tool_check
    assert "frida_tools_python" in tool_check


def test_repackage_confirm_true_missing_tools_returns_error(mock_session):
    """When confirm=True but tools are missing, returns error."""
    with _inject_session(mock_session):
        with patch(f"{_RT}._probe_host_tools") as mock_probe:
            mock_probe.return_value = MagicMock()
            mock_probe.return_value.all_ready = False
            mock_probe.return_value.to_dict.return_value = {
                "apktool": {"available": False},
                "zipalign": {"available": False},
                "apksigner": {"available": False},
                "frida_gadget_so": {"available": False},
                "frida_tools_python": {"available": False},
            }
            result = repackage_with_gadget(mock_session.session_id, confirm=True)

    assert result["status"] == "error"
    assert "Missing required tools" in result["message"]


# ---------------------------------------------------------------------------
# smali patching helpers
# ---------------------------------------------------------------------------


def test_java_class_to_smali_relpath():
    """Java class name converts to the correct smali relative path."""
    assert _java_class_to_smali_relpath("com.example.MainActivity") == "com/example/MainActivity.smali"
    assert _java_class_to_smali_relpath("Lcom/example/MainActivity;") == "com/example/MainActivity.smali"


def test_patch_smali_text_existing_clinit():
    """_patch_smali_text injects into an existing <clinit>."""
    src = (
        ".class public Lcom/example/App;\n"
        ".super Landroid/app/Application;\n"
        "\n"
        ".method static constructor <clinit>()V\n"
        "    .registers 1\n"
        "\n"
        "    return-void\n"
        ".end method\n"
    )
    new_src, kind = _patch_smali_text(src)
    assert kind == "clinit"
    assert "frida-gadget" in new_src
    assert "loadLibrary" in new_src
    # Should be after .registers line
    reg_pos = new_src.index(".registers")
    gadget_pos = new_src.index("frida-gadget")
    assert gadget_pos > reg_pos


def test_patch_smali_text_synthesize_clinit():
    """_patch_smali_text synthesizes a <clinit> when none exists."""
    src = (
        ".class public Lcom/example/App;\n"
        ".super Landroid/app/Application;\n"
        "\n"
        ".method public onCreate()V\n"
        "    .registers 1\n"
        "    return-void\n"
        ".end method\n"
    )
    new_src, kind = _patch_smali_text(src)
    assert kind == "clinit_new"
    assert "frida-gadget" in new_src
    assert "<clinit>" in new_src
    # Clinit block should appear after .super
    super_pos = new_src.index(".super")
    clinit_pos = new_src.index("<clinit>")
    assert clinit_pos > super_pos


def test_patch_smali_text_oncreate_fallback():
    """_patch_smali_text injects into onCreate when no clinit and no .super."""
    src = (
        ".method public onCreate(Landroid/os/Bundle;)V\n"
        "    .locals 1\n"
        "    return-void\n"
        ".end method\n"
    )
    new_src, kind = _patch_smali_text(src)
    assert kind == "onCreate"
    assert "frida-gadget" in new_src


def test_patch_smali_text_noop():
    """_patch_smali_text returns noop when nothing matches."""
    src = "no smali here\njust random text\n"
    new_src, kind = _patch_smali_text(src)
    assert kind == "noop"
    assert new_src == src


def test_patch_smali_load_gadget_end_to_end(tmp_path):
    """The full _patch_smali_load_gadget function patches a real smali file."""
    from apksaw.tools.runtime import _patch_smali_load_gadget

    # Create a fake decompiled directory
    smali_dir = tmp_path / "smali" / "com" / "example"
    smali_dir.mkdir(parents=True)
    smali_file = smali_dir / "MainActivity.smali"
    smali_file.write_text(
        ".class public Lcom/example/MainActivity;\n"
        ".super Landroid/app/Activity;\n"
        "\n"
        ".method public onCreate(Landroid/os/Bundle;)V\n"
        "    .locals 1\n"
        "\n"
        "    return-void\n"
        ".end method\n"
    )

    diag = _patch_smali_load_gadget(
        tmp_path,
        "com/example/MainActivity.smali",
        [],
    )
    assert diag["patched"] is True
    assert diag["method_kind"] == "clinit_new"
    patched_text = smali_file.read_text()
    assert "frida-gadget" in patched_text

    # Backup should exist
    backup = smali_file.with_suffix(".smali.apksaw.bak")
    assert backup.exists()
    assert "frida-gadget" not in backup.read_text()


# ---------------------------------------------------------------------------
# Payload classification
# ---------------------------------------------------------------------------


def test_classify_bearer_payload():
    """_classify_payload identifies a Bearer token from an HTTP header."""
    out = _classify_payload({
        "__apksaw_kind": "http_header",
        "name": "Authorization",
        "value": "Bearer eyJhbGciOi.eyJzdWIiOiJ0.InR5cCI6IkpXVCJ9",
        "url": "https://example.com/v1/me",
    })
    assert out["type"] == "bearer"
    assert out["endpoint"] == "https://example.com/v1/me"
    assert out["value"].startswith("Bearer ")


def test_classify_crypto_key_payload():
    """_classify_payload identifies a SecretKeySpec key."""
    out = _classify_payload({
        "__apksaw_kind": "secret_key",
        "algorithm": "AES",
        "key_hex": "deadbeef",
        "length": 16,
    })
    assert out["type"] == "crypto_key"
    assert out["algorithm"] == "AES"
    assert out["key_hex"] == "deadbeef"


def test_classify_iv_payload():
    """_classify_payload identifies an IV."""
    out = _classify_payload({
        "__apksaw_kind": "iv",
        "iv_hex": "cafebabe",
        "length": 16,
    })
    assert out["type"] == "crypto_iv"
    assert out["iv_hex"] == "cafebabe"


def test_classify_keystore_password():
    """_classify_payload identifies a keystore password."""
    out = _classify_payload({
        "__apksaw_kind": "keystore_load",
        "password": "s3cr3t",
    })
    assert out["type"] == "keystore_password"
    assert out["value"] == "s3cr3t"


def test_classify_webview_url():
    """_classify_payload identifies a WebView URL load."""
    out = _classify_payload({
        "__apksaw_kind": "webview_load",
        "url": "https://evil.example.com/payload",
    })
    assert out["type"] == "webview_url"
    assert out["url"] == "https://evil.example.com/payload"


def test_classify_js_bridge():
    """_classify_payload identifies a JS bridge registration."""
    out = _classify_payload({
        "__apksaw_kind": "js_bridge_registered",
        "name": "WebAppInterface",
        "class_name": "com.example.WebAppInterface",
    })
    assert out["type"] == "js_bridge"
    assert out["name"] == "WebAppInterface"


def test_classify_identifier():
    """_classify_payload identifies a device identifier."""
    out = _classify_payload({
        "__apksaw_kind": "identifier",
        "kind": "imei",
        "value": "123456789012345",
    })
    assert out["type"] == "device_identifier"
    assert out["kind"] == "imei"


def test_classify_unknown_payload():
    """_classify_payload handles unknown payloads."""
    out = _classify_payload({"unrelated": "data"})
    assert out["type"] == "unknown"

    out2 = _classify_payload("not a dict")
    assert out2["type"] == "unknown"


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


def test_redact_bearer_token():
    """_redact_text masks Bearer tokens."""
    text = "Authorization: Bearer eyJhbGciOiJIUzI1.eyJzdWIiOiJ0.InR5cCI6IkpXVCJ9"
    redacted = _redact_text(text)
    assert "REDACTED" in redacted
    assert "eyJhbGciOiJIUzI1" not in redacted


def test_redact_jwt():
    """_redact_text masks bare JWT tokens."""
    text = "token: eyJhbGciOiJIUzI1.eyJzdWIiOiJ0.InR5cCI6IkpXVCJ9"
    redacted = _redact_text(text)
    assert "JWT_REDACTED" in redacted


def test_redact_google_key():
    """_redact_text masks Google API keys."""
    text = "key=AIzaSyABC123XYZ456abc789def012ghi345jkl"
    redacted = _redact_text(text)
    assert "GOOGLE_KEY_REDACTED" in redacted


def test_redact_plain_text_unchanged():
    """_redact_text leaves non-secret text alone."""
    text = "This is just a normal log line."
    assert _redact_text(text) == text


# ---------------------------------------------------------------------------
# run_frida_script — error paths
# ---------------------------------------------------------------------------


def test_run_frida_script_bad_session():
    """run_frida_script returns error for unknown session."""
    with patch(f"{_RT}.get_session", side_effect=KeyError("not found")):
        result = run_frida_script("bad", script="console.log('x')")

    assert result["status"] == "error"
    assert "suggestion" in result


def test_run_frida_script_no_frida_tools(mock_session):
    """run_frida_script returns clear error when frida-tools not installed."""
    original_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def mock_import(name, *args, **kwargs):
        if name == "frida":
            raise ImportError("No module named 'frida'")
        return original_import(name, *args, **kwargs)

    with _inject_session(mock_session):
        with patch(f"{_RT}._require_device"):
            with patch("builtins.__import__", side_effect=mock_import):
                result = run_frida_script(
                    mock_session.session_id,
                    script="console.log('x')",
                )

    assert result["status"] == "error"
    assert "frida-tools" in result["message"].lower()
    assert "pip install" in result.get("suggestion", "").lower()


def test_run_frida_script_no_device(mock_session):
    """run_frida_script returns error when no device connected."""
    with _inject_session(mock_session):
        with patch(f"{_RT}._require_device", side_effect=RuntimeError("No ADB device")):
            result = run_frida_script(
                mock_session.session_id,
                script="console.log('x')",
            )

    assert result["status"] == "error"
    assert "device" in result["message"].lower()


def test_run_frida_script_invalid_target(mock_session):
    """run_frida_script rejects invalid target parameter."""
    with _inject_session(mock_session):
        with patch(f"{_RT}._require_device"):
            with patch.dict("sys.modules", {"frida": MagicMock()}):
                result = run_frida_script(
                    mock_session.session_id,
                    script="console.log('x')",
                    target="invalid",
                )

    assert result["status"] == "error"
    assert "target" in result["message"].lower()


def test_run_frida_script_writes_inline_js(mock_session):
    """run_frida_script writes inline JS to workspace."""
    with _inject_session(mock_session):
        with patch(f"{_RT}._require_device"):
            with patch.dict("sys.modules", {"frida": MagicMock()}):
                with patch(f"{_RT}._exec_capture", side_effect=RuntimeError("stop")):
                    run_frida_script(
                        mock_session.session_id,
                        script="console.log('hello');",
                        target="attach",
                    )

    # It should have written the inline JS
    expected_path = mock_session.workspace / "frida_scripts" / "user_inline.js"
    assert expected_path.exists()
    assert "console.log" in expected_path.read_text()


# ---------------------------------------------------------------------------
# capture_runtime_secrets — error paths + composition
# ---------------------------------------------------------------------------


def test_capture_runtime_secrets_bad_session():
    """capture_runtime_secrets returns error for unknown session."""
    with patch(f"{_RT}.get_session", side_effect=KeyError("not found")):
        result = capture_runtime_secrets("bad")

    assert result["status"] == "error"


def test_capture_runtime_secrets_no_frida_tools(mock_session):
    """capture_runtime_secrets returns clear error when frida not installed."""
    original_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def mock_import(name, *args, **kwargs):
        if name == "frida":
            raise ImportError("No module named 'frida'")
        return original_import(name, *args, **kwargs)

    with _inject_session(mock_session):
        with patch(f"{_RT}._require_device"):
            with patch("builtins.__import__", side_effect=mock_import):
                result = capture_runtime_secrets(mock_session.session_id)

    assert result["status"] == "error"
    assert "frida-tools" in result["message"].lower()


def test_capture_composes_script(mock_session):
    """capture_runtime_secrets writes a composed script before executing."""
    with _inject_session(mock_session):
        with patch(f"{_RT}._require_device"):
            with patch.dict("sys.modules", {"frida": MagicMock()}):
                with patch(f"{_RT}._exec_capture", side_effect=RuntimeError("stop")):
                    capture_runtime_secrets(mock_session.session_id)

    script_path = mock_session.workspace / "frida_scripts" / "capture_runtime_secrets.js"
    assert script_path.exists()
    content = script_path.read_text()
    assert "capture_runtime_secrets" in content
    assert "Java.perform" in content


def test_capture_compose_selective():
    """_compose_capture_script respects hook family flags."""
    full = _compose_capture_script()
    assert "http_header" in full
    assert "secret_key" in full
    assert "webview_load" in full
    assert "TelephonyManager" in full

    no_bearers = _compose_capture_script(capture_bearers=False)
    assert "http_header" not in no_bearers
    assert "secret_key" in no_bearers

    no_keys = _compose_capture_script(capture_keys=False)
    assert "secret_key" not in no_keys
    assert "webview_load" in no_keys


# ---------------------------------------------------------------------------
# capture_runtime_secrets — aggregation
# ---------------------------------------------------------------------------


def test_capture_aggregates_findings(mock_session):
    """capture_runtime_secrets classifies Frida messages into structured findings."""
    fake_messages = [
        {"payload": {
            "__apksaw_kind": "http_header",
            "name": "Authorization",
            "value": "Bearer test_token_123",
            "url": "https://api.example.com/v1/me",
        }, "ts": 0},
        {"payload": {
            "__apksaw_kind": "secret_key",
            "algorithm": "AES",
            "key_hex": "deadbeefdeadbeefdeadbeefdeadbeef",
            "length": 16,
        }, "ts": 0},
        {"payload": {
            "__apksaw_kind": "webview_load",
            "url": "https://app.example.com/dashboard",
        }, "ts": 0},
    ]

    fake_result = {"messages": fake_messages, "exceptions": []}

    with _inject_session(mock_session):
        with patch(f"{_RT}._require_device"):
            with patch.dict("sys.modules", {"frida": MagicMock()}):
                with patch(f"{_RT}._exec_capture", return_value=fake_result):
                    result = capture_runtime_secrets(
                        mock_session.session_id,
                        redact_secrets=False,
                    )

    assert result["status"] == "ok"
    data = result["data"]
    # Secrets should include bearer + crypto_key
    secret_types = {s["type"] for s in data["secrets"]}
    assert "bearer" in secret_types
    assert "crypto_key" in secret_types
    # WebView findings separated
    assert len(data["webview"]) == 1
    assert data["webview"][0]["type"] == "webview_url"
    # Endpoints extracted
    assert "https://api.example.com/v1/me" in data["endpoints"]
    # Summary has counts
    assert data["summary"]["bearer"] == 1
    assert data["summary"]["crypto_key"] == 1


def test_capture_redacts_by_default(mock_session):
    """capture_runtime_secrets redacts secrets by default."""
    fake_messages = [
        {"payload": {
            "__apksaw_kind": "http_header",
            "name": "Authorization",
            "value": "Bearer eyJhbGciOiJIUzI1.eyJzdWIiOiJ0.InR5cCI6IkpXVCJ9",
            "url": "https://api.example.com/v1/me",
        }, "ts": 0},
    ]

    fake_result = {"messages": fake_messages, "exceptions": []}

    with _inject_session(mock_session):
        with patch(f"{_RT}._require_device"):
            with patch.dict("sys.modules", {"frida": MagicMock()}):
                with patch(f"{_RT}._exec_capture", return_value=fake_result):
                    result = capture_runtime_secrets(mock_session.session_id)

    assert result["status"] == "ok"
    bearer = result["data"]["secrets"][0]
    assert "REDACTED" in bearer["value"]
    assert "eyJhbGciOiJIUzI1" not in bearer["value"]


# ---------------------------------------------------------------------------
# Tool registration check
# ---------------------------------------------------------------------------


def test_runtime_tools_registered():
    """All three runtime tools are registered with the MCP server.

    Under pytest the root conftest.py stubs mcp with a MagicMock (so .tool()
    is a no-op), so we verify via the module-level import chain instead.
    """
    # The three functions must be importable from the runtime module,
    # which itself is imported by server.py during normal startup.
    import apksaw.tools.runtime as rt
    assert callable(rt.repackage_with_gadget)
    assert callable(rt.run_frida_script)
    assert callable(rt.capture_runtime_secrets)

    # Verify server.py imports the runtime module (the registration mechanism)
    import apksaw.server as srv
    assert "runtime" in dir(srv) or hasattr(srv, "runtime")
