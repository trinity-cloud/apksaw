"""Runtime Frida execution — closes the gap between static and dynamic analysis.

Three tools:

- ``repackage_with_gadget``  — inject frida-gadget, patch smali, repackage, sign, install.
- ``run_frida_script``       — drive the frida client against the gadget over adb-forward.
- ``capture_runtime_secrets`` — composed capture of Bearer tokens / crypto keys / WebView
  bridges using the Java-hook families exposed by ``frida_gen``.

This module is the dynamic execution bridge. The existing ``frida_gen`` tools
generate Frida scripts as text files; this module actually runs them on the
non-rooted target device and returns structured evidence.

All mutating tools accept a ``confirm: bool`` flag. ``confirm=False`` returns the
command plan without invoking any of apktool/apksigner/adb — mirroring the
posture of ``dynamic.py::prepare_frida_apk``.
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import time
import traceback
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from apksaw.config import TOOLS_DIR, APKTOOL_JAR
from apksaw.server import mcp
from apksaw.session import get_session
from apksaw.utils.adb import check_device_connected, run_adb

_ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Smali snippet that loads frida-gadget from the app's native libs directory.
_SMALI_LOAD_GADGET = (
    '    const-string v0, "frida-gadget"\n'
    "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
)

# Gadget config for listen mode (gadget waits for a Frida client to attach).
_GADGET_CONFIG_LISTEN = json.dumps({
    "interaction": {
        "type": "listen",
        "address": "127.0.0.1",
        "port": 27042,
        "on_load": "wait",
    }
})


# ---------------------------------------------------------------------------
# Internal helpers — tool availability probe
# ---------------------------------------------------------------------------

@dataclass
class ToolProbe:
    """Snapshot of which host-side repackaging tools are available."""
    apktool_cmd: Optional[str]
    zipalign: Optional[str]
    apksigner: Optional[str]
    frida_gadget_so: Optional[str]
    frida_python: bool
    frida_version: Optional[str]

    @property
    def all_ready(self) -> bool:
        return bool(
            self.apktool_cmd and self.zipalign and self.apksigner
            and self.frida_gadget_so
        )

    def to_dict(self) -> dict:
        return {
            "apktool": {"available": bool(self.apktool_cmd), "command": self.apktool_cmd},
            "zipalign": {"available": bool(self.zipalign), "path": self.zipalign},
            "apksigner": {"available": bool(self.apksigner), "path": self.apksigner},
            "frida_gadget_so": {
                "available": self.frida_gadget_so is not None,
                "path": self.frida_gadget_so,
                "note": (
                    "Download from https://github.com/frida/frida/releases — "
                    "place as "
                    f"{TOOLS_DIR / 'frida-gadget' / 'libfrida-gadget.so'}"
                    if self.frida_gadget_so is None else ""
                ),
            },
            "frida_tools_python": {
                "available": self.frida_python,
                "version": self.frida_version,
                "note": "Install via: pip install frida-tools" if not self.frida_python else "",
            },
        }


def _probe_host_tools() -> ToolProbe:
    """Discover apktool / zipalign / apksigner / frida-gadget / frida-python."""
    apktool_cmd: Optional[str] = None
    if APKTOOL_JAR.exists():
        apktool_cmd = f"java -jar {APKTOOL_JAR}"
    elif shutil.which("apktool"):
        apktool_cmd = "apktool"

    gadget_so: Optional[str] = None
    search_dirs = [
        TOOLS_DIR / "frida-gadget",
        Path.home() / ".apksaw" / "tools" / "frida-gadget",
        Path("/tmp/frida-gadget"),
    ]
    for d in search_dirs:
        candidate = d / "libfrida-gadget.so"
        if candidate.exists():
            gadget_so = str(candidate)
            break

    frida_python = False
    frida_version: Optional[str] = None
    try:
        import frida  # noqa: F401
        import importlib.metadata as md
        frida_python = True
        frida_version = md.version("frida")
    except Exception:
        pass

    return ToolProbe(
        apktool_cmd=apktool_cmd,
        zipalign=shutil.which("zipalign"),
        apksigner=shutil.which("apksigner"),
        frida_gadget_so=gadget_so,
        frida_python=frida_python,
        frida_version=frida_version,
    )


# ---------------------------------------------------------------------------
# ABI detection
# ---------------------------------------------------------------------------

_ABI_DIR_MAP = {
    "lib/arm64-v8a": "arm64-v8a",
    "lib/armeabi-v7a": "armeabi-v7a",
    "lib/x86": "x86",
    "lib/x86_64": "x86_64",
}


def _detected_abis(apk_path: str) -> list[str]:
    """Return device-relevant ABIs present in the APK, arm64 first.

    Returns an empty list if the file is not a valid zip (e.g. during dry-run
    on a partial file) — callers fall back to ``["arm64-v8a"]``.
    """
    import zipfile
    abis: list[str] = []
    try:
        with zipfile.ZipFile(apk_path) as z:
            names = z.namelist()
    except (zipfile.BadZipFile, FileNotFoundError, OSError):
        return abis
    for path, abi in _ABI_DIR_MAP.items():
        if any(f.startswith(path + "/") for f in names):
            abis.append(abi)
    abis.sort(key=lambda a: 0 if a == "arm64-v8a" else 1)
    return abis


def _gadget_so_for_abi(probe: ToolProbe, abi: str) -> Path:
    """Locate the matching libfrida-gadget.so for a given ABI.

    Convention: ``<TOOLS_DIR>/frida-gadget/libfrida-gadget-<abi>.so``
    Fall back to a single shared ``libfrida-gadget.so``.
    """
    candidate = TOOLS_DIR / "frida-gadget" / f"libfrida-gadget-{abi}.so"
    if candidate.exists():
        return candidate
    return TOOLS_DIR / "frida-gadget" / "libfrida-gadget.so"


# ---------------------------------------------------------------------------
# Launcher activity + Application class detection
# ---------------------------------------------------------------------------

def _resolve_class_name(apk, raw_name: str) -> str:
    """Expand a short class name to a fully-qualified Java class name."""
    pkg = apk.get_package() or ""
    name = (raw_name or "").strip()
    if not name:
        return ""
    if name.startswith("."):
        return pkg + name
    if "." in name:
        return name
    return f"{pkg}.{name}"


def _java_class_to_smali_relpath(class_name: str) -> str:
    """``com.foo.Bar`` -> ``com/foo/Bar.smali``."""
    cn = class_name.strip().rstrip(";")
    if cn.startswith("L"):
        cn = cn[1:]
    return cn.replace(".", "/") + ".smali"


def _find_smali_targets(session) -> tuple[str, list[str]]:
    """Locate smali classes to patch for early frida-gadget loading.

    Resolution priority:
    1. ``<application android:name=...>`` -> custom Application subclass.
    2. ``<activity>`` whose intent-filter has MAIN+LAUNCHER.
    3. ``apk.get_main_activity()``.

    Returns ``(primary_relpath, [backup_relpaths])``.
    """
    apk = session.apk
    candidates: list[str] = []
    try:
        manifest = apk.get_android_manifest_xml()
    except Exception:
        manifest = None

    def _attr(elem, name):
        return elem.get(f"{{{_ANDROID_NS}}}{name}") if elem is not None else None

    app_cls: Optional[str] = None
    if manifest is not None:
        app_elem = manifest.find("application")
        if app_elem is not None:
            app_name = _attr(app_elem, "name")
            if app_name:
                app_cls = _resolve_class_name(apk, app_name)
                if app_cls:
                    candidates.append(app_cls)
            for act in app_elem.findall("activity"):
                cls = _resolve_class_name(apk, _attr(act, "name") or "")
                if not cls:
                    continue
                is_launcher = False
                for filt in act.findall("intent-filter"):
                    actions = [_attr(a, "name") for a in filt.findall("action")]
                    cats = [_attr(c, "name") for c in filt.findall("category")]
                    if ("android.intent.action.MAIN" in actions
                            and "android.intent.category.LAUNCHER" in cats):
                        is_launcher = True
                        break
                if is_launcher and cls not in candidates:
                    candidates.append(cls)

    # Fallback: Androguard's main activity
    try:
        main_act = apk.get_main_activity()
        if main_act and main_act not in candidates:
            candidates.append(main_act)
    except Exception:
        pass

    if not candidates:
        pkg = getattr(session, "package_name", "") or ""
        candidates.append(f"{pkg}.MainActivity")

    chosen = candidates[0]
    return (
        _java_class_to_smali_relpath(chosen),
        [_java_class_to_smali_relpath(c) for c in candidates[1:]],
    )


# ---------------------------------------------------------------------------
# Smali patch injection
# ---------------------------------------------------------------------------

def _find_smali_files(decompiled_dir: Path, rel_path: str) -> list[Path]:
    """Return matching smali file paths across all multidex slots."""
    out: list[Path] = []
    for sub in ("smali", "smali_classes2", "smali_classes3", "smali_classes4"):
        p = decompiled_dir / sub / rel_path
        if p.exists():
            out.append(p)
    return out


_CLINIT_RE = re.compile(
    r"\.method\s+(?:public\s+|private\s+|protected\s+)?"
    r"static\s+constructor\s+<clinit>\(\)V"
)
_ONCREATE_RE = re.compile(
    r"\.method\s+(?:public\s+)?(?:final\s+)?"
    r"(?:\S+\s+)*onCreate\(Landroid/os/Bundle;\)V"
)
_LOCALS_RE = re.compile(r"\s*\.locals\s+\d+")
_REGISTERS_RE = re.compile(r"\s*\.registers\s+\d+")


def _patch_smali_text(src: str) -> tuple[str, str]:
    """Patch a smali file's source to inject loadLibrary.

    Returns ``(new_src, method_kind)`` where ``method_kind`` describes
    how the injection was done: ``clinit`` (existing), ``clinit_new``
    (synthesized), ``onCreate``, or ``noop`` (unchanged).
    """
    # Strategy 1: inject into existing <clinit>
    m = _CLINIT_RE.search(src)
    if m:
        return _prepend_after_method_header(src, m.start()), "clinit"

    # Strategy 2: synthesize <clinit> after the last .super line
    super_match = list(re.finditer(r"\.super\s+\S+", src))
    if super_match:
        insert_at = super_match[-1].end()
        clinit_block = (
            "\n\n.method static constructor <clinit>()V"
            "\n    .registers 1\n"
            + _SMALI_LOAD_GADGET
            + "    return-void\n"
            + ".end method\n"
        )
        return src[:insert_at] + clinit_block + src[insert_at:], "clinit_new"

    # Strategy 3: inject into onCreate
    m = _ONCREATE_RE.search(src)
    if m:
        return _prepend_after_method_header(src, m.start()), "onCreate"

    # Nothing found
    return src, "noop"


def _prepend_after_method_header(src: str, method_start: int) -> str:
    """Find the end of the ``.method ...`` header line and inject the load call
    after the ``.registers``/``.locals`` directive."""
    header_end = src.index("\n", method_start)
    body_start = header_end + 1

    # Find .locals or .registers line within the method body
    rest = src[body_start:]
    lines = rest.split("\n")
    insert_offset = 0
    for line in lines:
        if _LOCALS_RE.match(line) or _REGISTERS_RE.match(line):
            insert_offset += len(line) + 1  # +1 for newline
            break
        insert_offset += len(line) + 1

    injection_point = body_start + insert_offset
    injection = _SMALI_LOAD_GADGET
    return src[:injection_point] + injection + src[injection_point:]


def _patch_smali_load_gadget(
    decompiled_dir: Path, rel_path: str, backups: list[str]
) -> dict:
    """Patch the smali file with the loadLibrary prepend.

    Tries primary path then backups, across all multidex slots.
    Backs up the original to ``<file>.apksaw.bak`` before modification.
    """
    diagnostics: dict[str, Any] = {
        "patched": False,
        "patched_file": None,
        "method_kind": None,
        "candidates_tried": [],
    }
    all_targets = [rel_path] + backups
    for cand in all_targets:
        files = _find_smali_files(decompiled_dir, cand)
        for f in files:
            diagnostics["candidates_tried"].append(str(f))
            text = f.read_text(encoding="utf-8", errors="replace")
            backup = f.with_suffix(f.suffix + ".apksaw.bak")
            try:
                backup.write_text(text, encoding="utf-8")
            except Exception:
                pass
            new_text, kind = _patch_smali_text(text)
            if new_text == text:
                continue
            f.write_text(new_text, encoding="utf-8")
            diagnostics.update({
                "patched": True,
                "patched_file": str(f),
                "method_kind": kind,
                "backup": str(backup),
            })
            return diagnostics
    return diagnostics


# ---------------------------------------------------------------------------
# Subprocess + ADB helpers
# ---------------------------------------------------------------------------

def _run_tool(argv: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Run a host-side tool command. Returns (returncode, stdout, stderr)."""
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def _require_device() -> None:
    """Raise RuntimeError if no ADB device is connected."""
    if not check_device_connected():
        raise RuntimeError(
            "No ADB device connected. Connect a device and enable USB debugging."
        )


def _adb_serial() -> Optional[str]:
    """Get the connected device serial number."""
    try:
        out = run_adb("get-serialno", timeout=5)
        s = out.strip()
        return s if s and s != "unknown" else None
    except (RuntimeError, FileNotFoundError):
        return None


# ---------------------------------------------------------------------------
# Port forward management
# ---------------------------------------------------------------------------

def _alloc_free_port() -> int:
    """Allocate a free TCP port on the host."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@dataclass
class ForwardLease:
    """Manages an adb forward lease for the gadget port."""
    serial: str
    host_port: int
    device_port: int = 27042

    def open(self) -> None:
        args = ["forward", f"tcp:{self.host_port}", f"tcp:{self.device_port}"]
        if self.serial:
            run_adb("-s", self.serial, *args, timeout=10)
        else:
            run_adb(*args, timeout=10)

    def close(self) -> None:
        try:
            if self.serial:
                run_adb("-s", self.serial, "forward", "--remove", f"tcp:{self.host_port}", timeout=5)
            else:
                run_adb("forward", "--remove", f"tcp:{self.host_port}", timeout=5)
        except RuntimeError:
            pass


# ---------------------------------------------------------------------------
# Frida execution engine
# ---------------------------------------------------------------------------

def _wait_for_process(package_name: str, timeout_s: int = 30) -> Optional[str]:
    """Wait for a package's process to appear on device. Returns the PID."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            out = run_adb("shell", "pidof", package_name, timeout=5).strip()
            if out:
                return out.split()[0]
        except RuntimeError:
            pass
        time.sleep(1)
    return None


def _frida_attach_and_collect(
    host_port: int,
    package_name: str,
    script_js: str,
    duration_s: int,
) -> dict[str, Any]:
    """Attach to the gadget-injected app via the forwarded port and collect messages.

    Requires the app process to already be running on the device (the gadget
    will be listening on port 27042, forwarded to host_port).
    """
    import frida

    messages: list[dict[str, Any]] = []
    exceptions: list[dict[str, str]] = []

    device = frida.get_device(f"tcp@127.0.0.1:{host_port}", timeout=20)
    session = device.attach(package_name)

    def on_message(msg, _data):
        if msg["type"] == "send":
            messages.append({"payload": msg.get("payload"), "ts": time.time()})
        elif msg["type"] == "error":
            exceptions.append({
                "type": "frida_error",
                "description": msg.get("description", ""),
                "stack": msg.get("stack", ""),
            })
        else:
            messages.append({"text": msg.get("text", ""), "ts": time.time()})

    script = session.create_script(script_js)
    script.on("message", on_message)
    script.load()

    deadline = time.time() + duration_s
    try:
        while time.time() < deadline:
            time.sleep(0.5)
    finally:
        try:
            session.detach()
        except Exception:
            pass

    return {"messages": messages, "exceptions": exceptions}


def _exec_capture(
    session,
    script_js: str,
    duration_s: int,
    drive_action: Optional[str] = None,
) -> dict[str, Any]:
    """Spawn/attach, adb forward, run Frida, return parsed messages.

    Shared engine used by both ``run_frida_script`` and ``capture_runtime_secrets``.
    """
    pkg = session.package_name
    if not pkg:
        raise RuntimeError("Session has no package_name. Call load_apk first.")

    # Drive action: launch the app so the gadget starts listening
    if drive_action:
        run_adb("shell", *drive_action.split(), timeout=15)
        _wait_for_process(pkg, timeout_s=30)

    # Clean up any stale forwards, then set up ours
    try:
        run_adb("forward", "--remove-all", timeout=5)
    except RuntimeError:
        pass

    port = _alloc_free_port()
    serial = _adb_serial()
    lease = ForwardLease(serial=serial or "", host_port=port)
    lease.open()
    try:
        return _frida_attach_and_collect(
            host_port=port,
            package_name=pkg,
            script_js=script_js,
            duration_s=duration_s,
        )
    finally:
        lease.close()


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._\-]+"), r"\1[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "[JWT_REDACTED]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[GOOGLE_KEY_REDACTED]"),
]


def _redact_text(text: str) -> str:
    for pat, repl in _SECRET_PATTERNS:
        text = pat.sub(repl, text)
    return text


def _redact_message(msg: dict) -> dict:
    out = dict(msg)
    p = out.get("payload")
    if isinstance(p, str):
        out["payload"] = _redact_text(p)
    elif isinstance(p, dict):
        try:
            out["payload"] = json.loads(_redact_text(json.dumps(p)))
        except (json.JSONDecodeError, TypeError):
            pass
    if isinstance(out.get("text"), str):
        out["text"] = _redact_text(out["text"])
    return out


# ---------------------------------------------------------------------------
# Composed capture scripts (inline JS — not imported from frida_gen)
# ---------------------------------------------------------------------------

_BEARER_CAPTURE_JS = """\
// --- Bearer token / HTTP header capture ---
Java.perform(function () {
    try {
        var RequestBuilder = Java.use("okhttp3.Request$Builder");
        RequestBuilder.build.implementation = function () {
            var req = this.build();
            try {
                var headers = req.headers();
                var url = req.url().toString();
                for (var i = 0; i < headers.size(); i++) {
                    var name = headers.name(i);
                    var value = headers.value(i);
                    send({__apksaw_kind:"http_header", name: name, value: value, url: url});
                }
            } catch (e) {}
            return req;
        };
    } catch (e) {
        console.log("[apksaw] OkHttp Request$Builder hook skipped: " + e);
    }

    try {
        var HUC = Java.use("java.net.HttpURLConnection");
        HUC.getHeaderField.overload("java.lang.String").implementation = function (k) {
            var v = this.getHeaderField(k);
            if (v) send({__apksaw_kind:"http_header", name: k, value: v, url: "<HttpURLConnection>"});
            return v;
        };
    } catch (e) {
        console.log("[apksaw] HttpURLConnection hook skipped: " + e);
    }
});
"""

_CRYPTO_CAPTURE_JS = """\
// --- Crypto key / IV / keystore password capture ---
Java.perform(function () {
    function hexOf(arr) {
        var s = "";
        for (var i = 0; i < arr.length; i++) {
            s += ("0" + (arr[i] & 0xff).toString(16)).slice(-2);
        }
        return s;
    }

    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (k, a) {
            send({__apksaw_kind:"secret_key", algorithm: a, key_hex: hexOf(k), length: k.length});
            return this.$init(k, a);
        };
    } catch (e) {
        console.log("[apksaw] SecretKeySpec hook skipped: " + e);
    }

    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload("[B").implementation = function (iv) {
            send({__apksaw_kind:"iv", iv_hex: hexOf(iv), length: iv.length});
            return this.$init(iv);
        };
    } catch (e) {
        console.log("[apksaw] IvParameterSpec hook skipped: " + e);
    }

    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key").implementation = function (mode, key) {
            send({
                __apksaw_kind: "cipher_init",
                mode: mode,
                algorithm: this.getAlgorithm(),
                key_algorithm: key.getAlgorithm(),
                key_hex: hexOf(key.getEncoded())
            });
            return this.init(mode, key);
        };
        Cipher.init.overload(
            "int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec"
        ).implementation = function (mode, key, spec) {
            var ivHex = null;
            try {
                var IvPS = Java.use("javax.crypto.spec.IvParameterSpec");
                ivHex = hexOf(Java.cast(spec, IvPS).getIV());
            } catch (e) {}
            send({
                __apksaw_kind: "cipher_init",
                mode: mode,
                algorithm: this.getAlgorithm(),
                key_hex: hexOf(key.getEncoded()),
                iv_hex: ivHex
            });
            return this.init(mode, key, spec);
        };
    } catch (e) {
        console.log("[apksaw] Cipher hook skipped: " + e);
    }

    try {
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.load.overload("java.io.InputStream", "[C").implementation = function (stream, pw) {
            if (pw) {
                try {
                    var pwd = Java.use("java.lang.String").$new(pw);
                    send({__apksaw_kind: "keystore_load", password: pwd.toString()});
                } catch (e) {}
            }
            return this.load(stream, pw);
        };
    } catch (e) {
        console.log("[apksaw] KeyStore hook skipped: " + e);
    }
});
"""

_WEBVIEW_CAPTURE_JS = """\
// --- WebView URL / JS bridge capture ---
Java.perform(function () {
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (u) {
            send({__apksaw_kind: "webview_load", url: u});
            return this.loadUrl(u);
        };
        WebView.evaluateJavascript.overload(
            "java.lang.String", "android.webkit.ValueCallback"
        ).implementation = function (js, cb) {
            send({__apksaw_kind: "webview_js", js: js.substring(0, 4000)});
            return this.evaluateJavascript(js, cb);
        };
        WebView.addJavascriptInterface.overload(
            "java.lang.Object", "java.lang.String"
        ).implementation = function (obj, name) {
            send({
                __apksaw_kind: "js_bridge_registered",
                name: name,
                class_name: obj.getClass().getName()
            });
            return this.addJavascriptInterface(obj, name);
        };
    } catch (e) {
        console.log("[apksaw] WebView hooks skipped: " + e);
    }
});
"""

_IDENTIFIER_CAPTURE_JS = """\
// --- Device identifier capture ---
Java.perform(function () {
    try {
        var TM = Java.use("android.telephony.TelephonyManager");
        TM.getDeviceId.overload().implementation = function () {
            var v = this.getDeviceId();
            send({__apksaw_kind: "identifier", kind: "imei", value: v});
            return v;
        };
        TM.getSubscriberId.overload().implementation = function () {
            var v = this.getSubscriberId();
            send({__apksaw_kind: "identifier", kind: "imsi", value: v});
            return v;
        };
    } catch (e) {
        console.log("[apksaw] TelephonyManager hooks skipped: " + e);
    }

    try {
        var Secure = Java.use("android.provider.Settings$Secure");
        Secure.getString.overload(
            "android.content.ContentResolver", "java.lang.String"
        ).implementation = function (cr, k) {
            var v = this.getString(cr, k);
            if (k && (k.indexOf("android_id") >= 0 || k.indexOf("advertising_id") >= 0)) {
                send({__apksaw_kind: "identifier", kind: k, value: v});
            }
            return v;
        };
    } catch (e) {
        console.log("[apksaw] Settings$Secure hook skipped: " + e);
    }
});
"""


def _compose_capture_script(
    capture_bearers: bool = True,
    capture_keys: bool = True,
    capture_webview: bool = True,
    capture_identifiers: bool = True,
) -> str:
    """Build a combined Frida JS script from the selected hook families."""
    parts = ["// Composed by apksaw capture_runtime_secrets\n"]
    if capture_bearers:
        parts.append(_BEARER_CAPTURE_JS)
    if capture_keys:
        parts.append(_CRYPTO_CAPTURE_JS)
    if capture_webview:
        parts.append(_WEBVIEW_CAPTURE_JS)
    if capture_identifiers:
        parts.append(_IDENTIFIER_CAPTURE_JS)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Payload classification
# ---------------------------------------------------------------------------

def _classify_payload(p: dict) -> dict:
    """Map a Frida ``send`` payload dict into a structured finding."""
    if not isinstance(p, dict):
        return {"type": "unknown", "raw": str(p)[:500]}

    kind = p.get("__apksaw_kind")

    if kind == "http_header":
        name = (p.get("name") or "").lower()
        v = p.get("value") or ""
        if name == "authorization" and v.lower().startswith("bearer "):
            return {"type": "bearer", "endpoint": p.get("url"), "value": v}
        if "cookie" in name:
            return {"type": "cookie", "endpoint": p.get("url"), "value": v}
        if "api" in name and "key" in name:
            return {"type": "api_key_header", "endpoint": p.get("url"), "name": name, "value": v}
        return {"type": "http_header", "name": name, "value": v, "endpoint": p.get("url")}

    if kind in ("secret_key", "cipher_init"):
        return {
            "type": "crypto_key",
            "algorithm": p.get("algorithm"),
            "key_hex": p.get("key_hex"),
            "iv_hex": p.get("iv_hex"),
            "mode": p.get("mode"),
            "length": p.get("length"),
        }

    if kind == "iv":
        return {"type": "crypto_iv", "iv_hex": p.get("iv_hex"), "length": p.get("length")}

    if kind == "keystore_load":
        return {"type": "keystore_password", "value": p.get("password")}

    if kind == "webview_load":
        return {"type": "webview_url", "url": p.get("url")}

    if kind == "webview_js":
        return {"type": "webview_js", "js": p.get("js")}

    if kind == "js_bridge_registered":
        return {"type": "js_bridge", "name": p.get("name"), "class_name": p.get("class_name")}

    if kind == "identifier":
        return {"type": "device_identifier", "kind": p.get("kind"), "value": p.get("value")}

    return {"type": "unknown", "raw": p}


def _summarise_findings(classified: list[dict]) -> dict:
    """Count findings by type."""
    return dict(Counter(c["type"] for c in classified))


# ---------------------------------------------------------------------------
# Tool 1: repackage_with_gadget
# ---------------------------------------------------------------------------

@mcp.tool()
def repackage_with_gadget(
    session_id: str,
    out_apk: str = "",
    gadget_mode: str = "listen",
    install: bool = True,
    confirm: bool = False,
) -> dict:
    """Inject frida-gadget into the session's APK, repackage, sign, and install.

    This is the **execute** counterpart to ``prepare_frida_apk`` (which only
    describes the process). When ``confirm=True``, it runs the full pipeline:
    apktool decode → inject gadget .so + config → patch smali → apktool build →
    zipalign → apksigner → adb install.

    **Safety:** Frida-gadget injection modifies the APK and replaces its signature.
    Only proceed on apps you have authorisation to analyse. The repackaged APK
    must be uninstalled before the original can be reinstalled.

    Args:
        session_id: Active analysis session ID returned by load_apk.
        out_apk: Optional override for the signed output APK path. Default:
                 ``<session.workspace>/<pkg>_frida_signed.apk``.
        gadget_mode: ``"listen"`` (gadget waits on port 27042 for a Frida
                     client to attach — default) or ``"script"`` (gadget
                     auto-executes a bundled JS file at boot).
        install: If True, adb-install the signed APK after signing.
        confirm: Must be ``True`` to actually run apktool/apksigner/adb.
                 ``False`` returns the plan + tool_check without side effects.

    Returns:
        ``{"status": "ok"|"requires_consent"|"error", "data": {...}}``.
        Status ``requires_consent``: confirm was False. Status ``error``: a
        pipeline step failed (data includes which step and stderr tail).
    """
    try:
        session = get_session(session_id)
    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }

    probe = _probe_host_tools()
    apk_path = str(session.apk_path)
    package = session.package_name or session.apk_path.stem
    workspace = session.workspace

    frida_dir = workspace / "frida"
    frida_dir.mkdir(parents=True, exist_ok=True)
    decompiled = frida_dir / "decompiled"
    unsigned = frida_dir / f"{package}_frida_unsigned.apk"
    aligned = frida_dir / f"{package}_frida_aligned.apk"
    signed = Path(out_apk) if out_apk else frida_dir / f"{package}_frida_signed.apk"
    keystore = frida_dir / "debug.keystore"

    abis = _detected_abis(apk_path) or ["arm64-v8a"]

    plan = {
        "apk_path": apk_path,
        "package_name": package,
        "workspace": str(workspace),
        "decompiled_dir": str(decompiled),
        "out_apk": str(signed),
        "gadget_mode": gadget_mode,
        "install": install,
        "abis": abis,
        "tool_check": probe.to_dict(),
        "steps": [
            "apktool d → decompile",
            "copy libfrida-gadget.so → lib/<abi>/",
            "write gadget config",
            "patch smali (System.loadLibrary)",
            "apktool b → rebuild",
            "zipalign",
            "apksigner sign",
            "adb install" if install else "(skip install)",
        ],
    }

    if not confirm:
        return {
            "status": "requires_consent",
            "consent_required": True,
            "message": "Set confirm=True to actually repackage and install.",
            "data": plan,
        }

    if not probe.all_ready:
        missing = [
            k for k, v in probe.to_dict().items()
            if k != "frida_tools_python" and not v["available"]
        ]
        return {
            "status": "error",
            "message": f"Missing required tools: {', '.join(missing)}.",
            "data": plan,
        }

    try:
        _require_device()
    except RuntimeError as exc:
        return {"status": "error", "message": str(exc), "data": plan}

    execution_log: list[str] = []

    try:
        # Step 1: apktool decode
        execution_log.append("[1/8] Decompiling with apktool...")
        apktool_parts = probe.apktool_cmd.split()
        rc, so, se = _run_tool(
            apktool_parts + ["d", "-f", "-o", str(decompiled), apk_path],
            timeout=600,
        )
        if rc != 0:
            return {
                "status": "error",
                "step": "apktool_decompile",
                "message": "apktool d failed.",
                "stderr": se[-2000:],
                "stdout": so[-2000:],
                "data": plan,
            }
        execution_log.append(f"  decompiled to {decompiled}")

        # Step 2: copy gadget .so for each ABI
        execution_log.append("[2/8] Copying frida-gadget .so for ABIs: " + ", ".join(abis))
        gadget_paths: list[str] = []
        for abi in abis:
            target_dir = decompiled / "lib" / abi
            target_dir.mkdir(parents=True, exist_ok=True)
            gadget_src = _gadget_so_for_abi(probe, abi)
            if not gadget_src.exists():
                return {
                    "status": "error",
                    "step": "gadget_missing",
                    "message": f"libfrida-gadget.so not found for ABI {abi}.",
                    "expected_at": str(gadget_src),
                    "data": plan,
                }
            target = target_dir / "libfrida-gadget.so"
            shutil.copy2(str(gadget_src), str(target))
            gadget_paths.append(str(target))
        execution_log.append(f"  gadget copied for {len(abis)} ABI(s)")

        # Step 3: write gadget config
        execution_log.append(f"[3/8] Writing gadget config ({gadget_mode} mode)...")
        for abi in abis:
            cfg = decompiled / "lib" / abi / "libfrida-gadget.config.so"
            cfg.write_text(_GADGET_CONFIG_LISTEN, encoding="utf-8")
        execution_log.append("  config written")

        # Step 4: patch smali
        execution_log.append("[4/8] Patching smali to inject System.loadLibrary...")
        rel, backups = _find_smali_targets(session)
        smali_diag = _patch_smali_load_gadget(decompiled, rel, backups)
        if not smali_diag["patched"]:
            return {
                "status": "error",
                "step": "smali_patch",
                "message": "No smali file found for loadLibrary injection.",
                "diagnostics": smali_diag,
                "suggestion": "Ensure the APK has a standard Application or launcher Activity.",
                "data": plan,
            }
        execution_log.append(f"  patched {smali_diag['patched_file']} ({smali_diag['method_kind']})")

        # Step 5: apktool build
        execution_log.append("[5/8] Rebuilding APK with apktool...")
        rc, so, se = _run_tool(
            apktool_parts + ["b", str(decompiled), "-o", str(unsigned)],
            timeout=1200,
        )
        if rc != 0:
            return {
                "status": "error",
                "step": "apktool_build",
                "message": "apktool b failed.",
                "stderr": se[-2000:],
                "data": plan,
            }
        execution_log.append(f"  rebuilt to {unsigned}")

        # Step 6: zipalign
        execution_log.append("[6/8] Zipaligning...")
        rc, so, se = _run_tool(
            [probe.zipalign, "-p", "4", str(unsigned), str(aligned)],
            timeout=120,
        )
        if rc != 0:
            return {
                "status": "error",
                "step": "zipalign",
                "message": "zipalign failed.",
                "stderr": se[-2000:],
                "data": plan,
            }
        execution_log.append(f"  aligned to {aligned}")

        # Step 7: create keystore (if needed) + sign
        execution_log.append("[7/8] Signing APK...")
        if not keystore.exists():
            rc, so, se = _run_tool([
                "keytool", "-genkey", "-v", "-keystore", str(keystore),
                "-alias", "androiddebugkey",
                "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                "-storepass", "android", "-keypass", "android",
                "-dname", "CN=Android Debug,O=Android,C=US",
            ], timeout=60)
            if rc != 0:
                return {
                    "status": "error",
                    "step": "keytool",
                    "message": "keytool failed to create keystore.",
                    "stderr": se[-2000:],
                    "data": plan,
                }
        rc, so, se = _run_tool([
            probe.apksigner, "sign",
            "--ks", str(keystore),
            "--ks-pass", "pass:android",
            "--key-pass", "pass:android",
            "--out", str(signed), str(aligned),
        ], timeout=120)
        if rc != 0:
            return {
                "status": "error",
                "step": "apksigner_sign",
                "message": "apksigner failed.",
                "stderr": se[-2000:],
                "data": plan,
            }
        execution_log.append(f"  signed to {signed}")

        # Step 8: install
        install_result: Optional[str] = None
        if install:
            execution_log.append("[8/8] Installing on device...")
            try:
                run_adb("uninstall", package, timeout=30)
            except RuntimeError:
                pass  # not installed — fine
            try:
                install_result = run_adb("install", str(signed), timeout=120)
                execution_log.append(f"  installed {package}")
            except RuntimeError as exc:
                install_result = f"install_failed: {exc}"
                execution_log.append(f"  install failed: {exc}")

        return {
            "status": "ok",
            "data": {
                **plan,
                "execution_log": execution_log,
                "out_apk": str(signed),
                "abis_installed": abis,
                "gadget_paths": gadget_paths,
                "smali_patch": smali_diag,
                "install_result": install_result,
                "next_action": (
                    "Launch the app once on device (the gadget will start listening "
                    "on port 27042). Then call run_frida_script or "
                    "capture_runtime_secrets to attach."
                ),
            },
        }

    except subprocess.TimeoutExpired as exc:
        return {
            "status": "error",
            "step": "timeout",
            "message": f"A pipeline step timed out: {exc}",
            "data": plan,
        }


# ---------------------------------------------------------------------------
# Tool 2: run_frida_script
# ---------------------------------------------------------------------------

@mcp.tool()
def run_frida_script(
    session_id: str,
    script: str,
    target: str = "spawn",
    duration_s: int = 60,
    redact_secrets: bool = True,
) -> dict:
    """Execute a Frida JavaScript hook on the target app and return captured output.

    The APK must already have frida-gadget injected (via ``repackage_with_gadget``
    or manually). This tool launches the app, sets up an adb port forward to the
    gadget, attaches Frida, loads the script, and collects output for the
    specified duration.

    Args:
        session_id: Active analysis session ID.
        script: Either an inline JS string OR a path to a ``.js`` file
                (e.g. output of ``generate_ssl_bypass``). Detected by checking
                if the string looks like a filesystem path to an existing file.
        target: ``"spawn"`` (launch the app fresh, then attach) or
                ``"attach"`` (assume the app process is already running).
        duration_s: How long to capture output. Clamped to [1, 600]. Default 60.
        redact_secrets: If True, mask Bearer/JWT/Google API keys in returned
                        values to keep secrets out of chat logs.

    Returns:
        ``{"status": "ok", "data": {"messages": [...], "exceptions": [...],
        "duration_s": N, "script_path": "..."}}``.
    """
    duration_s = min(max(1, duration_s), 600)

    try:
        session = get_session(session_id)
    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }

    pkg = session.package_name
    if not pkg:
        return {"status": "error", "message": "Session has no package_name."}

    # Resolve the script: either an existing file path or inline JS
    script_js: Optional[str] = None
    script_path_str: Optional[str] = None

    candidate = Path(script)
    if candidate.exists() and candidate.suffix == ".js":
        script_js = candidate.read_text(encoding="utf-8")
        script_path_str = str(candidate)
    else:
        # Inline JS — write to workspace for traceability
        scripts_dir = session.workspace / "frida_scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        script_path = scripts_dir / "user_inline.js"
        script_path.write_text(script, encoding="utf-8")
        script_js = script
        script_path_str = str(script_path)

    # Check device + frida availability
    try:
        _require_device()
    except RuntimeError as exc:
        return {"status": "error", "message": str(exc)}

    try:
        import frida  # noqa: F401
    except ImportError:
        return {
            "status": "error",
            "message": "frida-tools is not installed.",
            "suggestion": "Install with: pip install frida-tools (or uv sync --extra dynamic)",
        }

    # Determine drive action
    drive_action: Optional[str] = None
    if target == "spawn":
        try:
            main_activity = session.apk.get_main_activity()
        except Exception:
            main_activity = None
        comp = main_activity or f"{pkg}/.MainActivity"
        drive_action = f"am start -n {comp}"
    elif target == "attach":
        drive_action = None
    else:
        return {
            "status": "error",
            "message": f"Invalid target '{target}'. Must be 'spawn' or 'attach'.",
        }

    try:
        result = _exec_capture(
            session=session,
            script_js=script_js,
            duration_s=duration_s,
            drive_action=drive_action,
        )
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Frida execution failed: {exc}",
            "traceback": traceback.format_exc(),
        }

    messages = result["messages"]
    if redact_secrets:
        messages = [_redact_message(m) for m in messages]

    return {
        "status": "ok",
        "data": {
            "messages": messages,
            "exceptions": result["exceptions"],
            "duration_s": duration_s,
            "host_port": "auto",
            "script_path": script_path_str,
            "message_count": len(messages),
        },
    }


# ---------------------------------------------------------------------------
# Tool 3: capture_runtime_secrets
# ---------------------------------------------------------------------------

@mcp.tool()
def capture_runtime_secrets(
    session_id: str,
    duration_s: int = 45,
    capture_bearers: bool = True,
    capture_keys: bool = True,
    capture_webview: bool = True,
    capture_identifiers: bool = True,
    drive_action: str = "launcher",
    redact_secrets: bool = True,
) -> dict:
    """Boot the gadget-injected target and capture live secrets at runtime.

    Composes the token-dumper + crypto hooks + WebView bridge hooks + device
    identifier hooks into a single Frida script, launches the app, and returns
    all intercepted secrets as structured findings.

    This is the **one-call answer** to the Hinge case-study gap: the scanner
    found an empty CertificatePinner but couldn't capture the live Bearer token.
    With this tool, the agent gets the actual token value + endpoint as evidence.

    Args:
        session_id: Active analysis session ID returned by load_apk.
        duration_s: Total capture window. Clamped to [1, 600]. Default 45.
        capture_bearers: Hook OkHttp Request$Builder.build + HttpURLConnection.
        capture_keys: Hook SecretKeySpec + IvParameterSpec + Cipher + KeyStore.
        capture_webview: Hook WebView.addJavascriptInterface / loadUrl /
                         evaluateJavascript.
        capture_identifiers: Hook TelephonyManager.getDeviceId /
                             Settings$Secure for android_id.
        drive_action: ``"launcher"`` (start MAIN/LAUNCHER activity — default),
                      ``"existing"`` (use already-running process), or a literal
                      adb command string starting with ``"am "``.
        redact_secrets: Apply bearer/JWT/key redaction to returned values.

    Returns:
        ``{"status": "ok", "data": {"secrets": [...], "webview": [...],
        "endpoints": [...], "summary": {...}, "script_path": "..."}}``.
    """
    duration_s = min(max(1, duration_s), 600)

    try:
        session = get_session(session_id)
    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }

    pkg = session.package_name
    if not pkg:
        return {"status": "error", "message": "Session has no package_name."}

    # Compose the combined script
    composed_js = _compose_capture_script(
        capture_bearers=capture_bearers,
        capture_keys=capture_keys,
        capture_webview=capture_webview,
        capture_identifiers=capture_identifiers,
    )
    scripts_dir = session.workspace / "frida_scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    script_path = scripts_dir / "capture_runtime_secrets.js"
    script_path.write_text(composed_js, encoding="utf-8")

    # Resolve drive action
    drive: Optional[str] = None
    if drive_action == "launcher":
        try:
            main_activity = session.apk.get_main_activity()
        except Exception:
            main_activity = None
        comp = main_activity or f"{pkg}/.MainActivity"
        drive = f"am start -n {comp}"
    elif drive_action == "existing":
        drive = None
    elif isinstance(drive_action, str) and drive_action.startswith("am "):
        drive = drive_action

    # Check device + frida availability
    try:
        _require_device()
    except RuntimeError as exc:
        return {"status": "error", "message": str(exc)}

    try:
        import frida  # noqa: F401
    except ImportError:
        return {
            "status": "error",
            "message": "frida-tools is not installed.",
            "suggestion": "Install with: pip install frida-tools (or uv sync --extra dynamic)",
        }

    try:
        result = _exec_capture(
            session=session,
            script_js=composed_js,
            duration_s=duration_s,
            drive_action=drive,
        )
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Frida execution failed: {exc}",
            "traceback": traceback.format_exc(),
        }

    messages = result["messages"]
    payloads = [
        m.get("payload") for m in messages
        if isinstance(m.get("payload"), dict)
    ]
    classified = [_classify_payload(p) for p in payloads]

    if redact_secrets:
        classified = [
            {**c, "value": _redact_text(c["value"])} if "value" in c else c
            for c in classified
        ]

    secrets = [
        c for c in classified
        if c["type"] not in ("webview_url", "webview_js", "js_bridge")
    ]
    webview = [
        c for c in classified
        if c["type"] in ("webview_url", "webview_js", "js_bridge")
    ]
    endpoints = sorted({
        c.get("endpoint", "") for c in classified if c.get("endpoint")
    })

    return {
        "status": "ok",
        "consent_required": True,
        "data": {
            "secrets": secrets,
            "webview": webview,
            "endpoints": [e for e in endpoints if e],
            "summary": _summarise_findings(classified),
            "exceptions": result["exceptions"],
            "script_path": str(script_path),
            "duration_s": duration_s,
            "message_count": len(messages),
        },
    }
