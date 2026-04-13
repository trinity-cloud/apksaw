"""Frida JavaScript hook generator for Android APK analysis.

Generates ready-to-use Frida scripts based on static analysis of the APK.
All generated scripts target the Java layer via the Frida Java bridge.
"""

import re
import traceback
from pathlib import Path
from typing import Optional

from apksaw.server import mcp
from apksaw.session import get_session


# ---------------------------------------------------------------------------
# Dalvik / Java type conversion helpers
# ---------------------------------------------------------------------------

def _dalvik_to_java(name: str) -> str:
    """Convert a Dalvik class descriptor to a Java class name.

    Examples:
        ``Lcom/example/Foo;`` -> ``com.example.Foo``
        ``com.example.Foo``   -> ``com.example.Foo``
    """
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def _java_to_dalvik(name: str) -> str:
    """Convert a Java class name to a Dalvik type descriptor.

    Examples:
        ``com.example.Foo``   -> ``Lcom/example/Foo;``
        ``Lcom/example/Foo;`` -> ``Lcom/example/Foo;``
    """
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"


def _normalize_java(name: str) -> str:
    """Ensure a class name is in Java dot-separated format."""
    name = name.strip()
    if name.startswith("L") and name.endswith(";"):
        return _dalvik_to_java(name)
    return name


# ---------------------------------------------------------------------------
# Dalvik type descriptor -> Java type name used in Frida overload()
# ---------------------------------------------------------------------------

_PRIMITIVE_MAP: dict[str, str] = {
    "Z": "boolean",
    "B": "byte",
    "C": "char",
    "S": "short",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
    "V": "void",
}


def _dalvik_type_to_frida(descriptor: str) -> str:
    """Convert a single Dalvik type descriptor token to a Frida Java type string.

    Examples:
        ``Z``                      -> ``boolean``
        ``I``                      -> ``int``
        ``Ljava/lang/String;``     -> ``java.lang.String``
        ``[I``                     -> ``[I``           (primitive array — use as-is)
        ``[Ljava/lang/String;``    -> ``[Ljava/lang/String;``
    """
    if descriptor in _PRIMITIVE_MAP:
        return _PRIMITIVE_MAP[descriptor]
    if descriptor.startswith("L") and descriptor.endswith(";"):
        return _dalvik_to_java(descriptor)
    # Arrays and anything else are passed verbatim (Frida accepts Dalvik notation)
    return descriptor


def _parse_method_descriptor(descriptor: str) -> tuple[list[str], str]:
    """Parse a Dalvik method descriptor string into (param_types, return_type).

    The descriptor format is ``(param1param2...)returnType``.

    Returns:
        A tuple of (list of Frida-style param type strings, return type string).
    """
    # Strip surrounding whitespace
    descriptor = descriptor.strip()

    # Match the (params)return shape
    m = re.match(r"\(([^)]*)\)(.*)", descriptor)
    if not m:
        return [], "void"

    params_raw = m.group(1)
    return_raw = m.group(2).strip()

    params: list[str] = []
    i = 0
    while i < len(params_raw):
        ch = params_raw[i]
        if ch in _PRIMITIVE_MAP:
            params.append(_dalvik_type_to_frida(ch))
            i += 1
        elif ch == "L":
            end = params_raw.index(";", i)
            params.append(_dalvik_type_to_frida(params_raw[i : end + 1]))
            i = end + 1
        elif ch == "[":
            # Array — collect the full array descriptor (may be nested)
            j = i
            while j < len(params_raw) and params_raw[j] == "[":
                j += 1
            if j < len(params_raw) and params_raw[j] == "L":
                end = params_raw.index(";", j)
                params.append(params_raw[i : end + 1])
                i = end + 1
            else:
                params.append(params_raw[i : j + 1])
                i = j + 1
        else:
            # Unknown — skip
            i += 1

    return_type = _dalvik_type_to_frida(return_raw) if return_raw else "void"
    return params, return_type


# ---------------------------------------------------------------------------
# JavaScript code-generation helpers
# ---------------------------------------------------------------------------

def _js_log_args(params: list[str], return_type: str, label: str) -> str:
    """Emit JS lines that log each argument and the return value."""
    lines: list[str] = [f'        console.log("[apksaw] {label} called");']
    for idx, ptype in enumerate(params):
        lines.append(f'        console.log("  arg{idx} ({ptype}): " + arg{idx});')
    lines.append(f"        var result = this.{label.split('.')[-1]}({', '.join(f'arg{i}' for i in range(len(params)))});")
    lines.append(f'        console.log("  return ({return_type}): " + result);')
    lines.append("        return result;")
    return "\n".join(lines)


def _js_log_return(params: list[str], return_type: str, label: str) -> str:
    """Emit JS lines that log only the return value."""
    lines: list[str] = [f'        console.log("[apksaw] {label} called");']
    method_call = f"this.{label.split('.')[-1]}({', '.join(f'arg{i}' for i in range(len(params)))})"
    lines.append(f"        var result = {method_call};")
    lines.append(f'        console.log("  return ({return_type}): " + result);')
    lines.append("        return result;")
    return "\n".join(lines)


def _js_modify_return(params: list[str], return_type: str, label: str) -> str:
    """Emit JS lines that log and allow modifying the return value."""
    lines: list[str] = [
        f'        console.log("[apksaw] {label} called");',
    ]
    method_call = f"this.{label.split('.')[-1]}({', '.join(f'arg{i}' for i in range(len(params)))})"
    lines.append(f"        var result = {method_call};")
    lines.append(f'        console.log("  original return ({return_type}): " + result);')
    lines.append("        // TODO: modify result here before returning")
    lines.append("        // result = <new_value>;")
    lines.append("        return result;")
    return "\n".join(lines)


def _js_trace(params: list[str], return_type: str, label: str) -> str:
    """Emit JS lines that log args, return value, and a stack trace."""
    lines: list[str] = [
        f'        console.log("[apksaw] {label} called");',
    ]
    for idx, ptype in enumerate(params):
        lines.append(f'        console.log("  arg{idx} ({ptype}): " + arg{idx});')
    # Stack trace via Java reflection
    lines.extend([
        "        var stackTrace = Java.use('java.lang.Thread')",
        "            .currentThread().getStackTrace();",
        "        for (var i = 2; i < Math.min(stackTrace.length, 12); i++) {",
        '            console.log("  at " + stackTrace[i].toString());',
        "        }",
    ])
    method_call = f"this.{label.split('.')[-1]}({', '.join(f'arg{i}' for i in range(len(params)))})"
    lines.append(f"        var result = {method_call};")
    lines.append(f'        console.log("  return ({return_type}): " + result);')
    lines.append("        return result;")
    return "\n".join(lines)


def _build_overload_hook(
    java_class: str,
    method_name: str,
    params: list[str],
    return_type: str,
    hook_type: str,
) -> str:
    """Build the JS implementation block for one overload."""
    label = f"{java_class}.{method_name}"
    arg_list = ", ".join(f"arg{i}" for i in range(len(params)))

    if hook_type == "log_args":
        body = _js_log_args(params, return_type, label)
    elif hook_type == "log_return":
        body = _js_log_return(params, return_type, label)
    elif hook_type == "modify_return":
        body = _js_modify_return(params, return_type, label)
    elif hook_type == "trace":
        body = _js_trace(params, return_type, label)
    else:
        body = _js_log_args(params, return_type, label)

    if params:
        overload_args = ", ".join(f'"{p}"' for p in params)
        target = f'cls.{method_name}.overload({overload_args})'
    else:
        target = f'cls.{method_name}.overload()'

    block = (
        f"    {target}.implementation = function({arg_list}) {{\n"
        f"{body}\n"
        f"    }};"
    )
    return block


def _save_script(session, subname: str, js_code: str) -> Path:
    """Write *js_code* to ``session.workspace/frida_scripts/<subname>.js``.

    Returns the path where the file was written.
    """
    scripts_dir: Path = session.workspace / "frida_scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    out_path = scripts_dir / f"{subname}.js"
    out_path.write_text(js_code, encoding="utf-8")
    return out_path


def _usage_line(package_name: str, file_path: Path) -> str:
    pkg = package_name or "com.example.app"
    return f"frida -U -f {pkg} -l {file_path}"


# ---------------------------------------------------------------------------
# Tool 1: generate_frida_hook
# ---------------------------------------------------------------------------

@mcp.tool()
def generate_frida_hook(
    session_id: str,
    class_name: str,
    method_name: str,
    hook_type: str = "log_args",
) -> dict:
    """Generate a Frida hook script for a specific method.

    Finds all overloads of ``method_name`` on ``class_name`` in the APK's DEX
    and emits one ``implementation`` block per overload, wrapped in a single
    ``Java.perform`` call.

    Args:
        session_id: Active analysis session ID returned by load_apk.
        class_name: Fully-qualified class name (Java or Dalvik format).
        method_name: The method to hook (e.g. ``encrypt``).
        hook_type: One of ``log_args`` (default), ``log_return``,
                   ``modify_return``, or ``trace``.

    Returns:
        ``{"status": "ok", "data": {"script": "...", "file_path": "...", "usage": "..."}}``.
    """
    VALID_HOOK_TYPES = {"log_args", "log_return", "modify_return", "trace"}
    if hook_type not in VALID_HOOK_TYPES:
        return {
            "status": "error",
            "data": {
                "message": f"Invalid hook_type '{hook_type}'. Must be one of: {sorted(VALID_HOOK_TYPES)}",
            },
        }

    try:
        session = get_session(session_id)
        analysis = session.analysis

        java_class = _normalize_java(class_name)
        dalvik_class = _java_to_dalvik(java_class)

        # Locate the class in the DEX analysis
        class_analysis = None
        for ca in analysis.find_classes(name=re.escape(dalvik_class)):
            class_analysis = ca
            break

        if class_analysis is None:
            # Fuzzy fallback: search by Java name with flexible separator
            escaped = re.escape(java_class).replace(r"\.", "[./]")
            for ca in analysis.find_classes(name=escaped):
                class_analysis = ca
                break

        # Collect all overloads for the requested method
        overloads: list[tuple[list[str], str]] = []  # (param_types, return_type)

        if class_analysis is not None:
            for ma in class_analysis.get_methods():
                if ma.name != method_name:
                    continue
                # ma.descriptor e.g. "(Ljava/lang/String;I)Z"
                try:
                    descriptor = ma.descriptor
                except Exception:
                    descriptor = ""
                params, ret = _parse_method_descriptor(descriptor)
                overloads.append((params, ret))

        if not overloads:
            # Class not found or method not found — generate a generic single-overload stub
            overloads = [([], "void")]
            warning_comment = (
                f"// WARNING: '{java_class}.{method_name}' was not found in the APK's DEX.\n"
                "// The hook below is a generic stub — adjust argument types as needed.\n\n"
            )
        else:
            warning_comment = ""

        # Build per-overload hook blocks
        hook_blocks = []
        for params, ret in overloads:
            block = _build_overload_hook(java_class, method_name, params, ret, hook_type)
            hook_blocks.append(block)

        hooks_js = "\n\n".join(hook_blocks)

        js_code = (
            f"{warning_comment}"
            f"Java.perform(function() {{\n"
            f'    var cls = Java.use("{java_class}");\n\n'
            f"{hooks_js}\n"
            f"}});\n"
        )

        # Sanitise file name: replace dots/dollar signs with underscores
        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", f"{java_class}_{method_name}_{hook_type}")
        file_path = _save_script(session, safe_name, js_code)

        return {
            "status": "ok",
            "data": {
                "script": js_code,
                "file_path": str(file_path),
                "usage": _usage_line(session.package_name, file_path),
                "overloads_found": len(overloads),
                "hook_type": hook_type,
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "data": {
                "message": str(exc),
                "suggestion": "Call load_apk first and use the returned session_id.",
            },
        }
    except Exception as exc:
        return {
            "status": "error",
            "data": {
                "message": str(exc),
                "traceback": traceback.format_exc(),
            },
        }


# ---------------------------------------------------------------------------
# Tool 2: generate_ssl_bypass
# ---------------------------------------------------------------------------

# --- Sub-generators for each pinning strategy ---

def _okhttp_pinner_bypass() -> str:
    return """\
// OkHttp3 CertificatePinner bypass
Java.perform(function() {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");

    CertificatePinner.check.overload(
        "java.lang.String", "java.util.List"
    ).implementation = function(hostname, peerCertificates) {
        console.log("[apksaw] CertificatePinner.check bypassed for: " + hostname);
        // Do not call original — suppresses the pin check
    };

    // Some builds expose a second overload: check(String, [Certificate)
    try {
        CertificatePinner.check.overload(
            "java.lang.String", "[Ljava.security.cert.Certificate;"
        ).implementation = function(hostname, certs) {
            console.log("[apksaw] CertificatePinner.check (cert[]) bypassed for: " + hostname);
        };
    } catch (e) {
        // Overload not present in this build
    }
});
"""


def _trust_manager_bypass() -> str:
    return """\
// Custom X509TrustManager bypass — accept all certificates
Java.perform(function() {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext       = Java.use("javax.net.ssl.SSLContext");

    // Build a permissive TrustManager
    var TrustManagerImpl = Java.registerClass({
        name: "apksaw.TrustManagerImpl",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {
                console.log("[apksaw] checkServerTrusted bypassed");
            },
            getAcceptedIssuers: function() { return []; },
        },
    });

    var trustManagers = [TrustManagerImpl.$new()];
    var sslCtx = SSLContext.getInstance("TLS");
    sslCtx.init(null, trustManagers, null);

    var SSLSocketFactory = Java.use("javax.net.ssl.HttpsURLConnection");
    SSLSocketFactory.setDefaultSSLSocketFactory(sslCtx.getSocketFactory());

    console.log("[apksaw] Permissive TrustManager installed");
});
"""


def _conscrypt_bypass() -> str:
    return """\
// Conscrypt / network_security_config pin-set bypass
// Hooks the internal Conscrypt certificate verifier used when
// network_security_config.xml defines <pin-set> entries.
Java.perform(function() {
    // Android 7+ path
    try {
        var NetworkSecurityConfig = Java.use(
            "android.security.net.config.NetworkSecurityConfig"
        );
        NetworkSecurityConfig.getPins.implementation = function() {
            console.log("[apksaw] NetworkSecurityConfig.getPins bypassed");
            return Java.use("java.util.Collections").emptySet();
        };
    } catch (e) {
        console.log("[apksaw] NetworkSecurityConfig hook not applicable: " + e);
    }

    // Also hook PinningTrustManager if present
    try {
        var PinningTrustManager = Java.use(
            "android.security.net.config.PinningTrustManager"
        );
        PinningTrustManager.checkServerTrusted.implementation = function(chain, authType) {
            console.log("[apksaw] PinningTrustManager.checkServerTrusted bypassed");
        };
    } catch (e) {
        // Not present
    }

    console.log("[apksaw] Conscrypt / network_security_config bypass active");
});
"""


def _universal_ssl_bypass() -> str:
    return """\
// Universal SSL pinning bypass
// Covers: OkHttp3 CertificatePinner, X509TrustManager, Conscrypt,
//         HttpsURLConnection, and Android 7+ network security config.
Java.perform(function() {

    // --- 1. OkHttp3 CertificatePinner ---
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload(
            "java.lang.String", "java.util.List"
        ).implementation = function(hostname, peerCerts) {
            console.log("[apksaw] OkHttp CertificatePinner.check bypassed: " + hostname);
        };
        CertificatePinner.check.overload(
            "java.lang.String", "[Ljava.security.cert.Certificate;"
        ).implementation = function(hostname, certs) {
            console.log("[apksaw] OkHttp CertificatePinner.check (cert[]) bypassed: " + hostname);
        };
    } catch (e) {
        console.log("[apksaw] OkHttp CertificatePinner not found: " + e);
    }

    // --- 2. Custom X509TrustManager ---
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext        = Java.use("javax.net.ssl.SSLContext");
        var TrustManagerImpl = Java.registerClass({
            name: "apksaw.UniversalTrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {
                    console.log("[apksaw] checkServerTrusted bypassed (universal)");
                },
                getAcceptedIssuers: function() { return []; },
            },
        });
        var sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(null, [TrustManagerImpl.$new()], null);
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(
            Java.use("javax.net.ssl.HttpsURLConnection").getDefaultHostnameVerifier()
        );
    } catch (e) {
        console.log("[apksaw] TrustManager bypass error: " + e);
    }

    // --- 3. Android 7+ NetworkSecurityConfig pin-set ---
    try {
        var NetworkSecurityConfig = Java.use(
            "android.security.net.config.NetworkSecurityConfig"
        );
        NetworkSecurityConfig.getPins.implementation = function() {
            console.log("[apksaw] NetworkSecurityConfig.getPins bypassed");
            return Java.use("java.util.Collections").emptySet();
        };
    } catch (e) {
        // Not applicable on this API level
    }

    // --- 4. HostnameVerifier ---
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        var AllowAllHostnameVerifier = Java.registerClass({
            name: "apksaw.AllowAllHV",
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    return true;
                },
            },
        });
        Java.use("javax.net.ssl.HttpsURLConnection")
            .setDefaultHostnameVerifier(AllowAllHostnameVerifier.$new());
    } catch (e) {
        console.log("[apksaw] HostnameVerifier bypass error: " + e);
    }

    console.log("[apksaw] Universal SSL bypass active");
});
"""


@mcp.tool()
def generate_ssl_bypass(session_id: str) -> dict:
    """Generate a targeted SSL pinning bypass script based on the specific
    pinning implementation detected in this APK.

    Detection priority:
    1. ``okhttp3.CertificatePinner`` usage -> OkHttp-specific bypass.
    2. Custom ``X509TrustManager`` implementation -> TrustManager bypass.
    3. ``network_security_config.xml`` ``<pin-set>`` element -> Conscrypt bypass.
    4. None found -> universal bypass covering all common methods.

    Args:
        session_id: Active analysis session ID returned by load_apk.

    Returns:
        ``{"status": "ok", "data": {"script": "...", "file_path": "...", "usage": "...", "detected_method": "..."}}``.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis
        apk = session.apk

        detected: Optional[str] = None
        js_code: str = ""

        # --- Check 1: OkHttp3 CertificatePinner ---
        okhttp_found = False
        for _ in analysis.find_methods(
            classname="Lokhttp3/CertificatePinner;",
            methodname="check",
        ):
            okhttp_found = True
            break
        # Also check xrefs TO CertificatePinner from app code
        if not okhttp_found:
            for ca in analysis.find_classes(name="Lokhttp3/CertificatePinner;"):
                okhttp_found = True
                break

        if okhttp_found:
            detected = "okhttp3.CertificatePinner"
            js_code = _okhttp_pinner_bypass()

        # --- Check 2: Custom X509TrustManager ---
        if detected is None:
            trust_manager_iface = "Ljavax/net/ssl/X509TrustManager;"
            for ca in analysis.get_classes():
                if ca.is_external():
                    continue
                vm_class = ca.get_vm_class()
                interfaces = vm_class.get_interfaces() or []
                if trust_manager_iface in interfaces:
                    detected = "X509TrustManager"
                    js_code = _trust_manager_bypass()
                    break

        # --- Check 3: network_security_config.xml pin-set ---
        if detected is None:
            try:
                nsc_xml = apk.get_file("res/xml/network_security_config.xml")
                if nsc_xml and b"pin-set" in nsc_xml:
                    detected = "network_security_config"
                    js_code = _conscrypt_bypass()
            except Exception:
                pass

        # --- Fallback: universal ---
        if detected is None:
            detected = "universal (none specifically detected)"
            js_code = _universal_ssl_bypass()

        file_path = _save_script(session, "ssl_bypass", js_code)

        return {
            "status": "ok",
            "data": {
                "script": js_code,
                "file_path": str(file_path),
                "usage": _usage_line(session.package_name, file_path),
                "detected_method": detected,
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "data": {
                "message": str(exc),
                "suggestion": "Call load_apk first and use the returned session_id.",
            },
        }
    except Exception as exc:
        return {
            "status": "error",
            "data": {
                "message": str(exc),
                "traceback": traceback.format_exc(),
            },
        }


# ---------------------------------------------------------------------------
# Tool 3: generate_token_dumper
# ---------------------------------------------------------------------------

def _build_interceptor_hook(interceptor_java_class: str) -> str:
    """Return a JS block that hooks an OkHttp Interceptor's intercept method."""
    return (
        f"    // Hook {interceptor_java_class}\n"
        f'    try {{\n'
        f'        var Interceptor_{re.sub(r"[^a-zA-Z0-9]", "_", interceptor_java_class)} = '
        f'Java.use("{interceptor_java_class}");\n'
        f'        Interceptor_{re.sub(r"[^a-zA-Z0-9]", "_", interceptor_java_class)}'
        f'.intercept.implementation = function(chain) {{\n'
        f'            var request = chain.request();\n'
        f'            var headers = request.headers();\n'
        f'            var authHeader = headers.get("Authorization");\n'
        f'            if (authHeader !== null) {{\n'
        f'                console.log("[apksaw] TOKEN CAPTURED from {interceptor_java_class}");\n'
        f'                console.log("  Authorization: " + authHeader);\n'
        f'            }}\n'
        f'            // Log all headers for completeness\n'
        f'            for (var i = 0; i < headers.size(); i++) {{\n'
        f'                var headerName = headers.name(i);\n'
        f'                if (headerName.toLowerCase().indexOf("token") !== -1 ||\n'
        f'                    headerName.toLowerCase().indexOf("auth") !== -1 ||\n'
        f'                    headerName.toLowerCase().indexOf("session") !== -1) {{\n'
        f'                    console.log("  " + headerName + ": " + headers.value(i));\n'
        f'                }}\n'
        f'            }}\n'
        f'            return chain.proceed(request);\n'
        f'        }};\n'
        f'    }} catch (e) {{\n'
        f'        console.log("[apksaw] Could not hook {interceptor_java_class}: " + e);\n'
        f'    }}\n'
    )


def _build_shared_prefs_hooks(token_keys: list[str]) -> str:
    """Return JS that hooks SharedPreferences getString for known token keys."""
    key_list = ", ".join(f'"{k}"' for k in token_keys)
    return f"""\
    // SharedPreferences hooks for token keys: {key_list}
    try {{
        var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
        var TOKEN_KEYS = [{key_list}];

        SharedPreferences.getString.overload(
            "java.lang.String", "java.lang.String"
        ).implementation = function(key, defValue) {{
            var value = this.getString(key, defValue);
            var keyLower = key.toLowerCase();
            var isToken = false;
            for (var i = 0; i < TOKEN_KEYS.length; i++) {{
                if (keyLower.indexOf(TOKEN_KEYS[i].toLowerCase()) !== -1) {{
                    isToken = true;
                    break;
                }}
            }}
            if (isToken && value !== null) {{
                console.log("[apksaw] SharedPreferences token read:");
                console.log("  key:   " + key);
                console.log("  value: " + value);
            }}
            return value;
        }};
    }} catch (e) {{
        console.log("[apksaw] SharedPreferences hook error: " + e);
    }}
"""


@mcp.tool()
def generate_token_dumper(session_id: str) -> dict:
    """Generate a Frida script that hooks the auth interceptor to capture Bearer tokens.

    Analyzes the APK to find:
    1. Classes implementing ``okhttp3.Interceptor``.
    2. SharedPreferences reads for keys containing "token", "auth", "bearer", "session".

    Generates hooks for every interceptor class found, plus a generic
    SharedPreferences monitor for auth-related keys.

    Args:
        session_id: Active analysis session ID returned by load_apk.

    Returns:
        ``{"status": "ok", "data": {"script": "...", "file_path": "...", "usage": "...", "interceptors_found": [...]}}``.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        # --- Find OkHttp Interceptor implementations ---
        interceptor_iface = "Lokhttp3/Interceptor;"
        interceptor_classes: list[str] = []

        for ca in analysis.get_classes():
            if ca.is_external():
                continue
            vm_class = ca.get_vm_class()
            interfaces = vm_class.get_interfaces() or []
            if interceptor_iface in interfaces:
                interceptor_classes.append(_dalvik_to_java(ca.name))

        # --- Find SharedPreferences getString calls and token-like key strings ---
        token_key_patterns = {"token", "auth", "bearer", "session", "jwt", "access_key"}

        # Collect string constants that look like SharedPreferences keys
        found_sp_keys: set[str] = set()
        for cls_analysis in analysis.get_classes():
            if cls_analysis.is_external():
                continue
            for ma in cls_analysis.get_methods():
                if ma.is_external():
                    continue
                try:
                    for _, value in ma.get_method().get_strings():
                        low = value.lower()
                        for pat in token_key_patterns:
                            if pat in low:
                                found_sp_keys.add(value)
                                break
                except Exception:
                    pass

        sp_keys = sorted(found_sp_keys) or ["token", "auth_token", "bearer", "session_id"]

        # --- Build the script ---
        interceptor_blocks = "\n".join(
            _build_interceptor_hook(cls) for cls in interceptor_classes
        )
        if not interceptor_blocks:
            interceptor_blocks = (
                "    // No OkHttp Interceptor implementations found in DEX.\n"
                '    // Generic Authorization header hook via OkHttp Request:\n'
                "    try {\n"
                '        var Request = Java.use("okhttp3.Request");\n'
                '        Request.header.implementation = function(name) {\n'
                '            var val = this.header(name);\n'
                '            if (name.toLowerCase() === "authorization" && val !== null) {\n'
                '                console.log("[apksaw] Authorization header: " + val);\n'
                "            }\n"
                "            return val;\n"
                "        };\n"
                "    } catch (e) {\n"
                '        console.log("[apksaw] Request.header hook error: " + e);\n'
                "    }\n"
            )

        sp_block = _build_shared_prefs_hooks(sp_keys)

        js_code = (
            "// Token Dumper — generated by apksaw\n"
            "// Hooks OkHttp interceptors + SharedPreferences for auth tokens.\n\n"
            "Java.perform(function() {\n\n"
            f"{interceptor_blocks}\n"
            f"{sp_block}\n"
            '    console.log("[apksaw] Token dumper active");\n'
            "});\n"
        )

        file_path = _save_script(session, "token_dumper", js_code)

        return {
            "status": "ok",
            "data": {
                "script": js_code,
                "file_path": str(file_path),
                "usage": _usage_line(session.package_name, file_path),
                "interceptors_found": interceptor_classes,
                "sp_keys_monitored": sp_keys,
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "data": {
                "message": str(exc),
                "suggestion": "Call load_apk first and use the returned session_id.",
            },
        }
    except Exception as exc:
        return {
            "status": "error",
            "data": {
                "message": str(exc),
                "traceback": traceback.format_exc(),
            },
        }


# ---------------------------------------------------------------------------
# Tool 4: generate_crypto_hooks
# ---------------------------------------------------------------------------

@mcp.tool()
def generate_crypto_hooks(session_id: str) -> dict:
    """Generate Frida hooks for all crypto operations to log keys, IVs, plaintext, and ciphertext.

    Hooks the following Java crypto APIs:
    - ``javax.crypto.Cipher.getInstance`` — log algorithm string.
    - ``javax.crypto.Cipher.init`` — log encrypt/decrypt mode, key bytes, IV bytes.
    - ``javax.crypto.Cipher.doFinal`` — log input and output bytes (hex).
    - ``javax.crypto.spec.SecretKeySpec.<init>`` — log raw key bytes and algorithm.
    - ``java.security.MessageDigest.digest`` — log input bytes and resulting hash (hex).

    Args:
        session_id: Active analysis session ID returned by load_apk.

    Returns:
        ``{"status": "ok", "data": {"script": "...", "file_path": "...", "usage": "..."}}``.
    """
    try:
        session = get_session(session_id)

        js_code = """\
// Crypto Hooks — generated by apksaw
// Logs all JCE crypto operations: algorithm, key, IV, plaintext, ciphertext.

Java.perform(function() {

    // Utility: convert a Java byte[] to a hex string
    function toHex(bytes) {
        if (bytes === null) return "null";
        var hex = "";
        for (var i = 0; i < bytes.length; i++) {
            var b = (bytes[i] & 0xff).toString(16);
            hex += (b.length === 1 ? "0" : "") + b;
        }
        return hex;
    }

    // Utility: truncate long hex strings for readability
    function truncHex(bytes, maxBytes) {
        if (bytes === null) return "null";
        var h = toHex(bytes.slice(0, Math.min(bytes.length, maxBytes)));
        return h + (bytes.length > maxBytes ? "... (" + bytes.length + " bytes total)" : "");
    }

    // -----------------------------------------------------------------------
    // 1. Cipher.getInstance — log algorithm
    // -----------------------------------------------------------------------
    try {
        var Cipher = Java.use("javax.crypto.Cipher");

        Cipher.getInstance.overload("java.lang.String").implementation = function(transformation) {
            console.log("[apksaw] Cipher.getInstance: " + transformation);
            return this.getInstance(transformation);
        };

        Cipher.getInstance.overload(
            "java.lang.String", "java.lang.String"
        ).implementation = function(transformation, provider) {
            console.log("[apksaw] Cipher.getInstance: " + transformation + " (provider: " + provider + ")");
            return this.getInstance(transformation, provider);
        };

        Cipher.getInstance.overload(
            "java.lang.String", "java.security.Provider"
        ).implementation = function(transformation, provider) {
            console.log("[apksaw] Cipher.getInstance: " + transformation + " (Provider obj)");
            return this.getInstance(transformation, provider);
        };

    } catch (e) {
        console.log("[apksaw] Cipher.getInstance hook error: " + e);
    }

    // -----------------------------------------------------------------------
    // 2. Cipher.init — log mode, key bytes, IV bytes
    // -----------------------------------------------------------------------
    try {
        var _Cipher = Java.use("javax.crypto.Cipher");
        var MODES = {1: "ENCRYPT", 2: "DECRYPT", 3: "WRAP", 4: "UNWRAP"};

        // init(int opmode, Key key)
        _Cipher.init.overload(
            "int", "java.security.Key"
        ).implementation = function(opmode, key) {
            var modeStr = MODES[opmode] || opmode;
            var keyBytes = null;
            try { keyBytes = key.getEncoded(); } catch (e) {}
            console.log("[apksaw] Cipher.init mode=" + modeStr +
                        " algorithm=" + key.getAlgorithm() +
                        " key=" + truncHex(keyBytes, 32));
            return this.init(opmode, key);
        };

        // init(int opmode, Key key, AlgorithmParameterSpec params)
        _Cipher.init.overload(
            "int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec"
        ).implementation = function(opmode, key, params) {
            var modeStr = MODES[opmode] || opmode;
            var keyBytes = null;
            try { keyBytes = key.getEncoded(); } catch (e) {}
            var ivHex = "n/a";
            try {
                var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
                var ivSpec = Java.cast(params, IvParameterSpec);
                ivHex = toHex(ivSpec.getIV());
            } catch (e) {}
            console.log("[apksaw] Cipher.init mode=" + modeStr +
                        " algorithm=" + key.getAlgorithm() +
                        " key=" + truncHex(keyBytes, 32) +
                        " iv=" + ivHex);
            return this.init(opmode, key, params);
        };

        // init(int opmode, Key key, AlgorithmParameters params)
        _Cipher.init.overload(
            "int", "java.security.Key", "java.security.AlgorithmParameters"
        ).implementation = function(opmode, key, params) {
            var modeStr = MODES[opmode] || opmode;
            var keyBytes = null;
            try { keyBytes = key.getEncoded(); } catch (e) {}
            console.log("[apksaw] Cipher.init mode=" + modeStr +
                        " algorithm=" + key.getAlgorithm() +
                        " key=" + truncHex(keyBytes, 32) +
                        " params=" + params.toString());
            return this.init(opmode, key, params);
        };

    } catch (e) {
        console.log("[apksaw] Cipher.init hook error: " + e);
    }

    // -----------------------------------------------------------------------
    // 3. Cipher.doFinal — log input and output (hex, truncated to 64 bytes)
    // -----------------------------------------------------------------------
    try {
        var _CipherDF = Java.use("javax.crypto.Cipher");

        // doFinal() — no args
        _CipherDF.doFinal.overload().implementation = function() {
            var result = this.doFinal();
            console.log("[apksaw] Cipher.doFinal() -> " + truncHex(result, 64));
            return result;
        };

        // doFinal(byte[])
        _CipherDF.doFinal.overload("[B").implementation = function(input) {
            var result = this.doFinal(input);
            console.log("[apksaw] Cipher.doFinal input=" + truncHex(input, 64) +
                        " output=" + truncHex(result, 64));
            return result;
        };

        // doFinal(byte[], int, int)
        _CipherDF.doFinal.overload("[B", "int", "int").implementation = function(input, offset, len) {
            var result = this.doFinal(input, offset, len);
            console.log("[apksaw] Cipher.doFinal(slice) offset=" + offset +
                        " len=" + len +
                        " output=" + truncHex(result, 64));
            return result;
        };

        // doFinal(byte[], int)
        _CipherDF.doFinal.overload("[B", "int").implementation = function(output, outputOffset) {
            var result = this.doFinal(output, outputOffset);
            console.log("[apksaw] Cipher.doFinal(output, offset) outputOffset=" + outputOffset +
                        " result=" + result);
            return result;
        };

    } catch (e) {
        console.log("[apksaw] Cipher.doFinal hook error: " + e);
    }

    // -----------------------------------------------------------------------
    // 4. SecretKeySpec.<init> — log key bytes and algorithm
    // -----------------------------------------------------------------------
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(keyBytes, algorithm) {
            console.log("[apksaw] SecretKeySpec algorithm=" + algorithm +
                        " key=" + toHex(keyBytes) +
                        " (" + keyBytes.length * 8 + "-bit)");
            return this.$init(keyBytes, algorithm);
        };

        SecretKeySpec.$init.overload(
            "[B", "int", "int", "java.lang.String"
        ).implementation = function(keyBytes, offset, len, algorithm) {
            var sliced = keyBytes.slice(offset, offset + len);
            console.log("[apksaw] SecretKeySpec algorithm=" + algorithm +
                        " key=" + toHex(sliced) +
                        " (" + len * 8 + "-bit, offset=" + offset + ")");
            return this.$init(keyBytes, offset, len, algorithm);
        };

    } catch (e) {
        console.log("[apksaw] SecretKeySpec hook error: " + e);
    }

    // -----------------------------------------------------------------------
    // 5. MessageDigest.digest — log input and hash output
    // -----------------------------------------------------------------------
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");

        // digest() — hash buffered input
        MessageDigest.digest.overload().implementation = function() {
            var result = this.digest();
            console.log("[apksaw] MessageDigest.digest algorithm=" + this.getAlgorithm() +
                        " hash=" + toHex(result));
            return result;
        };

        // digest(byte[]) — hash the supplied bytes
        MessageDigest.digest.overload("[B").implementation = function(input) {
            var result = this.digest(input);
            console.log("[apksaw] MessageDigest.digest algorithm=" + this.getAlgorithm() +
                        " input=" + truncHex(input, 64) +
                        " hash=" + toHex(result));
            return result;
        };

        // digest(byte[], int, int)
        MessageDigest.digest.overload("[B", "int", "int").implementation = function(buf, offset, len) {
            var result = this.digest(buf, offset, len);
            console.log("[apksaw] MessageDigest.digest(buf,offset,len) algorithm=" + this.getAlgorithm() +
                        " hash=" + toHex(result));
            return result;
        };

    } catch (e) {
        console.log("[apksaw] MessageDigest hook error: " + e);
    }

    console.log("[apksaw] Crypto hooks active");
});
"""

        file_path = _save_script(session, "crypto_hooks", js_code)

        return {
            "status": "ok",
            "data": {
                "script": js_code,
                "file_path": str(file_path),
                "usage": _usage_line(session.package_name, file_path),
                "hooks": [
                    "javax.crypto.Cipher.getInstance",
                    "javax.crypto.Cipher.init",
                    "javax.crypto.Cipher.doFinal",
                    "javax.crypto.spec.SecretKeySpec.<init>",
                    "java.security.MessageDigest.digest",
                ],
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "data": {
                "message": str(exc),
                "suggestion": "Call load_apk first and use the returned session_id.",
            },
        }
    except Exception as exc:
        return {
            "status": "error",
            "data": {
                "message": str(exc),
                "traceback": traceback.format_exc(),
            },
        }
