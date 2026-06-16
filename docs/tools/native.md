# Native Library Tools

Tools for analyzing native `.so` libraries embedded in APKs, using LIEF for ELF parsing and Capstone for disassembly.

## `list_native_libs`

List all `.so` files in the APK with their ABI directories and sizes.

```
list_native_libs(session_id="abc123")
→ [
    {"name": "libcrypto.so", "abi": "arm64-v8a", "size": 2097152},
    {"name": "libnative.so", "abi": "arm64-v8a", "size": 524288}
  ]
```

## `analyze_native_lib`

Parse an ELF binary with LIEF. Returns exported/imported symbols, sections, dynamic dependencies, and linked libraries.

```
analyze_native_lib(session_id="abc123", lib_name="libnative.so")
→ {
    "exports": ["Java_com_example_NativeLib_init", ...],
    "imports": ["__android_log_print", "SSL_CTX_new", ...],
    "sections": [".text", ".rodata", ".data", ...],
    "needed": ["libssl.so", "libc.so"]
  }
```

## `search_native_strings`

Extract string literals from the `.rodata` section of a native library.

```
search_native_strings(session_id="abc123", lib_name="libnative.so", pattern="key")
→ ["encryption_key_slot", "api_key_prefix", ...]
```

## `check_native_security`

Audit native libraries for security issues: missing stack canaries, NX bit, RELRO, PIE, and suspicious symbol imports.

## `disassemble_function`

Disassemble a named exported function using Capstone. Detects ARM64/ARM/x86 automatically.

```
disassemble_function(
    session_id="abc123",
    lib_name="libnative.so",
    function_name="Java_com_example_NativeLib_verify"
)
→ "0x1234: ldr x0, [sp, #8]\n0x1238: bl #0x5678\n..."
```

## `find_rop_gadgets`

Walk the library's `.text` section with Capstone and emit one ROP candidate per ret / `bx lr` terminator within a 12-instruction sliding window. Each gadget is classified by mnemonic shape (`pop_ret`, `mov_ret`, `ldr_ret`, `ldp_pop_ret`, `bx_lr`, `ret_only`, `generic_ret`, …) so the LLM agent can pick.

This is the entry point for offensive native exploitation. The agent consumes the candidates, selects chains, and writes the exploit; ``generate_jni_hook`` and ``execute_native_hook`` chain into the resulting hook script.

```
find_rop_gadgets(
    session_id="abc123",
    lib_name="libnative.so",
    arch="arm64-v8a",
    max_gadgets=50,
)
→ {
    "count": 37,
    "truncated": False,
    "gadgets": [
      {"kind": "pop_ret", "address": "0x12f80",
       "instructions": [
         {"address": "0x12f70", "mnemonic": "ldr", "op_str": "x19, [sp, #0x10]"},
         {"address": "0x12f74", "mnemonic": "ldr", "op_str": "x0, [sp, #0x38]"},
         {"address": "0x12f78", "mnemonic": "pop",  "op_str": "{x19, x20}"},
         {"address": "0x12f7c", "mnemonic": "ret",  "op_str": ""}]}, ...]
    ]
  }
```

> The classifier labels by mnemonic shape — not exploitability — so the agent reasons about which gadgets actually matter for a given target. ``max_gadgets`` caps the result so a multi-MB `.so` doesn't burn CI minutes on disassembly.

## `generate_jni_hook`

Produce a Frida JS script that hooks every `Java_<class>_<method>` export from a library. Banking/fintech apps routinely move auth, crypto, and license validation into native `.so` code, and JNI entry points are the only observable surface from inside a live target process.

Each hook gets a `Java.use(cls).method.implementation` swap that logs args, forwards to the native implementation, and `send()`s a structured `__apksaw_kind: jni_call` / `jni_return` payload back to the Frida client. The script is written to `<session.workspace>/native_hooks/<lib>_jni.js`.

```
generate_jni_hook(
    session_id="abc123",
    lib_name="libnative.so",
    arch="arm64-v8a",
    class_filter=None,        # optional substring on the parsed class name
)
→ {
    "hooks": [
      {"symbol": "Java_com_example_Native_cryptoSign",
       "class_name": "com.example.Native",
       "method_name": "cryptoSign",
       "address": "0x12345"},
      ...],
    "script": "Java.perform(function () { try { ... } ... });",
    "file_path": "/workspace/native_hooks/libnative.so_jni.js"
  }
```

If the library exports no `Java_*` symbols, returns `status:ok` with `hooks=[]` and a message indicating the library may use private `JNI_OnLoad` registration that `analyze_native_lib`'s exported-symbols view cannot see.

## `execute_native_hook`

Runtime execution of a Frida JS hook script (typically the one produced by `generate_jni_hook`) against the target app on a connected device. Closes the verify loop the static `generate_jni_hook` leaves open: the agent now has *both* the candidate exploit lever *and* the means to drive it.

Same confirm-gated posture as `exploit_gen` / `runtime.repackage_with_gadget`:

- `confirm=False` returns a dry-run plan + tool_check; **no subprocess is invoked, no device is touched**.
- `confirm=True` requires **both** an ADB device **and** a working frida Python install. Either missing → `status:error` with a precise message.

```
# Step 1: dry-run, shows the plan
execute_native_hook(
    session_id="abc123",
    js_path="/workspace/native_hooks/libnative.so_jni.js",
    package="com.example.app",
    confirm=False,
)
→ {"status": "ok", "data": {"plan": True, "command": "frida -U -l ... -f com.example.app --no-pause", ...}}

# Step 2: after you confirm — actually drive the hook (requires ADB + frida-tools)
execute_native_hook(
    session_id="abc123",
    js_path="/workspace/native_hooks/libnative.so_jni.js",
    package="com.example.app",
    capture_seconds=10,
    confirm=True,
)
→ {"status": "ok", "data": {"package": "com.example.app", "pid": 12345,
                          "captured_count": 27, "findings": [...],
                          "summary": {"jni_call": 15, "jni_return": 12}}}
```
