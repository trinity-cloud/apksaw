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
