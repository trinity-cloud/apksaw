"""Native library (.so) analysis + exploitation tools for Android APK threat analysis.

Phase 5 additions (after the original 5 static analysis tools):

- ``find_rop_gadgets``    — Capstone-driven ROP gadget discovery over .text
- ``generate_jni_hook``   — Frida JS hook script generator for ``Java_*`` exports
- ``execute_native_hook`` — runtime Frida execution with ``confirm``-gated dry-run
"""

import re
import subprocess  # noqa: F401 — referenced by phase-5 tests for dry-run contract
import time
import zipfile
from pathlib import Path
from typing import Any, NamedTuple, Optional

from apksaw.server import mcp
from apksaw.session import Session, get_session
from apksaw.utils.adb import check_device_connected


# ---------------------------------------------------------------------------
# Frida Python client availability probe (used by execute_native_hook)
# ---------------------------------------------------------------------------


class _FridaImportStatus(NamedTuple):
    """Result of the lazy ``import frida`` probe used by ``execute_native_hook``.

    Tests patch the module-level ``_IMPORT_FRIDA`` constant with a MagicMock
    that exposes ``available`` and ``module`` attributes — so this NamedTuple
    shape must remain (available: bool, module: Any).
    """
    available: bool
    module: Any  # noqa: ANN401 — the frida module or None


def _try_import_frida() -> _FridaImportStatus:
    """Resolve the frida Python client without crashing if it isn't installed."""
    try:
        import frida  # type: ignore[import-not-found]  # noqa: PLC0415
        return _FridaImportStatus(available=True, module=frida)
    except Exception:
        return _FridaImportStatus(available=False, module=None)


_IMPORT_FRIDA: _FridaImportStatus = _try_import_frida()

# ---------------------------------------------------------------------------
# Suspicious function name patterns
# ---------------------------------------------------------------------------

_SUSPICIOUS_KEYWORDS = re.compile(
    r"(?:exec|system|dlopen|dlsym|ptrace|encrypt|decrypt|hook|"
    r"inject|mprotect|mmap|chmod|chown|fork|popen|strcat|strcpy|gets|"
    r"sprintf|vsprintf|memcpy|memmove)",
    re.IGNORECASE,
)

# Strings that are interesting in a security context
_RE_URL = re.compile(r"https?://\S+|ftp://\S+", re.IGNORECASE)
_RE_FILE_PATH = re.compile(r"(?:/[\w.\-]+){2,}|[\w\-]+\.(?:sh|so|dex|apk|db|sqlite|pem|key|crt)")
_RE_SHELL_CMD = re.compile(
    r"\b(?:chmod|chown|su\b|busybox|/system/bin|/system/xbin|/sbin|"
    r"/proc/|/data/data|mount\s|iptables|nc\s|netcat|curl\s|wget\s|"
    r"am\s+start|pm\s+install)\b",
    re.IGNORECASE,
)
_RE_CRYPTO = re.compile(
    r"\b(?:AES|DES|RSA|RC4|MD5|SHA|HMAC|EVP|encrypt|decrypt|cipher|"
    r"openssl|mbedtls|crypto)\b",
    re.IGNORECASE,
)

# Capstone arch/mode mapping by ELF machine type string
_ARCH_CAPSTONE_MAP: dict[str, tuple] = {}  # populated lazily


def _capstone_for_arch(arch_str: str) -> Optional[object]:
    """Return a configured Capstone disassembler for a given arch string.

    Args:
        arch_str: Architecture string, e.g. "arm64-v8a", "armeabi-v7a", "x86", "x86_64".

    Returns:
        A Cs instance or None if the arch is unsupported.
    """
    try:
        from capstone import (
            Cs,
            CS_ARCH_ARM64,
            CS_ARCH_ARM,
            CS_ARCH_X86,
            CS_MODE_ARM,
            CS_MODE_THUMB,
            CS_MODE_32,
            CS_MODE_64,
        )
    except ImportError:
        return None

    arch_lower = arch_str.lower()
    if "arm64" in arch_lower or "aarch64" in arch_lower:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif "armeabi" in arch_lower or "arm" in arch_lower:
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    elif "x86_64" in arch_lower or "x86-64" in arch_lower:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif "x86" in arch_lower:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        return None

    md.detail = True
    return md


# ---------------------------------------------------------------------------
# Helper: extract a .so from the APK ZIP to the workspace
# ---------------------------------------------------------------------------


def _extract_so(session: Session, lib_path: str) -> Path:
    """Extract a .so file from the APK ZIP to the workspace directory.

    The file is only extracted if it does not already exist at the destination.

    Args:
        session: Active analysis session.
        lib_path: Path inside the APK ZIP (e.g. "lib/arm64-v8a/libfoo.so").

    Returns:
        Path to the extracted file on disk.

    Raises:
        KeyError: If lib_path is not found inside the APK ZIP.
        zipfile.BadZipFile: If the APK cannot be opened as a ZIP.
    """
    dest = session.workspace / lib_path.replace("/", "_")
    if dest.exists():
        return dest

    with zipfile.ZipFile(str(session.apk_path), "r") as zf:
        data = zf.read(lib_path)

    dest.write_bytes(data)
    return dest


# ---------------------------------------------------------------------------
# Tool 1: list_native_libs
# ---------------------------------------------------------------------------


@mcp.tool()
def list_native_libs(session_id: str) -> dict:
    """List all native libraries (.so files) contained in the APK.

    Enumerates entries under ``lib/`` in the APK archive and groups them by
    ABI/architecture (arm64-v8a, armeabi-v7a, x86, x86_64, etc.).

    Args:
        session_id: Active analysis session ID returned by load_apk.

    Returns:
        dict: ``{"status": "ok", "data": {"libraries": [...], "architectures": [...]}}``

        Each library entry contains ``name``, ``arch``, ``size`` (bytes),
        and ``path`` (full path inside the APK).
    """
    try:
        session = get_session(session_id)

        libraries: list[dict] = []
        architectures: set[str] = set()

        with zipfile.ZipFile(str(session.apk_path), "r") as zf:
            for info in zf.infolist():
                path = info.filename
                if not path.startswith("lib/") or not path.endswith(".so"):
                    continue
                # Expected structure: lib/<arch>/<name>.so
                parts = path.split("/")
                if len(parts) < 3:
                    continue

                arch = parts[1]
                name = parts[-1]
                architectures.add(arch)

                libraries.append(
                    {
                        "name": name,
                        "arch": arch,
                        "size": info.file_size,
                        "path": path,
                    }
                )

        libraries.sort(key=lambda x: (x["arch"], x["name"]))

        return {
            "status": "ok",
            "data": {
                "libraries": libraries,
                "architectures": sorted(architectures),
                "count": len(libraries),
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }
    except zipfile.BadZipFile as exc:
        return {
            "status": "error",
            "message": f"APK is not a valid ZIP/APK archive: {exc}",
            "suggestion": "Verify the APK file is not corrupted.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Failed to list native libraries: {exc}",
            "suggestion": "Ensure the APK was loaded successfully.",
        }


# ---------------------------------------------------------------------------
# Tool 2: analyze_native_lib
# ---------------------------------------------------------------------------


@mcp.tool()
def analyze_native_lib(
    session_id: str,
    lib_name: str,
    arch: str = "arm64-v8a",
) -> dict:
    """Analyse a specific native library (.so) from the APK.

    Extracts the library from the APK if needed, then parses it with LIEF to
    produce a structured report including:

    - ELF architecture and header info
    - Exported functions (flagged as JNI if they start with ``Java_``)
    - Imported functions with their source library
    - Required shared libraries (DT_NEEDED)
    - ELF sections list
    - Suspicious function names

    Args:
        session_id: Active analysis session ID returned by load_apk.
        lib_name: Library file name, e.g. ``libfoo.so``.
        arch: ABI directory name (default ``arm64-v8a``).

    Returns:
        dict: Structured analysis result with ``status`` and ``data`` keys.
    """
    try:
        import lief  # noqa: PLC0415
    except ImportError:
        return {
            "status": "error",
            "message": "lief is not installed.",
            "suggestion": "pip install lief",
        }

    try:
        session = get_session(session_id)
        lib_path_in_apk = f"lib/{arch}/{lib_name}"

        try:
            so_path = _extract_so(session, lib_path_in_apk)
        except KeyError:
            return {
                "status": "error",
                "message": f"Library '{lib_path_in_apk}' not found in APK.",
                "suggestion": "Use list_native_libs to see available libraries and architectures.",
            }

        binary = lief.ELF.parse(str(so_path))
        if binary is None:
            return {
                "status": "error",
                "message": f"LIEF could not parse '{lib_name}' as a valid ELF binary.",
                "suggestion": "The file may be corrupted or use an unsupported ELF format.",
            }

        # --- Architecture info ---
        try:
            machine = str(binary.header.machine_type).split(".")[-1]
        except Exception:
            machine = "unknown"

        arch_info = {
            "machine": machine,
            "abi": arch,
            "is_pie": binary.is_pie,
        }

        # --- Exported functions ---
        exported_functions: list[dict] = []
        suspicious_exported: list[str] = []

        for fn in binary.exported_functions:
            name = fn.name or ""
            is_jni = name.startswith("Java_")
            is_suspicious = bool(_SUSPICIOUS_KEYWORDS.search(name))
            if is_suspicious:
                suspicious_exported.append(name)

            exported_functions.append(
                {
                    "name": name,
                    "address": hex(fn.address) if fn.address else "0x0",
                    "size": fn.size,
                    "is_jni": is_jni,
                    "is_suspicious": is_suspicious,
                }
            )

        # --- Imported functions ---
        imported_functions: list[dict] = []
        suspicious_imported: list[str] = []

        # Build a map from symbol name to the library it comes from (DT_NEEDED via versioning)
        # LIEF doesn't directly expose which lib each import comes from in all cases,
        # so we rely on the dynamic_symbols with UNDEF binding.
        try:
            for sym in binary.dynamic_symbols:
                if sym.imported:
                    name = sym.name or ""
                    is_suspicious = bool(_SUSPICIOUS_KEYWORDS.search(name))
                    if is_suspicious:
                        suspicious_imported.append(name)

                    # Try to get the version/library info
                    try:
                        library = sym.symbol_version.symbol_version_auxiliary.name if (
                            sym.symbol_version and sym.symbol_version.symbol_version_auxiliary
                        ) else ""
                    except Exception:
                        library = ""

                    imported_functions.append(
                        {
                            "name": name,
                            "library": library,
                            "is_suspicious": is_suspicious,
                        }
                    )
        except Exception:
            # Fallback: use imported_functions property
            for fn in binary.imported_functions:
                name = fn.name or ""
                is_suspicious = bool(_SUSPICIOUS_KEYWORDS.search(name))
                if is_suspicious:
                    suspicious_imported.append(name)
                imported_functions.append(
                    {"name": name, "library": "", "is_suspicious": is_suspicious}
                )

        # Deduplicate imports (dynamic_symbols may contain duplicates)
        seen_imports: set[str] = set()
        deduped_imports: list[dict] = []
        for entry in imported_functions:
            if entry["name"] not in seen_imports:
                seen_imports.add(entry["name"])
                deduped_imports.append(entry)
        imported_functions = deduped_imports

        # --- DT_NEEDED (required shared libraries) ---
        needed_libs: list[str] = []
        try:
            for dyn in binary.dynamic_entries:
                tag_str = str(dyn.tag).split(".")[-1]
                if tag_str == "NEEDED":
                    needed_libs.append(dyn.name)
        except Exception:
            pass

        # --- Sections ---
        sections: list[dict] = []
        try:
            for sec in binary.sections:
                sections.append(
                    {
                        "name": sec.name,
                        "size": sec.size,
                        "offset": hex(sec.offset),
                        "virtual_address": hex(sec.virtual_address),
                    }
                )
        except Exception:
            pass

        all_suspicious = sorted(set(suspicious_exported + suspicious_imported))

        return {
            "status": "ok",
            "data": {
                "lib_name": lib_name,
                "arch": arch,
                "path_in_apk": lib_path_in_apk,
                "file_size": so_path.stat().st_size,
                "architecture": arch_info,
                "exported_functions": exported_functions,
                "imported_functions": imported_functions,
                "needed_libraries": needed_libs,
                "sections": sections,
                "jni_functions": [f["name"] for f in exported_functions if f["is_jni"]],
                "suspicious_functions": all_suspicious,
                "counts": {
                    "exported": len(exported_functions),
                    "imported": len(imported_functions),
                    "jni": sum(1 for f in exported_functions if f["is_jni"]),
                    "suspicious": len(all_suspicious),
                    "needed_libs": len(needed_libs),
                    "sections": len(sections),
                },
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Failed to analyse native library: {exc}",
            "suggestion": "Ensure LIEF is installed and the library is a valid ELF binary.",
        }


# ---------------------------------------------------------------------------
# Tool 3: disassemble_function
# ---------------------------------------------------------------------------


@mcp.tool()
def disassemble_function(
    session_id: str,
    lib_name: str,
    function_name: str,
    arch: str = "arm64-v8a",
    max_instructions: int = 100,
) -> dict:
    """Disassemble a specific function from a native library.

    Locates the function by name in the ELF symbol table, reads its raw bytes,
    and disassembles them using Capstone for the given architecture.

    Args:
        session_id: Active analysis session ID returned by load_apk.
        lib_name: Library file name, e.g. ``libfoo.so``.
        function_name: Exported or dynamic symbol name to disassemble.
        arch: ABI directory name (default ``arm64-v8a``).
        max_instructions: Maximum number of instructions to return (default 100).

    Returns:
        dict: ``{"status": "ok", "data": {"function_name": ..., "arch": ...,
               "address": ..., "size": ..., "instructions": [...]}}``

        Each instruction entry has ``address``, ``mnemonic``, ``op_str``,
        and ``bytes``.
    """
    try:
        import lief  # noqa: PLC0415
    except ImportError:
        return {
            "status": "error",
            "message": "lief is not installed.",
            "suggestion": "pip install lief",
        }

    try:
        session = get_session(session_id)
        lib_path_in_apk = f"lib/{arch}/{lib_name}"

        try:
            so_path = _extract_so(session, lib_path_in_apk)
        except KeyError:
            return {
                "status": "error",
                "message": f"Library '{lib_path_in_apk}' not found in APK.",
                "suggestion": "Use list_native_libs to see available libraries.",
            }

        binary = lief.ELF.parse(str(so_path))
        if binary is None:
            return {
                "status": "error",
                "message": f"LIEF could not parse '{lib_name}'.",
                "suggestion": "The file may be corrupted.",
            }

        # Locate the function symbol
        target_sym = None
        for sym in binary.symbols:
            if sym.name == function_name and sym.size > 0:
                target_sym = sym
                break

        # Fallback: search exported functions (may not be in .symtab when stripped)
        if target_sym is None:
            for fn in binary.exported_functions:
                if fn.name == function_name and fn.size > 0:
                    # Create a minimal stand-in
                    target_sym = fn
                    break

        if target_sym is None:
            return {
                "status": "error",
                "message": f"Function '{function_name}' not found in '{lib_name}'.",
                "suggestion": (
                    "Use analyze_native_lib to list exported functions. "
                    "The symbol must have a non-zero size in the ELF symbol table."
                ),
            }

        fn_address = target_sym.address
        fn_size = target_sym.size

        if fn_size == 0:
            return {
                "status": "error",
                "message": f"Function '{function_name}' has size 0 in the symbol table.",
                "suggestion": "The binary may be stripped; try a known exported function.",
            }

        # Read raw bytes from the .so file
        # We look for the section that contains this address
        raw_bytes: Optional[bytes] = None
        so_bytes = so_path.read_bytes()

        for sec in binary.sections:
            sec_start = sec.virtual_address
            sec_end = sec_start + sec.size
            if sec_start <= fn_address < sec_end and sec.size > 0:
                offset_in_section = fn_address - sec_start
                file_offset = sec.offset + offset_in_section
                read_size = min(fn_size, sec_end - fn_address)
                raw_bytes = so_bytes[file_offset: file_offset + read_size]
                break

        # Fallback: use file offset directly (for segments)
        if raw_bytes is None:
            for seg in binary.segments:
                seg_start = seg.virtual_address
                seg_end = seg_start + seg.virtual_size
                if seg_start <= fn_address < seg_end:
                    offset_in_seg = fn_address - seg_start
                    file_offset = seg.file_offset + offset_in_seg
                    raw_bytes = so_bytes[file_offset: file_offset + fn_size]
                    break

        if not raw_bytes:
            return {
                "status": "error",
                "message": f"Could not locate bytes for '{function_name}' in the ELF layout.",
                "suggestion": "The function may be in a non-standard segment.",
            }

        # Disassemble
        md = _capstone_for_arch(arch)
        if md is None:
            return {
                "status": "error",
                "message": f"Unsupported architecture for disassembly: {arch}",
                "suggestion": "Supported architectures: arm64-v8a, armeabi-v7a, x86, x86_64.",
            }

        instructions: list[dict] = []
        try:
            for insn in md.disasm(raw_bytes, fn_address):
                if len(instructions) >= max_instructions:
                    break
                instructions.append(
                    {
                        "address": hex(insn.address),
                        "mnemonic": insn.mnemonic,
                        "op_str": insn.op_str,
                        "bytes": " ".join(f"{b:02x}" for b in insn.bytes),
                    }
                )
        except Exception as exc:
            if not instructions:
                return {
                    "status": "error",
                    "message": f"Capstone disassembly failed: {exc}",
                    "suggestion": "The function bytes may not be valid code for the selected arch.",
                }
            # Partial results are acceptable

        return {
            "status": "ok",
            "data": {
                "function_name": function_name,
                "lib_name": lib_name,
                "arch": arch,
                "address": hex(fn_address),
                "size": fn_size,
                "instruction_count": len(instructions),
                "truncated": len(instructions) >= max_instructions,
                "instructions": instructions,
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Failed to disassemble function: {exc}",
            "suggestion": "Ensure LIEF and Capstone are installed.",
        }


# ---------------------------------------------------------------------------
# Tool 4: search_native_strings
# ---------------------------------------------------------------------------


def _is_printable_char(b: int) -> bool:
    """Return True if the byte value represents a printable ASCII character."""
    return 0x20 <= b <= 0x7E


def _extract_strings_from_bytes(data: bytes, min_length: int) -> list[tuple[int, str]]:
    """Scan raw bytes and yield (offset, string) for printable ASCII runs.

    Args:
        data: Raw bytes to scan.
        min_length: Minimum string length to include.

    Returns:
        List of (offset, string) tuples.
    """
    results: list[tuple[int, str]] = []
    current: list[int] = []
    start_offset = 0

    for i, b in enumerate(data):
        if _is_printable_char(b):
            if not current:
                start_offset = i
            current.append(b)
        else:
            if len(current) >= min_length:
                results.append((start_offset, bytes(current).decode("ascii", errors="replace")))
            current = []

    if len(current) >= min_length:
        results.append((start_offset, bytes(current).decode("ascii", errors="replace")))

    return results


def _classify_string(value: str) -> list[str]:
    """Return a list of category tags for an interesting string."""
    tags: list[str] = []
    if _RE_URL.search(value):
        tags.append("url")
    if _RE_FILE_PATH.search(value):
        tags.append("file_path")
    if _RE_SHELL_CMD.search(value):
        tags.append("shell_command")
    if _RE_CRYPTO.search(value):
        tags.append("crypto")
    return tags


@mcp.tool()
def search_native_strings(
    session_id: str,
    lib_name: str,
    arch: str = "arm64-v8a",
    min_length: int = 4,
) -> dict:
    """Extract readable strings from a native library (.so).

    Scans the ``.rodata`` section (and other sections) for sequences of
    printable ASCII characters with a minimum length.  Strings are
    categorised as URLs, file paths, shell commands, or crypto-related.

    Args:
        session_id: Active analysis session ID returned by load_apk.
        lib_name: Library file name, e.g. ``libfoo.so``.
        arch: ABI directory name (default ``arm64-v8a``).
        min_length: Minimum character length to include (default 4).

    Returns:
        dict: ``{"status": "ok", "data": {"strings": [...], "interesting": [...],
               "total": N, "interesting_count": N}}``

        Each string entry has ``value``, ``offset`` (hex), ``section``,
        and ``tags`` (list of categories).
    """
    try:
        import lief  # noqa: PLC0415
    except ImportError:
        return {
            "status": "error",
            "message": "lief is not installed.",
            "suggestion": "pip install lief",
        }

    try:
        session = get_session(session_id)
        lib_path_in_apk = f"lib/{arch}/{lib_name}"

        try:
            so_path = _extract_so(session, lib_path_in_apk)
        except KeyError:
            return {
                "status": "error",
                "message": f"Library '{lib_path_in_apk}' not found in APK.",
                "suggestion": "Use list_native_libs to see available libraries.",
            }

        binary = lief.ELF.parse(str(so_path))
        if binary is None:
            return {
                "status": "error",
                "message": f"LIEF could not parse '{lib_name}'.",
                "suggestion": "The file may be corrupted.",
            }

        all_strings: list[dict] = []
        interesting: list[dict] = []

        # Prefer named sections; fall back to whole-file scan if no sections
        sections_to_scan: list[tuple[str, bytes, int]] = []  # (section_name, data, file_offset)

        try:
            for sec in binary.sections:
                if sec.size == 0:
                    continue
                try:
                    content = bytes(sec.content)
                except Exception:
                    continue
                sections_to_scan.append((sec.name or "<unnamed>", content, sec.offset))
        except Exception:
            pass

        if not sections_to_scan:
            # Whole-file fallback
            sections_to_scan = [("<raw>", so_path.read_bytes(), 0)]

        seen_values: set[str] = set()

        for sec_name, content, file_offset in sections_to_scan:
            for rel_offset, value in _extract_strings_from_bytes(content, min_length):
                if value in seen_values:
                    continue
                seen_values.add(value)

                abs_offset = file_offset + rel_offset
                tags = _classify_string(value)

                entry = {
                    "value": value,
                    "offset": hex(abs_offset),
                    "section": sec_name,
                    "tags": tags,
                }
                all_strings.append(entry)
                if tags:
                    interesting.append(entry)

        return {
            "status": "ok",
            "data": {
                "lib_name": lib_name,
                "arch": arch,
                "strings": all_strings,
                "interesting": interesting,
                "total": len(all_strings),
                "interesting_count": len(interesting),
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Failed to extract strings from native library: {exc}",
            "suggestion": "Ensure LIEF is installed and the library is a valid ELF binary.",
        }


# ---------------------------------------------------------------------------
# Tool 5: check_native_security
# ---------------------------------------------------------------------------


@mcp.tool()
def check_native_security(
    session_id: str,
    lib_name: str,
    arch: str = "arm64-v8a",
) -> dict:
    """Run security mitigations checks on a native library (.so).

    Checks for:

    - **Stack canary**: presence of ``__stack_chk_fail`` in imports.
    - **NX (No-eXecute)**: absence of segments flagged as both writable and executable.
    - **RELRO**: presence of a GNU_RELRO segment.
    - **BIND_NOW**: DT_FLAGS / DT_BIND_NOW in dynamic entries.
    - **PIE**: whether the binary is position-independent.
    - **Fortify**: presence of ``__*_chk`` wrapper functions (e.g. ``__memcpy_chk``).
    - **Stripped**: whether the ``.symtab`` section is absent (symbols stripped).

    Args:
        session_id: Active analysis session ID returned by load_apk.
        lib_name: Library file name, e.g. ``libfoo.so``.
        arch: ABI directory name (default ``arm64-v8a``).

    Returns:
        dict: ``{"status": "ok", "data": {"checks": {...}, "score": N,
               "max_score": N, "risk_level": "low"|"medium"|"high"}}``

        Each check result has ``enabled`` (bool), ``severity`` (if failing),
        and ``description``.
    """
    try:
        import lief  # noqa: PLC0415
    except ImportError:
        return {
            "status": "error",
            "message": "lief is not installed.",
            "suggestion": "pip install lief",
        }

    try:
        session = get_session(session_id)
        lib_path_in_apk = f"lib/{arch}/{lib_name}"

        try:
            so_path = _extract_so(session, lib_path_in_apk)
        except KeyError:
            return {
                "status": "error",
                "message": f"Library '{lib_path_in_apk}' not found in APK.",
                "suggestion": "Use list_native_libs to see available libraries.",
            }

        binary = lief.ELF.parse(str(so_path))
        if binary is None:
            return {
                "status": "error",
                "message": f"LIEF could not parse '{lib_name}'.",
                "suggestion": "The file may be corrupted.",
            }

        # Collect imported symbol names for quick lookup
        imported_names: set[str] = set()
        try:
            for sym in binary.dynamic_symbols:
                if sym.imported:
                    imported_names.add(sym.name or "")
        except Exception:
            try:
                for fn in binary.imported_functions:
                    imported_names.add(fn.name or "")
            except Exception:
                pass

        # --- 1. Stack canary ---
        has_stack_canary = "__stack_chk_fail" in imported_names

        # --- 2. NX bit (check for W+X segments) ---
        has_wx_segment = False
        try:
            for seg in binary.segments:
                flags = str(seg.flags)
                # LIEF represents flags as bitmask; check PF_W (2) and PF_X (1)
                try:
                    flag_val = int(seg.flags)
                    if (flag_val & 0x1) and (flag_val & 0x2):  # X and W both set
                        has_wx_segment = True
                        break
                except (TypeError, ValueError):
                    # Fallback: string check
                    if "W" in flags and "X" in flags:
                        has_wx_segment = True
                        break
        except Exception:
            pass
        nx_enabled = not has_wx_segment

        # --- 3. RELRO ---
        has_relro = False
        try:
            for seg in binary.segments:
                seg_type = str(seg.type).split(".")[-1]
                if seg_type == "GNU_RELRO":
                    has_relro = True
                    break
        except Exception:
            pass

        # --- 4. BIND_NOW (Full RELRO requires both RELRO segment and BIND_NOW) ---
        has_bind_now = False
        try:
            for dyn in binary.dynamic_entries:
                tag_str = str(dyn.tag).split(".")[-1]
                if tag_str in ("BIND_NOW",):
                    has_bind_now = True
                    break
                # DT_FLAGS with DF_BIND_NOW (0x8)
                if tag_str == "FLAGS":
                    try:
                        if int(dyn.value) & 0x8:
                            has_bind_now = True
                            break
                    except (TypeError, ValueError):
                        pass
        except Exception:
            pass

        # --- 5. PIE ---
        try:
            pie_enabled = binary.is_pie
        except Exception:
            pie_enabled = False

        # --- 6. Fortify (presence of __*_chk functions) ---
        fortify_funcs = [
            name for name in imported_names
            if re.match(r"^__.+_chk$", name)
        ]
        has_fortify = len(fortify_funcs) > 0

        # --- 7. Stripped (absence of .symtab) ---
        has_symtab = False
        try:
            for sec in binary.sections:
                if sec.name == ".symtab":
                    has_symtab = True
                    break
        except Exception:
            pass
        is_stripped = not has_symtab

        # --- Compile results ---
        # Score: 1 point per enabled mitigation (stripped is informational only)
        checks: dict[str, dict] = {
            "stack_canary": {
                "enabled": has_stack_canary,
                "severity": "high" if not has_stack_canary else "none",
                "description": (
                    "Stack canary protects against stack buffer overflows. "
                    "Detected via __stack_chk_fail import."
                ),
                "detail": "__stack_chk_fail" if has_stack_canary else "not found in imports",
            },
            "nx": {
                "enabled": nx_enabled,
                "severity": "high" if not nx_enabled else "none",
                "description": (
                    "NX (No-eXecute) prevents code execution in data segments. "
                    "A W+X segment indicates NX is disabled or bypassed."
                ),
                "detail": "no W+X segments found" if nx_enabled else "W+X segment present",
            },
            "relro": {
                "enabled": has_relro,
                "severity": "medium" if not has_relro else "none",
                "description": (
                    "RELRO (Relocation Read-Only) hardens the GOT against overwrites. "
                    "Partial RELRO: GNU_RELRO segment. Full RELRO also requires BIND_NOW."
                ),
                "detail": "GNU_RELRO segment present" if has_relro else "no GNU_RELRO segment",
            },
            "bind_now": {
                "enabled": has_bind_now,
                "severity": "low" if not has_bind_now else "none",
                "description": (
                    "BIND_NOW (DT_BIND_NOW or DF_BIND_NOW) resolves all symbols at load time, "
                    "enabling Full RELRO protection."
                ),
                "detail": "BIND_NOW flag set" if has_bind_now else "BIND_NOW not set (partial RELRO only)",
            },
            "pie": {
                "enabled": pie_enabled,
                "severity": "medium" if not pie_enabled else "none",
                "description": (
                    "PIE (Position Independent Executable) enables ASLR for the library, "
                    "randomising its load address."
                ),
                "detail": "binary is PIE" if pie_enabled else "binary is not PIE",
            },
            "fortify": {
                "enabled": has_fortify,
                "severity": "low" if not has_fortify else "none",
                "description": (
                    "Fortify Source replaces unsafe libc functions with bounds-checking variants "
                    "(e.g. __memcpy_chk). Detected via __*_chk imports."
                ),
                "detail": fortify_funcs if has_fortify else "no fortified functions found",
            },
            "stripped": {
                "enabled": is_stripped,
                "severity": "info",
                "description": (
                    "Stripped binaries lack a .symtab section, which removes debug symbols. "
                    "This is normal for release builds but hinders analysis."
                ),
                "detail": "no .symtab section (stripped)" if is_stripped else ".symtab present (not stripped)",
            },
        }

        # Score (max 6: stack_canary, nx, relro, bind_now, pie, fortify)
        scored_keys = ["stack_canary", "nx", "relro", "bind_now", "pie", "fortify"]
        score = sum(1 for k in scored_keys if checks[k]["enabled"])
        max_score = len(scored_keys)

        ratio = score / max_score if max_score else 0
        if ratio >= 0.8:
            risk_level = "low"
        elif ratio >= 0.5:
            risk_level = "medium"
        else:
            risk_level = "high"

        return {
            "status": "ok",
            "data": {
                "lib_name": lib_name,
                "arch": arch,
                "checks": checks,
                "score": score,
                "max_score": max_score,
                "risk_level": risk_level,
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Failed to run security checks on native library: {exc}",
            "suggestion": "Ensure LIEF is installed and the library is a valid ELF binary.",
        }


# ===========================================================================
# Phase 5 — Tool 6: find_rop_gadgets
# ===========================================================================
#
# Capstone-driven Return-Oriented Programming gadget discovery over the
# library's ``.text`` section. Weapons-grade native exploitation starts with
# gadget inventory; this tool emits one candidate per ret/bx-lr terminator
# within a sliding window of recent instructions, classified by mnemonic
# shape so the LLM agent can pick.
#
# Design constraints (kept conservative by design):
#
# - Sliding window of 12 instructions. Longer chains exist but produce noisy
#   candidates that distract the agent; longer chains can be re-discovered
#   with ``disassemble_function`` for known symbols.
# - Classifier labels by mnemonic shape, NOT by exploitability — matching
#   the project's "scanner emits, agent reasons from it" posture.
# - Hard cap on returned gadgets (default 50) so a 4 MB lib doesn't burn
#   CI minutes on disassembly.
# ===========================================================================


# Mnemonic patterns for gadget termination.
_TERMINATORS = frozenset({"ret", "bx"})

# How far back to walk for the gadget window.
_ROP_WINDOW_DEPTH = 12


def _classify_gadget(window: list, arch: str) -> str:
    """Return a human-readable kind label for a ret-terminated window.

    Conservative — labels by mnemonic shape, not exploitability.

    Args:
        window: List of capstone instruction mocks ending in a ret/bx.
        arch: Architecture string (currently informational only).

    Returns:
        One of: ``bx_lr``, ``ldp_pop_ret``, ``pop_ret``, ``ldp_ret``,
        ``ldr_ret``, ``sp_mov_ret``, ``sp_adjust_ret``, ``ret_only``,
        ``generic_ret``.
    """
    if not window:
        return "generic_ret"

    mnemonics = [str(getattr(i, "mnemonic", "") or "").lower() for i in window]
    if not mnemonics:
        return "generic_ret"

    last = mnemonics[-1]
    last_op = str(getattr(window[-1], "op_str", "") or "").lower()

    # ARM32 thumb: 'bx lr' is the effective return
    if last == "bx" and "lr" in last_op:
        return "bx_lr"

    seen = set(mnemonics)
    op_strs = " ".join(
        str(getattr(i, "op_str", "") or "").lower() for i in window
    )

    if "pop" in seen:
        if "ldp" in seen:
            return "ldp_pop_ret"
        return "pop_ret"
    if "ldp" in seen:
        return "ldp_ret"
    if "ldr" in seen:
        return "ldr_ret"
    if "mov" in seen and "sp" in op_strs:
        return "sp_mov_ret"
    if "add" in seen and "sp" in op_strs:
        return "sp_adjust_ret"
    if last == "ret" and len(window) == 1:
        return "ret_only"
    return "generic_ret"


@mcp.tool()
def find_rop_gadgets(
    session_id: str,
    lib_name: str,
    arch: str = "arm64-v8a",
    max_gadgets: int = 50,
) -> dict:
    """Find Return-Oriented Programming gadget *candidates* in a native library.

    Walks the library's ``.text`` section with Capstone, emits one gadget
    candidate per ret/bx-lr terminator within a sliding window of recent
    instructions, and classifies each by mnemonic shape.

    This is a **candidate generator**, not a full ROP finder like
    ROPgadget / ropper. The scan uses a single disassembly mode per arch
    (arm64/Thumb for armeabi, ARM64 for arm64-v8a) and resets the window
    after each terminator, so it will **miss**:

    - overlapping gadgets (the window doesn't slide)
    - Thumb-interleaved code on armeabi-v7a (only one mode is scanned)

    For exhaustive ROP coverage, export ``.text`` and run a dedicated
    tool (ropgadget / ropper) externally — the LLM agent can orchestrate
    that from this tool's output.

    Args:
        session_id: Active analysis session ID returned by load_apk.
        lib_name: Library file name, e.g. ``libfoo.so``.
        arch: ABI directory name (default ``arm64-v8a``). Supported: arm64-v8a,
            armeabi-v7a, x86, x86_64.
        max_gadgets: Cap on returned gadgets (default 50). Multi-MB libraries
            pre-cap disassembly time so CI stays bounded.

    Returns:
        dict: ``{"status": "ok", "data": {"gadgets": [...], "count": N,
        "truncated": bool, "lib_name": str, "arch": str}}``

        Each gadget has ``kind`` (e.g. ``pop_ret``), ``address`` (hex of
        terminator), ``start_address`` (hex of window start), and
        ``instructions`` (list of ``{address, mnemonic, op_str}``).
    """
    try:
        import lief  # noqa: PLC0415
    except ImportError:
        return {
            "status": "error",
            "message": "lief is not installed.",
            "suggestion": "pip install lief",
        }

    try:
        session = get_session(session_id)
        lib_path_in_apk = f"lib/{arch}/{lib_name}"

        try:
            so_path = _extract_so(session, lib_path_in_apk)
        except KeyError:
            return {
                "status": "error",
                "message": f"Library '{lib_path_in_apk}' not found in APK.",
                "suggestion": "Use list_native_libs to see available libraries.",
            }

        binary = lief.ELF.parse(str(so_path))
        if binary is None:
            return {
                "status": "error",
                "message": f"LIEF could not parse '{lib_name}'.",
                "suggestion": "The file may be corrupted.",
            }

        # Locate .text section. If missing or empty, no executable gadgets.
        text_section = None
        try:
            for sec in binary.sections:
                if getattr(sec, "name", "") == ".text":
                    text_section = sec
                    break
        except Exception:
            text_section = None

        if text_section is None or int(getattr(text_section, "size", 0) or 0) == 0:
            return {
                "status": "ok",
                "data": {
                    "lib_name": lib_name,
                    "arch": arch,
                    "gadgets": [],
                    "count": 0,
                    "truncated": False,
                },
            }

        md = _capstone_for_arch(arch)
        if md is None:
            return {
                "status": "error",
                "message": f"Unsupported architecture for ROP scan: {arch}",
                "suggestion": "Supported architectures: arm64-v8a, armeabi-v7a, x86, x86_64.",
            }

        try:
            raw = bytes(text_section.content)
        except Exception:
            raw = b""
        base_vaddr = int(getattr(text_section, "virtual_address", 0) or 0)

        gadgets: list[dict] = []
        truncated = False
        window: list = []

        try:
            for insn in md.disasm(raw, base_vaddr):
                window.append(insn)
                if len(window) > _ROP_WINDOW_DEPTH:
                    window = window[-_ROP_WINDOW_DEPTH:]

                last_mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
                last_op_str = str(getattr(insn, "op_str", "") or "").lower()

                # bx without lr is a regular indirect branch, not a return.
                if last_mnemonic == "bx" and "lr" not in last_op_str:
                    continue

                is_terminator = last_mnemonic in _TERMINATORS
                if not is_terminator:
                    continue
                if not window:
                    continue

                kind = _classify_gadget(window, arch)
                gadgets.append({
                    "kind": kind,
                    "address": hex(int(getattr(window[-1], "address", 0) or 0)),
                    "start_address": hex(int(getattr(window[0], "address", 0) or 0)),
                    "instructions": [
                        {
                            "address": hex(int(getattr(i, "address", 0) or 0)),
                            "mnemonic": str(getattr(i, "mnemonic", "") or ""),
                            "op_str": str(getattr(i, "op_str", "") or ""),
                        } for i in window
                    ],
                })
                window = []
                if len(gadgets) >= max_gadgets:
                    truncated = True
                    break
        except Exception:
            # Capstone failures mid-stream: emit whatever we have so far.
            pass

        return {
            "status": "ok",
            "data": {
                "lib_name": lib_name,
                "arch": arch,
                "count": len(gadgets),
                "truncated": truncated,
                "gadgets": gadgets,
            },
        }
    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Failed to scan for ROP gadgets: {exc}",
            "suggestion": "Ensure LIEF and Capstone are installed and the .so is a valid ELF.",
        }


# ===========================================================================
# Phase 5 — Tool 7: generate_jni_hook
# ===========================================================================
#
# Produces a Frida JS script that hooks every ``Java_<class>_<method>``
# export from a native library. The classic Android high-grade capability
# gap: many banking / fintech apps move crypto, auth, and license validation
# into .so native code, and the only sane way to peek inside is to hook
# the JNI entry points from inside a live target process.
#
# Output:
#   <session.workspace>/native_hooks/<lib_name>_jni.js
#
# Designed for compose-with: ``execute_native_hook`` can take the produced
# JS path directly as input, so the verb chain is:
#
#   analyze_native_lib(lib) → generate_jni_hook(lib) → execute_native_hook(js)
# ===========================================================================


# ---------------------------------------------------------------------------
# JNI demangling (Phase 5 — Tool 7 helpers)
# ---------------------------------------------------------------------------
#
# JNI symbol mangling (per the JNI spec, Chapter 11.3):
#   Java_<fully-qualified-class>_<method>
#
# - '/'        → '_' (package separator to underscore)
# - '_'        → '_1' (underscore was escaped in C name)
# - ';'        → '_2'
# - '['        → '_3'
# - '\\xNN'    → '_0NNNN' (Unicode char by code point)
# - overloads  → '__' suffix before method signature
#
# This module implements a simple, correct-for-common-symbols demangler
# that walks the symbol char-by-char and handles the core escape set.
# Edge cases (_0NNNN for non-ASCII, double-underscore overload markers)
# are rejected gracefully with return-None so the caller can emit a clean
# per-skipped log instead of a broken ``Java.use`` call.
# ---------------------------------------------------------------------------


def _parse_jni_export(symbol: str) -> tuple[str, str] | None:
    """Parse a ``Java_<cls>_<method>`` symbol into ``(class_name, method_name)``.

    Returns ``None`` if the symbol does not conform to the JNI mangling
    scheme (overload markers (`__`), Unicode escapes (`_0xxxx`), or
    missing method separator). Agents should reconcile ambiguous class
    names with ``dex.list_classes``.
    """
    if not symbol or not symbol.startswith("Java_"):
        return None

    body = symbol[5:]  # strip "Java_"
    n = len(body)
    if n == 0:
        return None

    # ---- Locate the method separator (the last *bare* underscore) ----
    # A bare underscore is one that is NOT part of an escape sequence
    # (_1, _2, _3, _0xxxx, __).  Escape pairs are skipped entirely.
    method_sep = -1
    i = 0
    while i < n:
        if body[i] != "_":
            i += 1
            continue
        # ch == '_'
        if i + 1 >= n:
            # trailing '_' — this is the method separator with
            # nothing after it.  Mark it and stop.
            method_sep = i
            break
        nxt = body[i + 1]
        if nxt in ("1", "2", "3"):
            # _1 / _2 / _3 → escape sequence, not a separator
            i += 2
            continue
        if nxt == "_" or nxt == "0":
            # __ overload or _0xxxx Unicode — reject the whole symbol.
            return None
        # otherwise nxt is a regular character → bare underscore
        method_sep = i
        i += 1

    if method_sep == -1:
        return None  # no method separator found

    # ---- Build class name from body[:method_sep] ----
    class_chars: list[str] = []
    i = 0
    while i < method_sep:
        ch = body[i]
        if ch != "_":
            class_chars.append(ch)
            i += 1
            continue
        # ch == '_' — we already know from the first pass that this
        # underscore is either bare or part of an escape pair.
        nxt = body[i + 1]
        if nxt == "1":
            class_chars.append("_")
        elif nxt == "2":
            class_chars.append(";")
        elif nxt == "3":
            class_chars.append("[")
        else:
            # bare underscore — package separator (originally '/')
            class_chars.append("/")
        i += 2 if nxt in ("1", "2", "3") else 1

    cls = "".join(class_chars).replace("/", ".")

    # ---- Method name is everything after the separator ----
    method = body[method_sep + 1:]
    if not method:
        return None

    return cls, method


@mcp.tool()
def generate_jni_hook(
    session_id: str,
    lib_name: str,
    arch: str = "arm64-v8a",
    class_filter: str | None = None,
) -> dict:
    """Generate a Frida JS script that hooks all ``Java_*`` exports from a library.

    For each ``Java_<class>_<method>`` symbol in the named library, generates
    a ``Java.use(class).method.implementation`` swap that logs the call,
    forwards to the native implementation, and ``send()``s a structured
    payload back to the Frida client. The composed script is written to
    ``<session.workspace>/native_hooks/<lib>_jni.js``.

    When the library exports no JNI symbols, returns ``status:ok`` with
    ``hooks=[]`` and a verification message — the library may be unloaded
    by the target process, or the symbols may be private (dlsym rather
    than JNI_OnLoad).

    Args:
        session_id: Active analysis session ID returned by load_apk.
        lib_name: Library file name, e.g. ``libfoo.so``.
        arch: ABI directory name (default ``arm64-v8a``).
        class_filter: Optional substring restricting hooks to symbols whose
            parsed class name contains the filter (case-insensitive).

    Returns:
        dict: ``{"status": "ok", "data": {"hooks": [...], "script": str,
        "file_path": str, "message": str}}``

        Each ``hooks`` entry has ``symbol``, ``class_name``, ``method_name``,
        and ``address``.
    """
    try:
        import lief  # noqa: PLC0415
    except ImportError:
        return {
            "status": "error",
            "message": "lief is not installed.",
            "suggestion": "pip install lief",
        }

    try:
        session = get_session(session_id)
        lib_path_in_apk = f"lib/{arch}/{lib_name}"

        try:
            so_path = _extract_so(session, lib_path_in_apk)
        except KeyError:
            return {
                "status": "error",
                "message": f"Library '{lib_path_in_apk}' not found in APK.",
                "suggestion": "Use list_native_libs to see available libraries.",
            }

        binary = lief.ELF.parse(str(so_path))
        if binary is None:
            return {
                "status": "error",
                "message": f"LIEF could not parse '{lib_name}'.",
                "suggestion": "The file may be corrupted.",
            }

        raw_exports: list[dict] = []
        try:
            exports = list(binary.exported_functions or [])
        except Exception:
            exports = []

        for fn in exports:
            name = str(getattr(fn, "name", "") or "")
            parsed = _parse_jni_export(name)
            if not parsed:
                continue
            cls, method = parsed

            if class_filter:
                cf = str(class_filter).strip().lower()
                if cf and cf not in cls.lower():
                    continue

            try:
                addr = int(getattr(fn, "address", 0) or 0)
            except Exception:
                addr = 0

            raw_exports.append({
                "symbol": name,
                "class_name": cls,
                "method_name": method,
                "address": hex(addr),
            })

        if not raw_exports:
            return {
                "status": "ok",
                "data": {
                    "lib_name": lib_name,
                    "arch": arch,
                    "hooks": [],
                    "script": "",
                    "file_path": "",
                    "message": (
                        "No Java_* JNI exports found in this library — verify "
                        "the library is actually loaded by the target app, "
                        "and that any private registration in JNI_OnLoad is "
                        "covered by listing exported symbols."
                    ),
                },
            }

        # Compose the Frida JS: one Java.use().method.implementation swap per hook.
        # A JS-side helper defensively stringifies each argument so send()
        # doesn't choke on non-serializable Java object handles. Static
        # native methods are not detected at the ELF level — the generated
        # hook binds to the instance. If the agent knows the method is
        # static, they should adjust the script manually.
        script_parts: list[str] = [
            "// Generated by apksaw generate_jni_hook — review before running on a target.\n",
            "// Source: " + lib_path_in_apk + "\n",
            "function args_to_json(args) {\n"
            "    var a = [];\n"
            "    for (var i = 0; i < args.length; i++) {\n"
            "        try { a.push(String(args[i])); } catch (_) { a.push(null); }\n"
            "    }\n"
            "    return a;\n"
            "}\n\n",
            "Java.perform(function () {\n",
        ]
        for hook in raw_exports:
            script_parts.append(
                "    try {{\n"
                "        var cls = Java.use(\"{cls}\");\n"
                "        cls.{mth}.implementation = function () {{\n"
                "            send({{__apksaw_kind: \"jni_call\","
                " method: \"{mth}\","
                " args: args_to_json(arguments)}});\n"
                "            var ret = this.{mth}.apply(this, arguments);\n"
                "            send({{__apksaw_kind: \"jni_return\","
                " method: \"{mth}\","
                " value: ret !== undefined ? String(ret) : null}});\n"
                "            return ret;\n"
                "        }};\n"
                "        console.log(\"[apksaw] hooked {cls}.{mth}\");\n"
                "    }} catch (e) {{\n"
                "        console.log(\"[apksaw] skipped {cls}.{mth}: \" + e);\n"
                "    }}\n\n".format(
                    cls=hook["class_name"],
                    mth=hook["method_name"],
                )
            )
        script_parts.append("});\n")
        script = "".join(script_parts)

        out_dir = session.workspace / "native_hooks"
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^\w\-.]", "_", lib_name)
        out_path = out_dir / f"{safe_name}_jni.js"
        out_path.write_text(script)

        return {
            "status": "ok",
            "data": {
                "lib_name": lib_name,
                "arch": arch,
                "hooks": raw_exports,
                "script": script,
                "file_path": str(out_path),
                "message": (
                    f"Generated {len(raw_exports)} JNI hook(s). "
                    "Run via execute_native_hook (gadget path) or: "
                    f"frida -U -l {out_path} -f {session.package_name} --no-pause"
                    if session.package_name else
                    f"Generated {len(raw_exports)} JNI hook(s). "
                    f"Run via: frida -U -l {out_path}"
                ),
            },
        }
    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a session.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Failed to generate JNI hook script: {exc}",
            "suggestion": "Ensure LIEF is installed and the library is a valid ELF binary.",
        }


# ===========================================================================
# Phase 5 — Tool 8: execute_native_hook
# ===========================================================================
#
# Runtime execution of a generated Frida JS hook script against the target
# app on a connected device. Closes the verify loop that the static
# ``generate_jni_hook`` leaves open: the agent now has *both* the candidate
# exploit lever (the script) and the means to drive it. Same posture as
# ``runtime.run_frida_script`` — confirm-gated dry-run, ADB device check,
# frida Python client probe.
# ===========================================================================


def _frida_plan_response(js_path: str, package: str | None, capture_seconds: int) -> dict:
    """Build the dry-run plan for execute_native_hook (no side effects)."""
    command = f"frida -U -l {js_path}"
    if package:
        command += f" -f {package} --no-pause"
    return {
        "status": "ok",
        "data": {
            "plan": True,
            "command": command,
            "tool_check": {
                "adb_device_required": True,
                "frida_python_required": True,
            },
            "steps": [
                "Verify `adb devices` lists the target device",
                "Verify the frida Python client is importable (uv add frida-tools)",
                "Spawn/attach the target app via frida.get_device_manager()",
                "Load the JS hook script into the spawned session",
                f"Capture send() payloads for {capture_seconds}s",
                "Return classified findings via the message handler",
            ],
        },
    }


@mcp.tool()
def execute_native_hook(
    session_id: str,
    js_path: str,
    package: str | None = None,
    capture_seconds: int = 5,
    confirm: bool = False,
) -> dict:
    """Execute a generated Frida JS hook script against the target app.

    Spawns (or attaches to) the target package via the frida Python
    client, loads the JS script, and collects ``send()`` payloads for
    ``capture_seconds`` before unloading. Output shape mirrors
    ``runtime.capture_runtime_secrets`` so downstream reasoning is uniform
    across Java and native hooks.

    Safety:

    - ``confirm=False`` returns a plan + tool_check WITHOUT spawning any
      process or touching the device. ``subprocess`` is not invoked in
      this mode (same dry-run posture as ``exploit_gen`` and
      ``runtime.repackage_with_gadget``).
    - ``confirm=True`` requires BOTH an ADB device AND a working frida
      Python install. If either is missing, the tool declines and reports
      the missing dependency rather than failing mid-pipeline.

    Args:
        session_id: Active analysis session ID.
        js_path: Absolute path to the JS hook script (typically produced
            by ``generate_jni_hook``).
        package: Target Android package name. Required when ``confirm=True``
            — there is no reliable "attach to whatever is running" on Android,
            so the tool spawns and attaches to this package. Ignored in the
            ``confirm=False`` dry-run (it is only echoed into the plan command).
        capture_seconds: How long to listen for ``send()`` payloads
            (default 5).
        confirm: Must be ``True`` to actually spawn / attach. ``False``
            returns a dry-run plan only.

    Returns:
        Dry-run: ``{"status": "ok", "data": {"plan": True, "command": str, ...}}``
        Live:    ``{"status": "ok", "data": {"findings": [...], "captured_count": N, ...}}``
        Error:   ``{"status": "error", "message": str, "suggestion": str}``
    """
    try:
        js_file = Path(js_path)
        if not js_file.exists():
            return {
                "status": "error",
                "message": f"Hook script not found at: {js_path}",
                "suggestion": "Generate it with generate_jni_hook first.",
            }

        if not confirm:
            return _frida_plan_response(str(js_file), package, capture_seconds)

        if not check_device_connected():
            return {
                "status": "error",
                "message": "No ADB device connected.",
                "suggestion": "Connect a device and verify with `adb devices`.",
            }

        if not _IMPORT_FRIDA.available:
            return {
                "status": "error",
                "message": (
                    "frida Python client is not importable. "
                    "execute_native_hook requires frida-tools to spawn the target."
                ),
                "suggestion": "Install with: uv add frida-tools (or pip install frida-tools).",
            }

        # Live execution. Failures here are reported as status:error so the
        # agent can iterate on the script (e.g. correct a missing class name,
        # adjust the import path, etc.).

        # package is required for live execution — there is no reliable
        # "attach to whatever is running" on Android. If the caller has the
        # package name, they must supply it.
        if not package:
            return {
                "status": "error",
                "message": "package is required for execute_native_hook when confirm=True.",
                "suggestion": (
                    "Pass the target app's package name (e.g. the session's "
                    "package_name) to spawn and attach."
                ),
            }

        try:
            frida_mod = _IMPORT_FRIDA.module
            mgr = frida_mod.get_device_manager()
            device = mgr.get_usb_device(timeout=5)
            pid = device.spawn([package])
            session = device.attach(pid)

            captured: list[dict] = []

            def _on_message(message, _data):
                if isinstance(message, dict):
                    captured.append(message)

            script = session.create_script(js_file.read_text())
            script.on("message", _on_message)
            script.load()

            if pid is not None:
                try:
                    device.resume(pid)
                except Exception:
                    pass

            time.sleep(max(0, int(capture_seconds)))

            try:
                script.unload()
            except Exception:
                pass

            summary: dict[str, int] = {}
            for msg in captured:
                payload = msg.get("payload") if isinstance(msg, dict) else None
                kind = payload.get("__apksaw_kind") if isinstance(payload, dict) else None
                if kind:
                    summary[kind] = summary.get(kind, 0) + 1

            return {
                "status": "ok",
                "data": {
                    "package": package,
                    "pid": pid,
                    "captured_count": len(captured),
                    "findings": captured,
                    "capture_seconds": capture_seconds,
                    "summary": summary,
                    "tool_check": {
                        "adb_device_required": True,
                        "frida_python_required": True,
                    },
                },
            }
        except Exception as exec_exc:
            return {
                "status": "error",
                "message": f"Failed to execute native hook: {exec_exc}",
                "suggestion": (
                    "Verify the target accepts the spawn — Frida gadget installed "
                    "and listening, or root with frida-server running."
                ),
            }
    except Exception as outer_exc:
        return {
            "status": "error",
            "message": f"Failed to plan / execute native hook: {outer_exc}",
            "suggestion": "Re-check inputs (js_path, package) and confirm session is alive.",
        }
