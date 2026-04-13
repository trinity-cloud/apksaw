"""Native library (.so) analysis tools for Android APK threat analysis."""

import re
import string
import zipfile
from pathlib import Path
from typing import Optional

from apksaw.server import mcp
from apksaw.session import Session, get_session

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
        from capstone import CsError  # noqa: PLC0415
    except ImportError:
        return {
            "status": "error",
            "message": "capstone is not installed.",
            "suggestion": "pip install capstone",
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
