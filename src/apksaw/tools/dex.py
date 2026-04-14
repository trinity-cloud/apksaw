"""DEX bytecode analysis and decompilation tools."""

import asyncio
import re
import traceback
from pathlib import Path
from typing import Optional

from apksaw.server import mcp
from apksaw.session import get_session

# ---------------------------------------------------------------------------
# Module-level JADX class cache
# keyed by (apk_sha256, java_class_name) -> decompiled source str
# ---------------------------------------------------------------------------
_jadx_class_cache: dict[tuple[str, str], str] = {}


# ---------------------------------------------------------------------------
# Name-conversion helpers
# ---------------------------------------------------------------------------


def _dalvik_to_java(name: str) -> str:
    """Convert a Dalvik class name to Java-style.

    Examples:
        "Lcom/example/Foo;" -> "com.example.Foo"
        "Lcom/example/Foo$Bar;" -> "com.example.Foo$Bar"
    """
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def _java_to_dalvik(name: str) -> str:
    """Convert a Java-style class name to Dalvik format.

    Examples:
        "com.example.Foo" -> "Lcom/example/Foo;"
        "Lcom/example/Foo;" -> "Lcom/example/Foo;"  (already dalvik, passthrough)
    """
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"


def _normalize_class_name(name: str) -> str:
    """Return Dalvik format regardless of input style."""
    name = name.strip()
    if name.startswith("L") and name.endswith(";"):
        return name
    return _java_to_dalvik(name)


# ---------------------------------------------------------------------------
# Tool: list_classes
# ---------------------------------------------------------------------------


@mcp.tool()
def list_classes(
    session_id: str,
    filter: str = "",
    package_filter: str = "",
    exclude_external: bool = True,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List classes defined (or referenced) in the APK.

    Args:
        session_id: Active analysis session ID returned by load_apk.
        filter: Optional regex pattern matched against the full class name
                (Java-style, e.g. ".*Activity.*").
        package_filter: Filter by package prefix in Java style
                        (e.g. "com.example"). Matched against the converted name.
        exclude_external: When True (default) only include classes that are
                          actually defined in this APK's DEX, not external SDK
                          references.
        limit: Maximum number of classes to return (default 50).
        offset: Number of classes to skip for pagination (default 0).

    Returns:
        {"status": "ok", "data": {"classes": [...], "total": N, "offset": O, "limit": L}}
        Each entry contains: class_name (Java style), dalvik_name, method_count,
        field_count, is_external.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        compiled_filter = re.compile(filter) if filter else None

        results = []
        for class_analysis in analysis.get_classes():
            if exclude_external and class_analysis.is_external():
                continue

            dalvik_name = class_analysis.name
            java_name = _dalvik_to_java(dalvik_name)

            # package_filter check
            if package_filter:
                pkg = package_filter.rstrip(".")
                if not java_name.startswith(pkg + ".") and not java_name == pkg:
                    continue

            # regex filter check
            if compiled_filter and not compiled_filter.search(java_name):
                continue

            method_count = len(list(class_analysis.get_methods()))
            field_count = len(list(class_analysis.get_fields()))

            results.append(
                {
                    "class_name": java_name,
                    "dalvik_name": dalvik_name,
                    "method_count": method_count,
                    "field_count": field_count,
                    "is_external": class_analysis.is_external(),
                }
            )

        total = len(results)
        page = results[offset : offset + limit]

        return {
            "status": "ok",
            "data": {
                "classes": page,
                "total": total,
                "offset": offset,
                "limit": limit,
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
# Tool: get_class_info
# ---------------------------------------------------------------------------


@mcp.tool()
def get_class_info(session_id: str, class_name: str) -> dict:
    """Return detailed information about a specific class.

    Accepts either Dalvik format ("Lcom/example/Foo;") or Java format
    ("com.example.Foo").

    Args:
        session_id: Active analysis session ID.
        class_name: The class to inspect (Java or Dalvik format).

    Returns:
        {"status": "ok", "data": { class_name, dalvik_name, superclass,
        interfaces, access_flags, is_external, methods: [...], fields: [...] }}
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        dalvik_name = _normalize_class_name(class_name)

        # Try exact lookup first
        class_analysis = None
        for ca in analysis.find_classes(name=re.escape(dalvik_name)):
            class_analysis = ca
            break

        if class_analysis is None:
            # Fallback: try regex search for partial / Java-style input
            java_name = _dalvik_to_java(dalvik_name)
            escaped = re.escape(java_name).replace(r"\.", "[./]")
            for ca in analysis.find_classes(name=escaped):
                class_analysis = ca
                break

        if class_analysis is None:
            return {
                "status": "error",
                "data": {
                    "message": f"Class '{class_name}' not found.",
                    "suggestion": (
                        "Use list_classes to browse available classes. "
                        "Ensure the class name is correct (Java or Dalvik format)."
                    ),
                },
            }

        # Basic metadata — available from ClassAnalysis regardless of external status
        superclass = None
        interfaces = []
        access_flags = ""

        if not class_analysis.is_external():
            vm_class = class_analysis.get_vm_class()
            raw_super = vm_class.get_superclassname()
            if raw_super:
                superclass = _dalvik_to_java(raw_super)
            raw_interfaces = vm_class.get_interfaces()
            if raw_interfaces:
                interfaces = [_dalvik_to_java(i) for i in raw_interfaces]
            access_flags = vm_class.get_access_flags_string()

        # Methods
        methods = []
        for ma in class_analysis.get_methods():
            methods.append(
                {
                    "name": ma.name,
                    "descriptor": ma.descriptor,
                    "access_flags": ma.access,
                    "is_external": ma.is_external(),
                }
            )

        # Fields
        fields = []
        for fa in class_analysis.get_fields():
            field_obj = fa.get_field()
            field_type = ""
            field_access = ""
            try:
                field_type = _dalvik_to_java(field_obj.get_descriptor())
                field_access = field_obj.get_access_flags_string()
            except Exception:
                pass
            fields.append(
                {
                    "name": fa.name,
                    "type": field_type,
                    "access_flags": field_access,
                }
            )

        return {
            "status": "ok",
            "data": {
                "class_name": _dalvik_to_java(class_analysis.name),
                "dalvik_name": class_analysis.name,
                "superclass": superclass,
                "interfaces": interfaces,
                "access_flags": access_flags,
                "is_external": class_analysis.is_external(),
                "methods": methods,
                "fields": fields,
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
# Tool: list_methods
# ---------------------------------------------------------------------------


@mcp.tool()
def list_methods(
    session_id: str,
    class_name: str = "",
    filter: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List methods, optionally filtered by class or name pattern.

    Args:
        session_id: Active analysis session ID.
        class_name: If provided, restrict results to this class (Java or
                    Dalvik format). Accepts partial Dalvik or Java format.
        filter: Optional regex applied to the method name.
        limit: Maximum results to return (default 50).
        offset: Pagination offset (default 0).

    Returns:
        {"status": "ok", "data": {"methods": [...], "total": N, "offset": O, "limit": L}}
        Each entry: class_name, method_name, descriptor, access_flags, is_external.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        compiled_filter = re.compile(filter) if filter else None

        def _iter_classes():
            if class_name:
                dalvik = _normalize_class_name(class_name)
                for ca in analysis.find_classes(name=re.escape(dalvik)):
                    yield ca
                    return
                # fallback substring
                for ca in analysis.get_classes():
                    if dalvik in ca.name or class_name in _dalvik_to_java(ca.name):
                        yield ca
                        return
            else:
                yield from analysis.get_classes()

        results = []
        for ca in _iter_classes():
            for ma in ca.get_methods():
                if compiled_filter and not compiled_filter.search(ma.name):
                    continue
                results.append(
                    {
                        "class_name": _dalvik_to_java(ca.name),
                        "method_name": ma.name,
                        "descriptor": ma.descriptor,
                        "access_flags": ma.access,
                        "is_external": ma.is_external(),
                    }
                )

        total = len(results)
        page = results[offset : offset + limit]

        return {
            "status": "ok",
            "data": {
                "methods": page,
                "total": total,
                "offset": offset,
                "limit": limit,
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
# Internal decompilation helpers
# ---------------------------------------------------------------------------


def _disassemble_method(encoded_method) -> str:
    """Produce smali-like disassembly from a method's DalvikCode.

    Falls back to a minimal representation when bytecode is not available
    (e.g., abstract or native methods).
    """
    code = encoded_method.get_code()
    if code is None:
        return "# (no bytecode — abstract or native method)"

    lines = []
    try:
        for instruction in code.get_bc().get_instructions():
            lines.append(f"    {instruction.get_name():30s} {instruction.get_output()}")
    except Exception as exc:
        lines.append(f"# Error reading instructions: {exc}")

    return "\n".join(lines) if lines else "# (empty method body)"


def _decompile_single_method(
    dex_list, analysis, method_analysis
) -> tuple[str, str]:
    """Try DAD decompilation; fall back to smali disassembly.

    Returns (source: str, language: "java"|"smali").
    """
    # --- Attempt DAD decompilation ---
    try:
        from androguard.decompiler.decompiler import DecompilerDAD

        dec = DecompilerDAD(dex_list, analysis)
        # DecompilerDAD.display_source writes to stdout; we capture via get_source
        em = method_analysis.get_method()
        src = dec.get_source_method(em)
        if src and src.strip():
            return src, "java"
    except Exception:
        pass  # decompiler unavailable or failed

    # --- Fallback: smali disassembly ---
    try:
        em = method_analysis.get_method()
        if not method_analysis.is_external():
            asm = _disassemble_method(em)
            return asm, "smali"
    except Exception as exc:
        return f"# Disassembly failed: {exc}", "smali"

    return "# (external method — no bytecode available)", "smali"


# ---------------------------------------------------------------------------
# JADX backend helpers
# ---------------------------------------------------------------------------


def _run_async(coro):
    """Execute *coro* synchronously, working around an already-running event loop.

    asyncio.run() raises RuntimeError when called from inside a running loop
    (common in MCP server environments that use asyncio internally).  We detect
    that case and spin up a fresh thread-local loop instead.
    """
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def _decompile_method_jadx(session, class_name: str, method_name: str, descriptor: str) -> dict:
    """Decompile a single method using the JADX backend.

    Uses single-class decompilation when JADX supports it, falling back to a
    full-APK decompile-once strategy.  Results from decompile_class_jadx are
    cached at module level keyed by (sha256, class_name).

    Falls back to the Androguard backend if the method is not found in the
    JADX output.
    """
    from apksaw.utils.jadx import decompile_method_jadx as _jadx_decompile_method

    java_name = _dalvik_to_java(_normalize_class_name(class_name))
    java_dir = str(session.workspace / "java")

    method_source = _run_async(
        _jadx_decompile_method(
            str(session.apk_path),
            java_name,
            method_name,
            java_dir,
            descriptor=descriptor,
        )
    )

    if method_source is not None:
        return {
            "status": "ok",
            "data": {
                "class_name": java_name,
                "method_name": method_name,
                "results": [
                    {
                        "descriptor": descriptor,
                        "access_flags": "",
                        "source": method_source,
                        "language": "java",
                        "backend": "jadx",
                    }
                ],
            },
        }

    # Method not found in JADX output — fall back to Androguard
    return _decompile_method_androguard(session, class_name, method_name, descriptor)


def _decompile_method_androguard(
    session, class_name: str, method_name: str, descriptor: str
) -> dict:
    """Androguard decompilation path, extracted for reuse as a fallback."""
    analysis = session.analysis
    dex_list = session.dex_list
    dalvik_class = _normalize_class_name(class_name)
    java_name = _dalvik_to_java(dalvik_class)

    class_analysis = None
    for ca in analysis.find_classes(name=re.escape(dalvik_class)):
        class_analysis = ca
        break

    if class_analysis is None:
        return {
            "status": "error",
            "data": {
                "message": f"Class '{class_name}' not found (JADX fallback also failed).",
                "suggestion": "Use list_classes to find the correct class name.",
            },
        }

    matched_methods = []
    for ma in class_analysis.get_methods():
        if ma.name != method_name:
            continue
        if descriptor and ma.descriptor != descriptor:
            continue
        matched_methods.append(ma)

    if not matched_methods:
        return {
            "status": "error",
            "data": {
                "message": (
                    f"Method '{method_name}' not found in '{class_name}'."
                    + (f" (descriptor: {descriptor})" if descriptor else "")
                ),
                "suggestion": "Use list_methods to see available methods and their descriptors.",
            },
        }

    results = []
    for ma in matched_methods:
        source, language = _decompile_single_method(dex_list, analysis, ma)
        results.append(
            {
                "descriptor": ma.descriptor,
                "access_flags": ma.access,
                "source": source,
                "language": language,
                "backend": "androguard",
            }
        )

    return {
        "status": "ok",
        "data": {
            "class_name": java_name,
            "method_name": method_name,
            "results": results,
        },
    }


def _decompile_class_jadx(session, class_name: str) -> dict:
    """Decompile an entire class using the JADX backend.

    Results are cached in ``_jadx_class_cache`` keyed by
    ``(session.sha256, java_class_name)`` so repeated calls for the same class
    within a session are instant.
    """
    from apksaw.utils.jadx import decompile_class_jadx as _jadx_decompile_class

    java_name = _dalvik_to_java(_normalize_class_name(class_name))
    cache_key = (session.sha256, java_name)

    if cache_key in _jadx_class_cache:
        source = _jadx_class_cache[cache_key]
    else:
        java_dir = str(session.workspace / "java")
        source = _run_async(
            _jadx_decompile_class(str(session.apk_path), java_name, java_dir)
        )
        if source is not None:
            _jadx_class_cache[cache_key] = source

    if source is None:
        return {
            "status": "error",
            "data": {
                "message": (
                    f"JADX output file not found for class '{java_name}'. "
                    f"Searched under {session.workspace / 'java'}."
                ),
                "suggestion": (
                    "Verify the class name is correct. "
                    "Run decompile_apk_full to ensure the APK has been fully decompiled."
                ),
            },
        }

    return {
        "status": "ok",
        "data": {
            "class_name": java_name,
            "source": source,
            "language": "java",
            "backend": "jadx",
            "method_count": len(list(re.finditer(r'\bvoid\b|\bint\b|\bboolean\b|\bString\b|\bobject\b', source))),
        },
    }


# ---------------------------------------------------------------------------
# Tool: decompile_method
# ---------------------------------------------------------------------------


@mcp.tool()
def decompile_method(
    session_id: str,
    class_name: str,
    method_name: str,
    descriptor: str = "",
    backend: str = "androguard",
) -> dict:
    """Decompile a specific method to Java-like pseudocode or smali fallback.

    Args:
        session_id: Active analysis session ID.
        class_name: The class containing the method (Java or Dalvik format).
        method_name: The method to decompile (e.g. "onCreate").
        descriptor: Optional JVM descriptor to disambiguate overloads
                    (e.g. "(Landroid/os/Bundle;)V"). When omitted all
                    matching overloads are returned.
        backend: Decompilation backend to use. "androguard" (default) uses
                 Androguard DAD with smali fallback. "jadx" produces higher
                 quality Java output but requires a one-time full APK
                 decompilation (use decompile_apk_full to pre-cache).

    Returns:
        {"status": "ok", "data": {"class_name": ..., "method_name": ...,
         "results": [{"descriptor": ..., "source": ..., "language": ...}]}}
    """
    try:
        session = get_session(session_id)

        if backend == "jadx":
            # JADX path: uses single-class decompilation where supported,
            # falls back to Androguard automatically if the method is not
            # found in the JADX output.
            return _decompile_method_jadx(session, class_name, method_name, descriptor)

        # --- Androguard backend (default) ---
        return _decompile_method_androguard(session, class_name, method_name, descriptor)

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
# Tool: decompile_class
# ---------------------------------------------------------------------------


@mcp.tool()
def decompile_class(session_id: str, class_name: str, backend: str = "androguard") -> dict:
    """Decompile an entire class to Java-like pseudocode.

    Each method is decompiled individually (using DAD where available,
    otherwise smali disassembly) and assembled into a class structure.

    Args:
        session_id: Active analysis session ID.
        class_name: The class to decompile (Java or Dalvik format).
        backend: Decompilation backend to use. "androguard" (default) uses
                 Androguard DAD with smali fallback. "jadx" produces higher
                 quality Java output but requires a one-time full APK
                 decompilation (use decompile_apk_full to pre-cache).

    Returns:
        {"status": "ok", "data": {"class_name": ..., "source": ...,
         "language": "java"|"smali"|"mixed", "method_count": N}}
    """
    try:
        session = get_session(session_id)

        if backend == "jadx":
            return _decompile_class_jadx(session, class_name)

        analysis = session.analysis
        dex_list = session.dex_list

        dalvik_class = _normalize_class_name(class_name)

        class_analysis = None
        for ca in analysis.find_classes(name=re.escape(dalvik_class)):
            class_analysis = ca
            break

        if class_analysis is None:
            return {
                "status": "error",
                "data": {
                    "message": f"Class '{class_name}' not found.",
                    "suggestion": "Use list_classes to find the correct class name.",
                },
            }

        if class_analysis.is_external():
            return {
                "status": "error",
                "data": {
                    "message": (
                        f"'{class_name}' is an external (SDK) class — "
                        "no bytecode to decompile."
                    ),
                    "suggestion": "Only classes defined in this APK can be decompiled.",
                },
            }

        java_name = _dalvik_to_java(class_analysis.name)

        # Gather class metadata for the header
        vm_class = class_analysis.get_vm_class()
        superclass = ""
        interfaces_str = ""
        access_flags = ""
        try:
            raw_super = vm_class.get_superclassname()
            if raw_super and raw_super != "Ljava/lang/Object;":
                superclass = f" extends {_dalvik_to_java(raw_super)}"
            raw_ifaces = vm_class.get_interfaces()
            if raw_ifaces:
                iface_names = ", ".join(_dalvik_to_java(i) for i in raw_ifaces)
                interfaces_str = f" implements {iface_names}"
            access_flags = vm_class.get_access_flags_string() or "public"
        except Exception:
            access_flags = "public"

        # Try full-class DAD decompilation first
        full_source = None
        try:
            from androguard.decompiler.decompiler import DecompilerDAD

            dec = DecompilerDAD(dex_list, analysis)
            full_source = dec.get_source_class(vm_class)
        except Exception:
            pass

        if full_source and full_source.strip():
            return {
                "status": "ok",
                "data": {
                    "class_name": java_name,
                    "source": full_source,
                    "language": "java",
                    "method_count": len(list(class_analysis.get_methods())),
                },
            }

        # Fallback: decompile each method individually and assemble
        method_blocks = []
        languages_used = set()

        for ma in class_analysis.get_methods():
            source, language = _decompile_single_method(dex_list, analysis, ma)
            languages_used.add(language)

            flags = ma.access or ""
            sig = f"{flags} {ma.name}{ma.descriptor}".strip()

            if language == "java":
                block = source
            else:
                # Wrap smali in a pseudo-method block for readability
                block = (
                    f"    // smali disassembly\n"
                    f"    {sig} {{\n"
                    f"{source}\n"
                    f"    }}"
                )
            method_blocks.append(block)

        # Decide overall language label
        if languages_used == {"java"}:
            lang_label = "java"
        elif languages_used == {"smali"}:
            lang_label = "smali"
        else:
            lang_label = "mixed"

        inner = "\n\n".join(method_blocks)
        assembled = (
            f"{access_flags} class {java_name}{superclass}{interfaces_str} {{\n\n"
            f"{inner}\n\n"
            f"}}"
        )

        return {
            "status": "ok",
            "data": {
                "class_name": java_name,
                "source": assembled,
                "language": lang_label,
                "method_count": len(method_blocks),
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
# Tool: decompile_apk_full
# ---------------------------------------------------------------------------


@mcp.tool()
def decompile_apk_full(session_id: str) -> dict:
    """Run JADX decompilation on the entire APK. Results are cached in the session workspace.

    This may take several minutes for large APKs. Subsequent decompile_method/decompile_class
    calls with backend='jadx' will be instant because they read from the cached output.

    Args:
        session_id: Active analysis session ID returned by load_apk.

    Returns:
        {"status": "ok", "data": {"output_dir": "...", "file_count": N}}
    """
    try:
        session = get_session(session_id)

        java_dir = session.workspace / "java"
        output_dir_str = str(java_dir)

        from apksaw.utils.jadx import decompile_apk

        _run_async(decompile_apk(str(session.apk_path), output_dir_str))

        # Count produced .java files
        java_dir_path = Path(output_dir_str)
        file_count = len(list(java_dir_path.rglob("*.java")))

        return {
            "status": "ok",
            "data": {
                "output_dir": output_dir_str,
                "file_count": file_count,
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
