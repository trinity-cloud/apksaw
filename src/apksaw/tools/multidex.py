"""Multi-DEX analysis tools.

Provides tools for inspecting APKs that use multiple DEX files (multi-dex),
including cross-DEX reference analysis, isolated code detection, and dynamic
class loading discovery.
"""

import re
import traceback
from collections import defaultdict

from apksaw.server import mcp
from apksaw.session import get_session


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _dalvik_to_java(name: str) -> str:
    """Convert a Dalvik class descriptor to a Java-style class name.

    Examples:
        ``Lcom/example/Foo;`` -> ``com.example.Foo``
        ``com.example.Foo``   -> ``com.example.Foo``  (passthrough)
    """
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def _is_obfuscated_name(class_name: str) -> bool:
    """Heuristically decide whether a class name looks obfuscated.

    A name is considered obfuscated when the simple class name (last component
    after the final dot/slash) is one or two characters long, or consists
    entirely of lower-case single-letter segments (e.g. "a.b.c.d").
    """
    java_name = _dalvik_to_java(class_name)
    parts = java_name.split(".")
    simple = parts[-1] if parts else java_name
    if len(simple) <= 2:
        return True
    # All segments are tiny (e.g. "a.b.c")
    if all(len(p) <= 2 for p in parts):
        return True
    return False


def _build_class_to_dex_map(dex_list: list) -> dict[str, int]:
    """Return a mapping of Dalvik class name -> DEX index.

    Args:
        dex_list: List of DalvikVMFormat objects from Androguard.

    Returns:
        Dict mapping each class's Dalvik descriptor to its DEX file index.
    """
    class_to_dex: dict[str, int] = {}
    for idx, dvm in enumerate(dex_list):
        try:
            for cls in dvm.get_classes():
                class_to_dex[cls.get_name()] = idx
        except Exception:
            continue
    return class_to_dex


# Sensitive API patterns that warrant attention when found in secondary DEX
# files with no incoming cross-DEX references.
_SENSITIVE_API_PATTERNS = [
    # Crypto
    r"Ljavax/crypto/",
    r"Ljava/security/",
    # Reflection
    r"Ljava/lang/reflect/",
    r"Ljava/lang/Class;->forName",
    r"Ljava/lang/ClassLoader;",
    # Process execution
    r"Ljava/lang/Runtime;->exec",
    r"Ljava/lang/ProcessBuilder;",
    # Dynamic class loading
    r"Ldalvik/system/DexClassLoader;",
    r"Ldalvik/system/PathClassLoader;",
    r"Ldalvik/system/InMemoryDexClassLoader;",
    r"Ldalvik/system/BaseDexClassLoader;",
]

_SENSITIVE_COMPILED = [re.compile(p) for p in _SENSITIVE_API_PATTERNS]

_DYNAMIC_LOADER_CLASSES = [
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/PathClassLoader;",
    "Ldalvik/system/InMemoryDexClassLoader;",
    "Ldalvik/system/BaseDexClassLoader;",
]


def _uses_sensitive_api(method_analysis) -> bool:
    """Return True if the method calls any sensitive API."""
    try:
        for _tgt_cls, _tgt_mth, _offset in method_analysis.get_xref_to():
            try:
                cls_name = _tgt_cls.name if hasattr(_tgt_cls, "name") else ""
                mth_name = ""
                try:
                    mth_name = _tgt_mth.method.name
                except Exception:
                    pass
                sig = f"{cls_name}->{mth_name}"
                for pattern in _SENSITIVE_COMPILED:
                    if pattern.search(sig) or pattern.search(cls_name):
                        return True
            except Exception:
                continue
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Tool: list_dex_files
# ---------------------------------------------------------------------------


@mcp.tool()
def list_dex_files(session_id: str) -> dict:
    """List all DEX files in the APK with class counts, method counts, and sizes.

    Iterates over every ``*.dex`` entry in the APK's raw file listing and
    correlates each one with the parsed DalvikVMFormat object loaded by
    Androguard.  Returns per-file statistics (class count, method count, size)
    plus APK-wide totals.

    Args:
        session_id: Active analysis session ID returned by load_apk.

    Returns:
        A dict with status and data containing:
        - ``dex_files``: list of per-DEX stats (name, index, classes, methods, size_kb)
        - ``total_classes``: sum of all class counts across DEX files
        - ``total_methods``: sum of all method counts across DEX files
        - ``total_dex_files``: number of DEX files found
    """
    try:
        session = get_session(session_id)
        apk = session.apk
        dex_list = session.dex_list

        # Collect raw DEX file names and sizes from the APK zip
        dex_entries: list[tuple[str, int]] = []
        try:
            for filename in apk.get_files():
                if re.match(r"^classes\d*\.dex$", filename):
                    try:
                        raw = apk.get_file(filename)
                        size_bytes = len(raw) if raw else 0
                    except Exception:
                        size_bytes = 0
                    dex_entries.append((filename, size_bytes))
        except Exception:
            pass

        # Sort canonically: classes.dex first, then classes2.dex, classes3.dex ...
        def _dex_sort_key(item: tuple[str, int]) -> int:
            name = item[0]
            m = re.match(r"^classes(\d*)\.dex$", name)
            if m:
                return int(m.group(1)) if m.group(1) else 0
            return 999

        dex_entries.sort(key=_dex_sort_key)

        # If APK file listing gave nothing (some Androguard versions differ),
        # synthesise entries from the parsed dex_list length.
        if not dex_entries and dex_list:
            for i in range(len(dex_list)):
                name = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
                dex_entries.append((name, 0))

        dex_files_out = []
        total_classes = 0
        total_methods = 0

        for idx, (dex_name, size_bytes) in enumerate(dex_entries):
            class_count = 0
            method_count = 0

            if idx < len(dex_list):
                dvm = dex_list[idx]
                try:
                    classes = list(dvm.get_classes())
                    class_count = len(classes)
                    for cls in classes:
                        try:
                            method_count += len(list(cls.get_methods()))
                        except Exception:
                            pass
                except Exception:
                    pass

            size_kb = round(size_bytes / 1024, 1)

            dex_files_out.append(
                {
                    "name": dex_name,
                    "index": idx,
                    "classes": class_count,
                    "methods": method_count,
                    "size_kb": size_kb,
                }
            )
            total_classes += class_count
            total_methods += method_count

        return {
            "status": "ok",
            "data": {
                "dex_files": dex_files_out,
                "total_classes": total_classes,
                "total_methods": total_methods,
                "total_dex_files": len(dex_files_out),
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
# Tool: analyze_dex_boundaries
# ---------------------------------------------------------------------------


@mcp.tool()
def analyze_dex_boundaries(session_id: str) -> dict:
    """Analyze cross-DEX references and detect suspicious patterns.

    Builds a full map of which class lives in which DEX, then walks every
    method's outgoing xrefs to count calls that cross DEX boundaries.

    Suspicious patterns detected:
    - **isolated_secondary_dex**: a secondary DEX with zero incoming cross-DEX
      calls, suggesting dynamically loaded or unreachable code.
    - **obfuscated_secondary_dex**: a secondary DEX where the majority of class
      names look obfuscated while the primary DEX uses readable names.
    - **sensitive_api_isolated**: classes in an isolated secondary DEX that
      invoke crypto, reflection, exec, or dynamic loading APIs.

    Also locates dynamic class loading sites (``DexClassLoader``,
    ``PathClassLoader``, ``InMemoryDexClassLoader``) and reports the calling
    context.

    Handles single-DEX APKs gracefully — cross-DEX fields will be empty but
    dynamic loading and other data is still reported.

    Args:
        session_id: Active analysis session ID returned by load_apk.

    Returns:
        A dict with status and data containing:
        - ``cross_dex_calls``: dict keyed ``"src_to_dst"`` with call counts
        - ``suspicious_patterns``: list of detected anomalies with severity
        - ``dynamic_loading``: list of dynamic class loader usage sites
    """
    try:
        session = get_session(session_id)
        dex_list = session.dex_list
        analysis = session.analysis

        num_dex = len(dex_list)

        # ------------------------------------------------------------------ #
        # Step 1: Build class_name -> dex_index map                           #
        # ------------------------------------------------------------------ #
        class_to_dex = _build_class_to_dex_map(dex_list)

        # ------------------------------------------------------------------ #
        # Step 2: Count cross-DEX calls                                        #
        # cross_dex_counts[(src_idx, dst_idx)] = call_count                   #
        # ------------------------------------------------------------------ #
        cross_dex_counts: dict[tuple[int, int], int] = defaultdict(int)
        # Track which secondary DEX indices receive at least one incoming call
        incoming_counts: dict[int, int] = defaultdict(int)

        for ma in analysis.get_methods():
            if ma.is_external():
                continue

            # Determine source DEX
            try:
                src_class_name = ma.class_analysis.name
            except Exception:
                continue
            src_dex = class_to_dex.get(src_class_name, -1)
            if src_dex < 0:
                continue

            try:
                for tgt_class_a, _tgt_method_a, _offset in ma.get_xref_to():
                    try:
                        tgt_class_name = tgt_class_a.name
                        dst_dex = class_to_dex.get(tgt_class_name, -1)
                        if dst_dex >= 0 and dst_dex != src_dex:
                            cross_dex_counts[(src_dex, dst_dex)] += 1
                            incoming_counts[dst_dex] += 1
                    except Exception:
                        continue
            except Exception:
                continue

        # Format cross_dex_calls as {"0_to_1": N, ...}
        cross_dex_calls: dict[str, int] = {}
        for (src, dst), count in sorted(cross_dex_counts.items()):
            cross_dex_calls[f"{src}_to_{dst}"] = count

        # ------------------------------------------------------------------ #
        # Step 3: Detect suspicious patterns                                   #
        # ------------------------------------------------------------------ #
        suspicious_patterns: list[dict] = []

        # Collect DEX file names for reporting
        dex_names: dict[int, str] = {}
        for i in range(num_dex):
            dex_names[i] = "classes.dex" if i == 0 else f"classes{i + 1}.dex"

        if num_dex > 1:
            # 3a. Obfuscation ratio in primary vs secondary DEX
            def _obfuscation_ratio(dex_idx: int) -> float:
                dvm = dex_list[dex_idx]
                try:
                    classes = list(dvm.get_classes())
                except Exception:
                    return 0.0
                if not classes:
                    return 0.0
                obf = sum(1 for c in classes if _is_obfuscated_name(c.get_name()))
                return obf / len(classes)

            primary_ratio = _obfuscation_ratio(0)

            for i in range(1, num_dex):
                # 3b. Isolated secondary DEX (no incoming cross-DEX calls)
                incoming = incoming_counts.get(i, 0)
                if incoming == 0:
                    suspicious_patterns.append(
                        {
                            "type": "isolated_secondary_dex",
                            "dex_index": i,
                            "detail": (
                                f"{dex_names[i]} has 0 incoming cross-DEX calls "
                                "— may contain dynamically loaded or dead code"
                            ),
                            "severity": "medium",
                        }
                    )

                # 3c. Secondary DEX more obfuscated than primary
                sec_ratio = _obfuscation_ratio(i)
                if sec_ratio > 0.7 and primary_ratio < 0.3:
                    suspicious_patterns.append(
                        {
                            "type": "obfuscated_secondary_dex",
                            "dex_index": i,
                            "detail": (
                                f"{dex_names[i]} obfuscation ratio {sec_ratio:.0%} "
                                f"vs primary {primary_ratio:.0%} — secondary DEX "
                                "may hide sensitive logic behind obfuscated names"
                            ),
                            "severity": "low",
                        }
                    )

                # 3d. Isolated secondary DEX classes that use sensitive APIs
                if incoming_counts.get(i, 0) == 0:
                    dvm = dex_list[i]
                    sensitive_classes: list[str] = []
                    try:
                        for cls in dvm.get_classes():
                            cls_name = cls.get_name()
                            # Look up the ClassAnalysis for xref data
                            try:
                                for ca in analysis.find_classes(
                                    name=re.escape(cls_name)
                                ):
                                    for mth_a in ca.get_methods():
                                        if _uses_sensitive_api(mth_a):
                                            sensitive_classes.append(
                                                _dalvik_to_java(cls_name)
                                            )
                                            break  # one hit per class is enough
                                    break
                            except Exception:
                                continue
                    except Exception:
                        pass

                    if sensitive_classes:
                        suspicious_patterns.append(
                            {
                                "type": "sensitive_api_isolated",
                                "dex_index": i,
                                "detail": (
                                    f"{dex_names[i]} is isolated (0 incoming cross-DEX "
                                    f"calls) but contains classes using sensitive APIs: "
                                    + ", ".join(sensitive_classes[:5])
                                    + ("..." if len(sensitive_classes) > 5 else "")
                                ),
                                "severity": "high",
                                "classes": sensitive_classes[:20],
                            }
                        )

        # ------------------------------------------------------------------ #
        # Step 4: Detect dynamic DEX loading                                  #
        # ------------------------------------------------------------------ #
        dynamic_loading: list[dict] = []
        seen_loaders: set[tuple] = set()

        for loader_dalvik in _DYNAMIC_LOADER_CLASSES:
            loader_java = _dalvik_to_java(loader_dalvik)
            try:
                for ca in analysis.find_classes(name=re.escape(loader_dalvik)):
                    for mth_a in ca.get_methods():
                        # Find callers of <init> and loadClass
                        if mth_a.name not in ("<init>", "loadClass", "load"):
                            continue
                        try:
                            for src_cls_a, src_mth_a, _offset in mth_a.get_xref_from():
                                try:
                                    src_cls = _dalvik_to_java(src_cls_a.name)
                                    try:
                                        src_mth = src_mth_a.method.name
                                    except Exception:
                                        src_mth = str(src_mth_a)

                                    key = (loader_java, src_cls, src_mth)
                                    if key in seen_loaders:
                                        continue
                                    seen_loaders.add(key)

                                    # Attempt to determine where the DEX path comes
                                    # from by inspecting the caller's xrefs for
                                    # string constants or parameter passing patterns.
                                    dex_path_source = "unknown"
                                    try:
                                        if not src_mth_a.is_external():
                                            em = src_mth_a.get_method()
                                            code = em.get_code()
                                            if code:
                                                instrs = list(
                                                    code.get_bc().get_instructions()
                                                )
                                                for instr in instrs:
                                                    op = instr.get_name().lower()
                                                    out = instr.get_output()
                                                    # String constant loaded before
                                                    # the loader constructor
                                                    if op in (
                                                        "const-string",
                                                        "const-string/jumbo",
                                                    ):
                                                        if any(
                                                            kw in out.lower()
                                                            for kw in (
                                                                ".dex",
                                                                ".jar",
                                                                ".apk",
                                                                "dex",
                                                            )
                                                        ):
                                                            dex_path_source = (
                                                                "hardcoded_string"
                                                            )
                                                            break
                                                else:
                                                    # No dex-related string constant —
                                                    # path likely comes from a parameter
                                                    # or field.
                                                    dex_path_source = "parameter"
                                    except Exception:
                                        dex_path_source = "parameter"

                                    dynamic_loading.append(
                                        {
                                            "loader_class": loader_java,
                                            "loader_method": mth_a.name,
                                            "caller_class": src_cls,
                                            "caller_method": src_mth,
                                            "dex_path_source": dex_path_source,
                                        }
                                    )
                                except Exception:
                                    continue
                        except Exception:
                            pass
            except Exception:
                continue

        return {
            "status": "ok",
            "data": {
                "total_dex_files": num_dex,
                "cross_dex_calls": cross_dex_calls,
                "suspicious_patterns": suspicious_patterns,
                "dynamic_loading": dynamic_loading,
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
# Tool: get_dex_class_map
# ---------------------------------------------------------------------------


@mcp.tool()
def get_dex_class_map(session_id: str, dex_index: int = -1) -> dict:
    """Show which classes are in which DEX file.

    When *dex_index* is -1 (the default) the full map for every DEX file is
    returned.  When a specific index is provided only that DEX file's classes
    are listed.  Handles single-DEX APKs gracefully.

    Args:
        session_id: Active analysis session ID returned by load_apk.
        dex_index:  Zero-based DEX file index.  -1 returns all DEX files.

    Returns:
        A dict with status and data containing:
        - ``dex_map``: list of per-DEX objects, each with ``dex_index``,
          ``dex_name``, ``class_count``, and ``classes`` (list of Java names).
        - ``total_classes``: total class count across reported DEX files.
    """
    try:
        session = get_session(session_id)
        dex_list = session.dex_list
        num_dex = len(dex_list)

        if dex_index != -1 and not (0 <= dex_index < num_dex):
            return {
                "status": "error",
                "data": {
                    "message": (
                        f"dex_index {dex_index} is out of range. "
                        f"This APK has {num_dex} DEX file(s) (indices 0–{num_dex - 1})."
                    ),
                    "suggestion": (
                        "Call list_dex_files first to see available DEX indices."
                    ),
                },
            }

        indices_to_report = (
            [dex_index] if dex_index != -1 else list(range(num_dex))
        )

        dex_map: list[dict] = []
        total_classes = 0

        for idx in indices_to_report:
            dex_name = "classes.dex" if idx == 0 else f"classes{idx + 1}.dex"
            dvm = dex_list[idx]

            classes: list[str] = []
            try:
                for cls in dvm.get_classes():
                    try:
                        java_name = _dalvik_to_java(cls.get_name())
                        classes.append(java_name)
                    except Exception:
                        continue
            except Exception:
                pass

            classes.sort()
            total_classes += len(classes)

            dex_map.append(
                {
                    "dex_index": idx,
                    "dex_name": dex_name,
                    "class_count": len(classes),
                    "classes": classes,
                }
            )

        return {
            "status": "ok",
            "data": {
                "dex_map": dex_map,
                "total_classes": total_classes,
                "single_dex": num_dex == 1,
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
