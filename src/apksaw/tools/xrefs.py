"""Cross-reference and call graph analysis tools."""

import re
from collections import deque

from apksaw.server import mcp
from apksaw.session import get_session


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _dalvik_to_java(name: str) -> str:
    """Convert a Dalvik type descriptor to a Java class name.

    Examples:
        ``Lcom/example/Foo;`` -> ``com.example.Foo``
        ``com.example.Foo``   -> ``com.example.Foo``  (already Java)
    """
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def _java_to_dalvik(name: str) -> str:
    """Convert a Java class name to a Dalvik type descriptor.

    Examples:
        ``com.example.Foo``   -> ``Lcom/example/Foo;``
        ``Lcom/example/Foo;`` -> ``Lcom/example/Foo;``  (already Dalvik)
    """
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"


def _method_id(class_name: str, method_name: str) -> str:
    """Build a stable node identifier string from class and method names."""
    return f"{class_name}.{method_name}"


def _safe_class_name(class_analysis) -> str:
    """Extract the Java class name from a ClassAnalysis object safely."""
    try:
        return _dalvik_to_java(class_analysis.name)
    except Exception:
        return "<unknown_class>"


def _safe_method_name(method_analysis) -> str:
    """Extract the method name from a MethodAnalysis object safely."""
    try:
        m = method_analysis.method
        return m.name if hasattr(m, "name") else str(method_analysis)
    except Exception:
        return "<unknown_method>"


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

@mcp.tool()
def get_xrefs_to(
    session_id: str,
    class_name: str,
    method_name: str = "",
) -> dict:
    """Get outgoing cross-references — what does this class/method call or reference?

    When *method_name* is provided the tool returns every method that the
    specified method directly calls.  When only *class_name* is provided the
    tool aggregates outgoing references (method calls + field reads/writes)
    for the entire class.

    Args:
        session_id:  Session ID returned by load_apk.
        class_name:  Target class in either Java (``com.example.Foo``) or
                     Dalvik (``Lcom/example/Foo;``) format.
        method_name: Optional method name within the class.

    Returns:
        A dict with status and a ``xrefs`` list of
        ``{"target_class", "target_method", "type"}`` entries.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        dalvik_class = _java_to_dalvik(class_name)
        results: list[dict] = []

        if method_name:
            # -- method-level xref_to --
            methods = list(analysis.find_methods(
                classname=re.escape(dalvik_class),
                methodname=re.escape(method_name),
            ))
            if not methods:
                return {
                    "status": "error",
                    "message": (
                        f"Method '{method_name}' not found in class '{class_name}'."
                    ),
                    "suggestion": (
                        "Check spelling; use find_classes to list available classes."
                    ),
                }

            for ma in methods:
                try:
                    for tgt_class_a, tgt_method_a, _offset in ma.get_xref_to():
                        try:
                            results.append({
                                "target_class": _safe_class_name(tgt_class_a),
                                "target_method": _safe_method_name(tgt_method_a),
                                "type": "call",
                            })
                        except Exception:
                            continue
                except Exception:
                    pass
        else:
            # -- class-level outgoing references --
            class_analyses = list(analysis.find_classes(dalvik_class))
            if not class_analyses:
                return {
                    "status": "error",
                    "message": f"Class '{class_name}' not found in the APK.",
                    "suggestion": (
                        "Check the class name; use find_classes to enumerate classes."
                    ),
                }

            for ca in class_analyses:
                # Method calls via get_xref_to on each method
                for ma in ca.get_methods():
                    try:
                        for tgt_class_a, tgt_method_a, _offset in ma.get_xref_to():
                            try:
                                results.append({
                                    "target_class": _safe_class_name(tgt_class_a),
                                    "target_method": _safe_method_name(tgt_method_a),
                                    "type": "call",
                                })
                            except Exception:
                                continue
                    except Exception:
                        continue

                # Field references via ClassAnalysis.get_xref_to
                try:
                    for _ref_kind, tgt_class_a, tgt_method_a in ca.get_xref_to():
                        try:
                            results.append({
                                "target_class": _safe_class_name(tgt_class_a),
                                "target_method": _safe_method_name(tgt_method_a),
                                "type": "field_read",
                            })
                        except Exception:
                            continue
                except Exception:
                    pass

        # Deduplicate while preserving order
        seen: set[tuple] = set()
        deduped: list[dict] = []
        for entry in results:
            key = (entry["target_class"], entry["target_method"], entry["type"])
            if key not in seen:
                seen.add(key)
                deduped.append(entry)

        return {
            "status": "ok",
            "data": {
                "class_name": _dalvik_to_java(dalvik_class),
                "method_name": method_name or None,
                "xrefs": deduped,
                "count": len(deduped),
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
            "message": f"Failed to retrieve outgoing xrefs: {exc}",
            "suggestion": "Verify that the class/method name is correct.",
        }


@mcp.tool()
def get_xrefs_from(
    session_id: str,
    class_name: str,
    method_name: str = "",
) -> dict:
    """Get incoming cross-references — who calls this class/method?

    When *method_name* is provided the tool returns all callers of that
    specific method.  When only *class_name* is provided the tool returns
    all callers of any method in the class.

    Args:
        session_id:  Session ID returned by load_apk.
        class_name:  Target class in either Java or Dalvik format.
        method_name: Optional method name within the class.

    Returns:
        A dict with status and a ``xrefs`` list of
        ``{"source_class", "source_method", "type"}`` entries.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        dalvik_class = _java_to_dalvik(class_name)
        results: list[dict] = []

        if method_name:
            # -- method-level xref_from --
            methods = list(analysis.find_methods(
                classname=re.escape(dalvik_class),
                methodname=re.escape(method_name),
            ))
            if not methods:
                return {
                    "status": "error",
                    "message": (
                        f"Method '{method_name}' not found in class '{class_name}'."
                    ),
                    "suggestion": (
                        "Check spelling; use find_classes to list available classes."
                    ),
                }

            for ma in methods:
                try:
                    for src_class_a, src_method_a, _offset in ma.get_xref_from():
                        try:
                            results.append({
                                "source_class": _safe_class_name(src_class_a),
                                "source_method": _safe_method_name(src_method_a),
                                "type": "call",
                            })
                        except Exception:
                            continue
                except Exception:
                    pass
        else:
            # -- class-level incoming references --
            class_analyses = list(analysis.find_classes(dalvik_class))
            if not class_analyses:
                return {
                    "status": "error",
                    "message": f"Class '{class_name}' not found in the APK.",
                    "suggestion": (
                        "Check the class name; use find_classes to enumerate classes."
                    ),
                }

            for ca in class_analyses:
                # Method-level callers
                for ma in ca.get_methods():
                    try:
                        for src_class_a, src_method_a, _offset in ma.get_xref_from():
                            try:
                                results.append({
                                    "source_class": _safe_class_name(src_class_a),
                                    "source_method": _safe_method_name(src_method_a),
                                    "type": "call",
                                })
                            except Exception:
                                continue
                    except Exception:
                        continue

                # Class-level callers (references from other classes)
                try:
                    for _ref_kind, src_class_a, src_method_a in ca.get_xref_from():
                        try:
                            results.append({
                                "source_class": _safe_class_name(src_class_a),
                                "source_method": _safe_method_name(src_method_a),
                                "type": "field_write",
                            })
                        except Exception:
                            continue
                except Exception:
                    pass

        # Deduplicate while preserving order
        seen: set[tuple] = set()
        deduped: list[dict] = []
        for entry in results:
            key = (entry["source_class"], entry["source_method"], entry["type"])
            if key not in seen:
                seen.add(key)
                deduped.append(entry)

        return {
            "status": "ok",
            "data": {
                "class_name": _dalvik_to_java(dalvik_class),
                "method_name": method_name or None,
                "xrefs": deduped,
                "count": len(deduped),
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
            "message": f"Failed to retrieve incoming xrefs: {exc}",
            "suggestion": "Verify that the class/method name is correct.",
        }


@mcp.tool()
def get_call_graph(
    session_id: str,
    class_name: str,
    method_name: str = "",
    depth: int = 2,
    direction: str = "both",
) -> dict:
    """Build a call graph centred on a class or method via BFS traversal.

    Args:
        session_id:  Session ID returned by load_apk.
        class_name:  Starting class in Java or Dalvik format.
        method_name: Optional specific method within the class.  When omitted,
                     all methods in the class are used as starting points.
        depth:       How many BFS levels to expand (default 2, max 5).
        direction:   ``"callers"`` — who calls this; ``"callees"`` — what this
                     calls; ``"both"`` — both directions.

    Returns:
        A dict with ``nodes`` (id, class, method) and ``edges`` (from, to).
    """
    MAX_DEPTH = 5
    MAX_NODES = 200

    if direction not in ("callers", "callees", "both"):
        return {
            "status": "error",
            "message": (
                f"Invalid direction '{direction}'. "
                "Must be 'callers', 'callees', or 'both'."
            ),
            "suggestion": "Use 'both' to see the full neighbourhood.",
        }

    depth = max(1, min(depth, MAX_DEPTH))

    try:
        session = get_session(session_id)
        analysis = session.analysis

        dalvik_class = _java_to_dalvik(class_name)

        # Collect seed MethodAnalysis objects
        if method_name:
            seeds = list(analysis.find_methods(
                classname=re.escape(dalvik_class),
                methodname=re.escape(method_name),
            ))
            if not seeds:
                return {
                    "status": "error",
                    "message": (
                        f"Method '{method_name}' not found in class '{class_name}'."
                    ),
                    "suggestion": (
                        "Check spelling; use find_classes to list available classes."
                    ),
                }
        else:
            class_analyses = list(analysis.find_classes(dalvik_class))
            if not class_analyses:
                return {
                    "status": "error",
                    "message": f"Class '{class_name}' not found in the APK.",
                    "suggestion": (
                        "Check the class name; use find_classes to enumerate classes."
                    ),
                }
            seeds = []
            for ca in class_analyses:
                seeds.extend(ca.get_methods())

        # Nodes: {node_id -> {"id", "class", "method"}}
        nodes: dict[str, dict] = {}
        # Edges: set of (from_id, to_id)
        edges: set[tuple[str, str]] = set()

        def _add_node(ma) -> str | None:
            try:
                cls_name = _safe_class_name(ma.class_analysis)
                mth_name = _safe_method_name(ma)
            except Exception:
                return None
            nid = _method_id(cls_name, mth_name)
            if nid not in nodes:
                nodes[nid] = {"id": nid, "class": cls_name, "method": mth_name}
            return nid

        # BFS
        # Queue items: (method_analysis, current_depth)
        visited: set[int] = set()  # object ids to avoid reprocessing
        queue: deque[tuple] = deque()

        for seed in seeds:
            nid = _add_node(seed)
            if nid and id(seed) not in visited:
                visited.add(id(seed))
                queue.append((seed, 0))

        while queue and len(nodes) < MAX_NODES:
            ma, cur_depth = queue.popleft()
            if cur_depth >= depth:
                continue

            src_id = _add_node(ma)
            if src_id is None:
                continue

            # Expand callees (xref_to)
            if direction in ("callees", "both"):
                try:
                    for tgt_class_a, tgt_method_a, _offset in ma.get_xref_to():
                        if len(nodes) >= MAX_NODES:
                            break
                        try:
                            tgt_id = _add_node(tgt_method_a)
                            if tgt_id:
                                edges.add((src_id, tgt_id))
                                if id(tgt_method_a) not in visited:
                                    visited.add(id(tgt_method_a))
                                    queue.append((tgt_method_a, cur_depth + 1))
                        except Exception:
                            continue
                except Exception:
                    pass

            # Expand callers (xref_from)
            if direction in ("callers", "both"):
                try:
                    for src_class_a, src_method_a, _offset in ma.get_xref_from():
                        if len(nodes) >= MAX_NODES:
                            break
                        try:
                            caller_id = _add_node(src_method_a)
                            if caller_id:
                                edges.add((caller_id, src_id))
                                if id(src_method_a) not in visited:
                                    visited.add(id(src_method_a))
                                    queue.append((src_method_a, cur_depth + 1))
                        except Exception:
                            continue
                except Exception:
                    pass

        edge_list = [{"from": f, "to": t} for f, t in edges]

        return {
            "status": "ok",
            "data": {
                "class_name": _dalvik_to_java(dalvik_class),
                "method_name": method_name or None,
                "direction": direction,
                "depth": depth,
                "truncated": len(nodes) >= MAX_NODES,
                "nodes": list(nodes.values()),
                "edges": edge_list,
                "node_count": len(nodes),
                "edge_count": len(edge_list),
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
            "message": f"Failed to build call graph: {exc}",
            "suggestion": "Try reducing depth or specifying a method_name.",
        }


@mcp.tool()
def find_method_usage(
    session_id: str,
    target_class: str,
    target_method: str,
) -> dict:
    """Find all places in the APK that call a specific method.

    Useful for locating API usage such as ``Runtime.exec``,
    ``DexClassLoader.<init>``, ``Cipher.getInstance``, etc.

    Args:
        session_id:    Session ID returned by load_apk.
        target_class:  Class that owns the method (Java or Dalvik format).
        target_method: Method name to search for.

    Returns:
        A dict with a ``callers`` list of ``{"class", "method"}`` entries
        and the total call count.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        dalvik_class = _java_to_dalvik(target_class)

        methods = list(analysis.find_methods(
            classname=re.escape(dalvik_class),
            methodname=re.escape(target_method),
        ))

        if not methods:
            return {
                "status": "ok",
                "data": {
                    "target_class": _dalvik_to_java(dalvik_class),
                    "target_method": target_method,
                    "callers": [],
                    "count": 0,
                },
            }

        callers: list[dict] = []
        seen: set[tuple] = set()

        for ma in methods:
            try:
                for src_class_a, src_method_a, _offset in ma.get_xref_from():
                    try:
                        src_cls = _safe_class_name(src_class_a)
                        src_mth = _safe_method_name(src_method_a)
                        key = (src_cls, src_mth)
                        if key not in seen:
                            seen.add(key)
                            callers.append({"class": src_cls, "method": src_mth})
                    except Exception:
                        continue
            except Exception:
                pass

        return {
            "status": "ok",
            "data": {
                "target_class": _dalvik_to_java(dalvik_class),
                "target_method": target_method,
                "callers": callers,
                "count": len(callers),
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
            "message": f"Failed to find method usage: {exc}",
            "suggestion": (
                "Verify the class and method names. "
                "You can pass partial Dalvik descriptors like "
                "'Ljava/lang/Runtime;' as target_class."
            ),
        }


@mcp.tool()
def find_api_calls(session_id: str, api_pattern: str) -> dict:
    """Find calls to Android/Java API methods matching a regex pattern.

    The pattern is matched against the full method signature expressed as
    ``Lclass/path;->method_name``.  For example:

    * ``"Ljavax/crypto/Cipher;->getInstance"``
    * ``"Ljava/lang/Runtime;->exec"``
    * ``"Ljava/lang/reflect"``  — match any reflection call

    Args:
        session_id:  Session ID returned by load_apk.
        api_pattern: Regex pattern applied to ``Lclass/path;->method_name``.

    Returns:
        A dict with ``api_calls`` — a list of
        ``{"api", "callers": [{"class", "method"}]}`` entries.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        try:
            pattern = re.compile(api_pattern)
        except re.error as exc:
            return {
                "status": "error",
                "message": f"Invalid regex pattern: {exc}",
                "suggestion": (
                    "Provide a valid Python regex. "
                    "Example: 'Ljava/lang/Runtime;->exec'"
                ),
            }

        api_calls: list[dict] = []

        # Iterate over all MethodAnalysis objects in the APK
        for ma in analysis.get_methods():
            try:
                m = ma.method
                cls_descriptor = m.class_name if hasattr(m, "class_name") else ""
                mth_name = m.name if hasattr(m, "name") else ""
                signature = f"{cls_descriptor}->{mth_name}"

                if not pattern.search(signature):
                    continue

                # Collect callers
                callers: list[dict] = []
                seen: set[tuple] = set()
                try:
                    for src_class_a, src_method_a, _offset in ma.get_xref_from():
                        try:
                            src_cls = _safe_class_name(src_class_a)
                            src_mth = _safe_method_name(src_method_a)
                            key = (src_cls, src_mth)
                            if key not in seen:
                                seen.add(key)
                                callers.append({"class": src_cls, "method": src_mth})
                        except Exception:
                            continue
                except Exception:
                    pass

                if callers:
                    api_calls.append({
                        "api": signature,
                        "callers": callers,
                    })
            except Exception:
                continue

        return {
            "status": "ok",
            "data": {
                "pattern": api_pattern,
                "api_calls": api_calls,
                "api_count": len(api_calls),
                "total_callers": sum(len(a["callers"]) for a in api_calls),
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
            "message": f"Failed to search API calls: {exc}",
            "suggestion": (
                "Ensure the APK was loaded successfully and the pattern is valid."
            ),
        }
