"""Call graph visualization tools — Mermaid, DOT, and JSON export."""

import json
import re
from collections import deque
from pathlib import Path

from apksaw.server import mcp
from apksaw.session import get_session


# ---------------------------------------------------------------------------
# Security-sensitive API classification
# ---------------------------------------------------------------------------

SECURITY_SENSITIVE: dict[str, str] = {
    # Cryptography
    "Ljavax/crypto/Cipher;": "crypto",
    "Ljavax/crypto/SecretKey;": "crypto",
    "Ljavax/crypto/KeyGenerator;": "crypto",
    "Ljavax/crypto/Mac;": "crypto",
    "Ljava/security/MessageDigest;": "crypto",
    "Ljava/security/KeyStore;": "crypto",
    "Ljava/security/KeyPairGenerator;": "crypto",
    # Code execution
    "Ljava/lang/Runtime;": "exec",
    "Ljava/lang/ProcessBuilder;": "exec",
    "Ldalvik/system/DexClassLoader;": "exec",
    "Ldalvik/system/PathClassLoader;": "exec",
    "Ljava/lang/reflect/Method;": "reflection",
    # Web / network
    "Landroid/webkit/WebView;": "webview",
    "Landroid/webkit/WebViewClient;": "webview",
    "Ljava/net/HttpURLConnection;": "network",
    "Ljava/net/URL;": "network",
    "Lokhttp3/OkHttpClient;": "network",
    "Lretrofit2/Retrofit;": "network",
    # Storage
    "Landroid/database/sqlite/SQLiteDatabase;": "database",
    "Landroid/content/SharedPreferences;": "storage",
    "Ljava/io/FileOutputStream;": "storage",
    "Ljava/io/FileInputStream;": "storage",
    # Location / identifiers
    "Landroid/location/LocationManager;": "location",
    "Landroid/telephony/TelephonyManager;": "pii",
    "Landroid/accounts/AccountManager;": "pii",
    # IPC / broadcast
    "Landroid/content/ContentResolver;": "ipc",
    "Landroid/app/ActivityManager;": "ipc",
}

# Colour palette used across all output formats
_COLOR_SENSITIVE = "#ff6666"   # red — security-sensitive API
_COLOR_APP       = "#6699ff"   # blue — application code
_COLOR_THIRD     = "#cccccc"   # grey — Android framework / third-party

# Per-format node cap
_MAX_NODES_MERMAID = 60
_MAX_NODES_DOT     = 100
_MAX_NODES_JSON    = 200


# ---------------------------------------------------------------------------
# Internal helpers (deliberately not imported from xrefs to avoid coupling)
# ---------------------------------------------------------------------------

def _dalvik_to_java(name: str) -> str:
    """Convert a Dalvik descriptor to a dotted Java class name."""
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def _java_to_dalvik(name: str) -> str:
    """Convert a dotted Java class name to a Dalvik descriptor."""
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"


def _safe_class_name(class_analysis) -> str:
    """Extract a dotted Java class name from a ClassAnalysis object."""
    try:
        return _dalvik_to_java(class_analysis.name)
    except Exception:
        return "<unknown>"


def _safe_method_name(method_analysis) -> str:
    """Extract a plain method name from a MethodAnalysis object."""
    try:
        m = method_analysis.method
        return m.name if hasattr(m, "name") else str(method_analysis)
    except Exception:
        return "<unknown>"


def _node_id(class_name: str, method_name: str) -> str:
    """Build a stable string identifier for a call-graph node."""
    return f"{class_name}.{method_name}"


def _classify_node(node_class: str, package_name: str) -> tuple[str, str]:
    """Return (category, colour) for a node.

    Priority order:
    1. Security-sensitive API (red)
    2. App code matching the APK package name (blue)
    3. Everything else — framework / third-party (grey)
    """
    dalvik = _java_to_dalvik(node_class)
    for prefix, category in SECURITY_SENSITIVE.items():
        if dalvik.startswith(prefix.rstrip(";")):
            return category, _COLOR_SENSITIVE

    if package_name and node_class.startswith(package_name):
        return "app", _COLOR_APP

    return "framework", _COLOR_THIRD


def _build_graph(
    analysis,
    package_name: str,
    dalvik_class: str,
    method_name: str,
    depth: int,
    direction: str,
    max_nodes: int,
) -> tuple[dict, list[tuple[str, str]], bool]:
    """Run BFS from seed methods and return (nodes_dict, edges_list, truncated).

    nodes_dict maps node_id -> {id, class, method, category, color}
    edges_list is a list of (from_id, to_id) tuples.
    """
    nodes: dict[str, dict] = {}
    edges: list[tuple[str, str]] = []
    edge_set: set[tuple[str, str]] = set()

    def add_node(ma):
        """Register a MethodAnalysis as a node; return its id or None."""
        try:
            cls = _safe_class_name(ma.class_analysis)
            mth = _safe_method_name(ma)
        except Exception:
            return None
        nid = _node_id(cls, mth)
        if nid not in nodes:
            category, color = _classify_node(cls, package_name)
            nodes[nid] = {
                "id": nid,
                "class": cls,
                "method": mth,
                "category": category,
                "color": color,
            }
        return nid

    # Collect seed methods
    if method_name:
        seeds = list(analysis.find_methods(
            classname=re.escape(dalvik_class),
            methodname=re.escape(method_name),
        ))
    else:
        class_analyses = list(analysis.find_classes(dalvik_class))
        seeds = []
        for ca in class_analyses:
            seeds.extend(ca.get_methods())

    if not seeds:
        return nodes, [], False

    visited: set[int] = set()
    queue: deque[tuple] = deque()

    for seed in seeds:
        nid = add_node(seed)
        if nid and id(seed) not in visited:
            visited.add(id(seed))
            queue.append((seed, 0))

    while queue and len(nodes) < max_nodes:
        ma, cur_depth = queue.popleft()
        if cur_depth >= depth:
            continue

        src_id = add_node(ma)
        if src_id is None:
            continue

        if direction in ("callees", "both"):
            try:
                for _tgt_cls, tgt_ma, _offset in ma.get_xref_to():
                    if len(nodes) >= max_nodes:
                        break
                    try:
                        tgt_id = add_node(tgt_ma)
                        if tgt_id and (src_id, tgt_id) not in edge_set:
                            edge_set.add((src_id, tgt_id))
                            edges.append((src_id, tgt_id))
                        if tgt_id and id(tgt_ma) not in visited:
                            visited.add(id(tgt_ma))
                            queue.append((tgt_ma, cur_depth + 1))
                    except Exception:
                        continue
            except Exception:
                pass

        if direction in ("callers", "both"):
            try:
                for _src_cls, src_ma, _offset in ma.get_xref_from():
                    if len(nodes) >= max_nodes:
                        break
                    try:
                        caller_id = add_node(src_ma)
                        if caller_id and (caller_id, src_id) not in edge_set:
                            edge_set.add((caller_id, src_id))
                            edges.append((caller_id, src_id))
                        if caller_id and id(src_ma) not in visited:
                            visited.add(id(src_ma))
                            queue.append((src_ma, cur_depth + 1))
                    except Exception:
                        continue
            except Exception:
                pass

    truncated = len(nodes) >= max_nodes
    return nodes, edges, truncated


def _short_label(full_id: str, max_len: int = 45) -> str:
    """Shorten a ``Class.method`` label for display in diagrams."""
    parts = full_id.rsplit(".", 1)
    if len(parts) == 2:
        # Keep the simple class name (last dotted segment) + method
        simple_class = parts[0].rsplit(".", 1)[-1]
        label = f"{simple_class}.{parts[1]}"
    else:
        label = full_id
    if len(label) > max_len:
        label = label[: max_len - 1] + "…"
    return label


# ---------------------------------------------------------------------------
# Mermaid renderer
# ---------------------------------------------------------------------------

def _render_mermaid(nodes: dict, edges: list, truncated: bool) -> str:
    """Render nodes and edges as a Mermaid flowchart string."""
    # Assign stable short IDs so Mermaid doesn't choke on dots/semicolons
    id_map: dict[str, str] = {}
    for i, nid in enumerate(nodes):
        id_map[nid] = f"N{i}"

    lines = ["graph TD"]

    # Node declarations with labels and optional colour styling
    styled: list[str] = []
    for nid, node in nodes.items():
        mid = id_map[nid]
        label = _short_label(nid)
        # Escape double quotes inside labels
        label = label.replace('"', "'")
        lines.append(f'    {mid}["{label}"]')
        if node["color"] != _COLOR_THIRD:
            styled.append(f"    style {mid} fill:{node['color']}")

    # Edges
    for src_id, tgt_id in edges:
        if src_id in id_map and tgt_id in id_map:
            lines.append(f"    {id_map[src_id]} --> {id_map[tgt_id]}")

    # Style declarations come after edges in Mermaid
    lines.extend(styled)

    if truncated:
        lines.append(f"    %% Graph truncated at {_MAX_NODES_MERMAID} nodes")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# DOT renderer
# ---------------------------------------------------------------------------

def _sanitize_dot_id(s: str) -> str:
    """Wrap a string in double-quotes for use as a DOT identifier."""
    return '"' + s.replace('"', '\\"') + '"'


def _render_dot(nodes: dict, edges: list, graph_name: str) -> str:
    """Render nodes and edges as a DOT digraph string."""
    lines = [
        f"digraph {_sanitize_dot_id(graph_name)} {{",
        "    rankdir=LR;",
        '    node [shape=box, fontsize=10];',
    ]

    # Node declarations with colour fill
    for nid, node in nodes.items():
        label = _short_label(nid)
        dot_id = _sanitize_dot_id(label)
        color = node["color"]
        fill = color if color != _COLOR_THIRD else "#eeeeee"
        lines.append(
            f'    {dot_id} [label={_sanitize_dot_id(label)}, '
            f'style=filled, fillcolor="{fill}"];'
        )

    # Edge declarations
    for src_id, tgt_id in edges:
        if src_id in nodes and tgt_id in nodes:
            src_label = _sanitize_dot_id(_short_label(src_id))
            tgt_label = _sanitize_dot_id(_short_label(tgt_id))
            # Colour edges that touch a security-sensitive target
            tgt_node = nodes[tgt_id]
            edge_attr = (
                ' [color=red]'
                if tgt_node["color"] == _COLOR_SENSITIVE
                else ""
            )
            lines.append(f"    {src_label} -> {tgt_label}{edge_attr};")

    lines.append("}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public MCP tool
# ---------------------------------------------------------------------------

@mcp.tool()
def export_call_graph(
    session_id: str,
    class_name: str,
    method_name: str = "",
    format: str = "mermaid",
    depth: int = 2,
    direction: str = "both",
) -> dict:
    """Export a call graph centred on a class/method in the requested format.

    Performs a BFS traversal of cross-references up to *depth* levels from the
    seed class or method, then renders the result in one of three formats.

    Nodes are colour-coded by category:
    * Red  — security-sensitive APIs (crypto, exec, WebView, database …)
    * Blue — app code matching the APK's own package name
    * Grey — Android framework / third-party libraries

    Args:
        session_id:  Session ID returned by load_apk.
        class_name:  Starting class in Java (``com.example.Foo``) or
                     Dalvik (``Lcom/example/Foo;``) format.
        method_name: Optional specific method within the class.  When omitted
                     all methods of the class are used as BFS seeds.
        format:      Output format — ``"mermaid"``, ``"dot"``, or ``"json"``.
        depth:       BFS expansion depth (1–5, default 2).
        direction:   ``"callers"`` — who calls this; ``"callees"`` — what this
                     calls; ``"both"`` — both directions (default).

    Returns:
        For *mermaid*: ``{"status", "data": {"diagram", "node_count", …}}``
        For *dot*:     ``{"status", "data": {"dot_file", "content", …}}``
        For *json*:    ``{"status", "data": {"nodes", "edges", …}}``
    """
    if format not in ("mermaid", "dot", "json"):
        return {
            "status": "error",
            "message": f"Invalid format '{format}'. Must be 'mermaid', 'dot', or 'json'.",
            "suggestion": "Use 'mermaid' for inline diagrams, 'dot' for Graphviz, 'json' for programmatic use.",
        }

    if direction not in ("callers", "callees", "both"):
        return {
            "status": "error",
            "message": f"Invalid direction '{direction}'. Must be 'callers', 'callees', or 'both'.",
            "suggestion": "Use 'both' to see the full call neighbourhood.",
        }

    depth = max(1, min(depth, 5))
    max_nodes = {
        "mermaid": _MAX_NODES_MERMAID,
        "dot":     _MAX_NODES_DOT,
        "json":    _MAX_NODES_JSON,
    }[format]

    try:
        session = get_session(session_id)
        analysis = session.analysis
        package_name = session.package_name or ""

        dalvik_class = _java_to_dalvik(class_name)

        # Validate the target exists before running BFS
        if method_name:
            probe = list(analysis.find_methods(
                classname=re.escape(dalvik_class),
                methodname=re.escape(method_name),
            ))
            if not probe:
                return {
                    "status": "error",
                    "message": f"Method '{method_name}' not found in class '{class_name}'.",
                    "suggestion": "Check spelling; use find_classes to list available classes.",
                }
        else:
            probe = list(analysis.find_classes(dalvik_class))
            if not probe:
                return {
                    "status": "error",
                    "message": f"Class '{class_name}' not found in the APK.",
                    "suggestion": "Check the class name; use find_classes to enumerate classes.",
                }

        nodes, edges, truncated = _build_graph(
            analysis=analysis,
            package_name=package_name,
            dalvik_class=dalvik_class,
            method_name=method_name,
            depth=depth,
            direction=direction,
            max_nodes=max_nodes,
        )

        graph_name = (
            f"{_dalvik_to_java(dalvik_class)}.{method_name}"
            if method_name
            else _dalvik_to_java(dalvik_class)
        )
        base_meta = {
            "class_name": _dalvik_to_java(dalvik_class),
            "method_name": method_name or None,
            "direction": direction,
            "depth": depth,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "truncated": truncated,
            "truncation_limit": max_nodes if truncated else None,
        }

        # ---- Mermaid --------------------------------------------------------
        if format == "mermaid":
            diagram = _render_mermaid(nodes, edges, truncated)
            return {
                "status": "ok",
                "data": {
                    **base_meta,
                    "diagram": diagram,
                },
            }

        # ---- DOT ------------------------------------------------------------
        if format == "dot":
            dot_content = _render_dot(nodes, edges, graph_name)
            # Persist to workspace/graphs/<name>.dot
            graphs_dir: Path = session.workspace / "graphs"
            graphs_dir.mkdir(parents=True, exist_ok=True)
            safe_name = re.sub(r"[^\w.\-]", "_", graph_name)[:80]
            dot_file = graphs_dir / f"{safe_name}.dot"
            dot_file.write_text(dot_content, encoding="utf-8")
            return {
                "status": "ok",
                "data": {
                    **base_meta,
                    "dot_file": str(dot_file),
                    "content": dot_content,
                },
            }

        # ---- JSON -----------------------------------------------------------
        # format == "json"
        node_list = list(nodes.values())
        edge_list = [{"from": f, "to": t} for f, t in edges]
        return {
            "status": "ok",
            "data": {
                **base_meta,
                "nodes": node_list,
                "edges": edge_list,
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
            "message": f"Failed to export call graph: {exc}",
            "suggestion": "Try reducing depth or specifying a method_name.",
        }
