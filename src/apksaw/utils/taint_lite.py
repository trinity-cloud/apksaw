"""Lightweight taint analysis helpers for DroidScope security scanners.

These utilities operate on Androguard's analysis objects without requiring a
full data-flow framework.  They cover the most common false-positive reduction
needs: tracing constant strings to call-sites, checking whether a method body
is trivially empty, and determining reachability from exported components.

All functions are intentionally defensive — they return safe default values
(None / False / 'unknown') when they cannot resolve the information rather
than raising exceptions, so callers in the security scanners can use them
without try/except wrappers.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass  # Androguard types are imported lazily at call-time

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------- #
# Entry-point method names per component type
# ----------------------------------------------------------------------- #

_ACTIVITY_ENTRY_POINTS = frozenset({
    "onCreate",
    "onStart",
    "onResume",
    "onNewIntent",
    "onActivityResult",
    "onRestoreInstanceState",
})

_RECEIVER_ENTRY_POINTS = frozenset({"onReceive"})

_SERVICE_ENTRY_POINTS = frozenset({
    "onBind",
    "onStartCommand",
    "onHandleIntent",
    "onTaskRemoved",
})

_PROVIDER_ENTRY_POINTS = frozenset({
    "query",
    "insert",
    "update",
    "delete",
    "call",
    "openFile",
    "getType",
    "onCreate",
})

_ALL_ENTRY_POINT_NAMES = (
    _ACTIVITY_ENTRY_POINTS
    | _RECEIVER_ENTRY_POINTS
    | _SERVICE_ENTRY_POINTS
    | _PROVIDER_ENTRY_POINTS
)

# Maximum call-graph depth for reachability BFS
_BFS_MAX_DEPTH = 10


# ----------------------------------------------------------------------- #
# Public API
# ----------------------------------------------------------------------- #


def get_const_string_at_callsite(
    analysis,
    method_analysis,
    invoke_offset: int,
    arg_index: int,
) -> str | None:
    """Walk backwards from an invoke instruction to find the const-string
    that feeds the argument at *arg_index*.

    The function inspects the basic block that contains *invoke_offset*,
    walking backwards from that instruction.  It tracks the register used
    by the invoke for the given argument and looks for a ``const-string``
    (or ``const-string/jumbo``) assignment to that register, following
    ``move-object`` and ``move-result-object`` chains one level deep.

    Args:
        analysis: Androguard ``Analysis`` object.
        method_analysis: ``MethodAnalysis`` object for the *caller* method
            (the method that contains the invoke instruction).
        invoke_offset: Byte offset of the invoke instruction within the
            method's code unit.  Matches the offset reported by
            Androguard's instruction iterator.
        arg_index: Zero-based index of the argument whose source we want.
            For instance methods the first argument (index 0) is ``this``;
            static-method argument 0 is the first explicit parameter.

    Returns:
        The constant string value if one can be resolved, otherwise ``None``.
    """
    try:
        method = method_analysis.get_method()
        if method is None:
            return None

        instructions = list(method.get_instructions())
        if not instructions:
            return None

        # Build an (offset -> instruction) map and find the invoke
        offset_map: dict[int, object] = {}
        current_offset = 0
        invoke_idx: int | None = None

        for idx, instr in enumerate(instructions):
            offset_map[current_offset] = (idx, instr)
            if current_offset == invoke_offset:
                invoke_idx = idx
            current_offset += instr.get_length()

        if invoke_idx is None:
            # Offset not found — try a looser match by scanning for any invoke
            # near the requested offset (within ±8 bytes) to handle alignment.
            for offset, (idx, instr) in offset_map.items():
                if abs(offset - invoke_offset) <= 8 and "invoke" in instr.get_name():
                    invoke_idx = idx
                    break

        if invoke_idx is None:
            return None

        invoke_instr = instructions[invoke_idx]
        target_reg = _get_invoke_arg_register(invoke_instr, arg_index)
        if target_reg is None:
            return None

        # Walk backwards from invoke_idx to find what loaded target_reg
        return _trace_register_backward(instructions, invoke_idx - 1, target_reg)

    except Exception as exc:
        logger.debug("get_const_string_at_callsite failed: %s", exc)
        return None


def is_reachable_from_exported(analysis, apk, target_method_analysis) -> bool:
    """BFS backwards through the call graph to check if an exported
    component's entry point can reach *target_method_analysis*.

    Traversal starts at *target_method_analysis* and follows
    ``get_xref_from()`` (callers) edges up to ``_BFS_MAX_DEPTH`` hops.
    If any reached method belongs to a class that is both listed in the
    manifest as an exported component and has a name matching a known
    entry-point method, the function returns ``True``.

    Args:
        analysis: Androguard ``Analysis`` object.
        apk: Androguard ``APK`` object (used to query exported components).
        target_method_analysis: ``MethodAnalysis`` to start BFS from.

    Returns:
        ``True`` if reachable from an exported entry point, ``False``
        otherwise (including on any error).
    """
    try:
        exported_class_names = _get_exported_class_names(apk)
        if not exported_class_names:
            return False

        entry_points = get_exported_entry_points(apk, analysis)
        entry_point_set: set[tuple[str, str]] = {
            (ep.class_name, ep.name) for ep in entry_points
        }
        if not entry_point_set:
            return False

        visited: set[tuple[str, str]] = set()
        queue: deque[tuple[object, int]] = deque()
        queue.append((target_method_analysis, 0))

        while queue:
            current_ma, depth = queue.popleft()
            key = (current_ma.class_name, current_ma.name)

            if key in visited:
                continue
            visited.add(key)

            # Check if this node is itself an exported entry point
            if key in entry_point_set:
                return True

            if depth >= _BFS_MAX_DEPTH:
                continue

            # Follow callers (xref_from = methods that call current_ma)
            try:
                for _, caller_ma, _ in current_ma.get_xref_from():
                    caller_key = (caller_ma.class_name, caller_ma.name)
                    if caller_key not in visited:
                        queue.append((caller_ma, depth + 1))
            except Exception:
                pass

        return False

    except Exception as exc:
        logger.debug("is_reachable_from_exported failed: %s", exc)
        return False


def get_exported_entry_points(apk, analysis) -> list:
    """Return all ``MethodAnalysis`` objects that are entry points of
    exported components as declared in the AndroidManifest.

    An entry point is a well-known lifecycle callback method (e.g.
    ``onCreate``, ``onReceive``) on a class whose component is exported.

    Args:
        apk: Androguard ``APK`` object.
        analysis: Androguard ``Analysis`` object.

    Returns:
        A list of ``MethodAnalysis`` instances (may be empty).
    """
    try:
        exported_class_names = _get_exported_class_names(apk)
        if not exported_class_names:
            return []

        results: list = []
        for class_name in exported_class_names:
            # Normalise to Dalvik descriptor format
            dalvik_name = _to_dalvik(class_name)
            class_analysis = analysis.get_class_analysis(dalvik_name)
            if class_analysis is None:
                continue

            for method_analysis in class_analysis.get_methods():
                if method_analysis.name in _ALL_ENTRY_POINT_NAMES:
                    results.append(method_analysis)

        return results

    except Exception as exc:
        logger.debug("get_exported_entry_points failed: %s", exc)
        return []


def check_empty_method_body(
    analysis,
    class_name: str,
    method_name: str,
) -> bool:
    """Check if a method has an empty or trivially-returning body.

    A method is considered "empty" if its instruction sequence contains
    only a single ``return-void`` (or ``return`` with a constant 0/null),
    or if it contains no instructions at all.  This is used to detect
    TrustManager implementations whose ``checkServerTrusted`` does nothing.

    Args:
        analysis: Androguard ``Analysis`` object.
        class_name: Class name in either Dalvik (``Lcom/Foo;``) or Java
            (``com.Foo``) format.
        method_name: Simple method name (e.g. ``checkServerTrusted``).

    Returns:
        ``True`` if the method body is empty/trivial, ``False`` otherwise
        (including when the method is not found).
    """
    try:
        dalvik_name = _to_dalvik(class_name)
        class_analysis = analysis.get_class_analysis(dalvik_name)
        if class_analysis is None:
            return False

        for method_analysis in class_analysis.get_methods():
            if method_analysis.name != method_name:
                continue

            method = method_analysis.get_method()
            if method is None:
                return True  # No bytecode — treat as empty

            instructions = [
                instr for instr in method.get_instructions()
            ]

            if not instructions:
                return True

            if len(instructions) == 1:
                mnemonic = instructions[0].get_name()
                if mnemonic in ("return-void", "return", "return-object"):
                    return True

            # Two instructions: const/4 v0, 0x0 followed by return
            if len(instructions) == 2:
                m0 = instructions[0].get_name()
                m1 = instructions[1].get_name()
                if m0 in ("const/4", "const/16", "const") and m1 in (
                    "return",
                    "return-void",
                    "return-object",
                ):
                    return True

            return False  # Non-trivial body

        return False  # Method not found

    except Exception as exc:
        logger.debug("check_empty_method_body failed: %s", exc)
        return False


def get_arg_source_type(
    analysis,
    method_analysis,
    invoke_offset: int,
    arg_index: int,
) -> str:
    """Determine where a method argument originates.

    Walks backwards from the invoke instruction (identified by
    *invoke_offset*) and classifies the source register as one of:

    - ``'constant'``      — loaded by ``const-string``, ``const``,
                            ``const/4``, ``const/16``, or ``const-wide``.
    - ``'parameter'``     — the register is a method parameter
                            (``p0``..``pN``).
    - ``'field'``         — loaded by ``iget-object``, ``sget-object``,
                            or a similar field read.
    - ``'method_return'`` — result of a previous ``invoke-*`` (loaded via
                            ``move-result-object`` or ``move-result``).
    - ``'unknown'``       — cannot be determined.

    Args:
        analysis: Androguard ``Analysis`` object.
        method_analysis: ``MethodAnalysis`` for the caller method.
        invoke_offset: Byte offset of the invoke instruction.
        arg_index: Zero-based argument index.

    Returns:
        One of the string literals listed above.
    """
    try:
        method = method_analysis.get_method()
        if method is None:
            return "unknown"

        instructions = list(method.get_instructions())
        if not instructions:
            return "unknown"

        # Locate the invoke instruction by offset
        current_offset = 0
        invoke_idx: int | None = None
        for idx, instr in enumerate(instructions):
            if current_offset == invoke_offset:
                invoke_idx = idx
                break
            current_offset += instr.get_length()

        if invoke_idx is None:
            # Loose match
            current_offset = 0
            for idx, instr in enumerate(instructions):
                if abs(current_offset - invoke_offset) <= 8 and "invoke" in instr.get_name():
                    invoke_idx = idx
                    break
                current_offset += instr.get_length()

        if invoke_idx is None:
            return "unknown"

        invoke_instr = instructions[invoke_idx]
        target_reg = _get_invoke_arg_register(invoke_instr, arg_index)
        if target_reg is None:
            return "unknown"

        return _classify_register_source(instructions, invoke_idx - 1, target_reg)

    except Exception as exc:
        logger.debug("get_arg_source_type failed: %s", exc)
        return "unknown"


# ----------------------------------------------------------------------- #
# Private helpers
# ----------------------------------------------------------------------- #


def _to_dalvik(class_name: str) -> str:
    """Coerce a class name to Dalvik descriptor format."""
    name = class_name.strip()
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"


def _get_exported_class_names(apk) -> set[str]:
    """Return the set of Dalvik-format class names for all exported components."""
    exported: set[str] = set()
    package = apk.get_package()

    component_getters = [
        apk.get_activities,
        apk.get_services,
        apk.get_receivers,
        apk.get_providers,
    ]

    # Collect all declared components
    all_components: list[str] = []
    for getter in component_getters:
        try:
            all_components.extend(getter())
        except Exception:
            pass

    # Determine which ones are exported
    try:
        manifest = apk.get_android_manifest_xml()
        _ANDROID_NS = "http://schemas.android.com/apk/res/android"

        def _attr(elem, name):
            return elem.get(f"{{{_ANDROID_NS}}}{name}")

        app_elem = manifest.find("application")
        if app_elem is None:
            return exported

        target_sdk_raw = apk.get_target_sdk_version()
        try:
            target_sdk = int(target_sdk_raw) if target_sdk_raw else 0
        except (ValueError, TypeError):
            target_sdk = 0

        for tag in ("activity", "service", "receiver", "provider"):
            for elem in app_elem.findall(tag):
                comp_name = _attr(elem, "name") or ""
                # Resolve short names (e.g. ".MyActivity")
                if comp_name.startswith("."):
                    comp_name = package + comp_name
                elif "." not in comp_name:
                    comp_name = package + "." + comp_name

                exported_raw = _attr(elem, "exported")
                has_filters = bool(elem.findall("intent-filter"))

                if exported_raw is not None:
                    is_exported = exported_raw.lower() in ("true", "1")
                else:
                    is_exported = has_filters and target_sdk < 31

                if is_exported:
                    exported.add(_to_dalvik(comp_name))

    except Exception as exc:
        logger.debug("_get_exported_class_names manifest parse failed: %s", exc)

    return exported


def _get_invoke_arg_register(invoke_instr, arg_index: int):
    """Extract the register name used for argument *arg_index* from an
    invoke instruction's output string.

    Androguard formats invoke instructions as::

        invoke-virtual {v0, v1, v2}, Ljava/...; method desc

    The registers between the braces are the argument list.  For
    ``invoke-virtual``/``invoke-interface``/``invoke-direct`` the first
    register is ``this`` (index 0); for ``invoke-static`` the first
    register is the first explicit argument.

    Returns the register name string (e.g. ``'v1'``) or ``None``.
    """
    try:
        output = invoke_instr.get_output()
        # Extract register list from braces
        start = output.index("{")
        end = output.index("}")
        regs_str = output[start + 1:end]
        if not regs_str.strip():
            return None
        regs = [r.strip() for r in regs_str.split(",")]
        if arg_index < len(regs):
            return regs[arg_index]
        return None
    except (ValueError, IndexError, AttributeError):
        return None


def _trace_register_backward(instructions, start_idx: int, target_reg: str) -> str | None:
    """Walk backwards from *start_idx* to find a ``const-string`` that
    last wrote to *target_reg*.  Follows one level of ``move-object`` /
    ``move-result-object`` indirection.

    Returns the constant string value or ``None``.
    """
    current_reg = target_reg
    for idx in range(start_idx, -1, -1):
        instr = instructions[idx]
        mnemonic = instr.get_name()
        output = instr.get_output()

        dest_reg = _get_dest_register(output)
        if dest_reg != current_reg:
            continue

        if mnemonic in ("const-string", "const-string/jumbo"):
            # output format:  v0, 'some string'
            return _extract_const_string_value(output)

        if mnemonic in ("move-object", "move", "move-wide",
                        "move-object/from16", "move/from16"):
            # output format:  vDest, vSrc — follow the source register
            src = _get_move_source(output)
            if src:
                current_reg = src
            continue

        if mnemonic == "move-result-object":
            # The value came from the previous invoke — not a constant
            return None

        # Any other instruction writing to current_reg terminates the trace
        return None

    return None


def _classify_register_source(instructions, start_idx: int, target_reg: str) -> str:
    """Classify the source type of a register by walking backwards."""
    current_reg = target_reg
    for idx in range(start_idx, -1, -1):
        instr = instructions[idx]
        mnemonic = instr.get_name()
        output = instr.get_output()

        dest_reg = _get_dest_register(output)
        if dest_reg != current_reg:
            continue

        if mnemonic in ("const-string", "const-string/jumbo",
                        "const", "const/4", "const/16",
                        "const-wide", "const-wide/16", "const-wide/32"):
            return "constant"

        if mnemonic in ("move-object", "move", "move-wide",
                        "move-object/from16", "move/from16"):
            src = _get_move_source(output)
            if src:
                current_reg = src
            continue

        if mnemonic in ("move-result-object", "move-result", "move-result-wide"):
            return "method_return"

        if mnemonic in ("iget-object", "iget", "iget-boolean", "iget-byte",
                        "iget-char", "iget-short", "iget-wide",
                        "sget-object", "sget", "sget-boolean", "sget-byte",
                        "sget-char", "sget-short", "sget-wide"):
            return "field"

        # Anything else that writes to the register
        return "unknown"

    # If we exhausted all instructions, the register is likely a parameter
    # (parameter registers are pre-set before the first instruction)
    if current_reg.startswith("p"):
        return "parameter"

    return "unknown"


def _get_dest_register(output: str) -> str | None:
    """Extract the destination register from an instruction output string.

    Androguard typically formats the destination register as the first
    token before a comma or end-of-string.
    """
    try:
        # Strip leading/trailing whitespace
        output = output.strip()
        # Destination is the first token before the first comma
        part = output.split(",")[0].strip()
        # Remove any leading type info like "[I" for arrays
        # Valid register names: v0..vN or p0..pN
        if part.startswith(("v", "p")) and part[1:].isdigit():
            return part
        # Handle "v10", "p0" etc with more digits
        for token in part.split():
            t = token.strip(",").strip()
            if len(t) >= 2 and t[0] in ("v", "p") and t[1:].isdigit():
                return t
        return None
    except Exception:
        return None


def _get_move_source(output: str) -> str | None:
    """Extract the source register from a move instruction output string.

    Format: ``vDest, vSrc``
    """
    try:
        parts = output.split(",")
        if len(parts) >= 2:
            src = parts[1].strip()
            if src.startswith(("v", "p")) and src[1:].isdigit():
                return src
        return None
    except Exception:
        return None


def _extract_const_string_value(output: str) -> str | None:
    """Extract the string literal from a ``const-string`` output.

    Androguard formats const-string as::

        v0, 'AES/CBC/PKCS5Padding'

    or without quotes in some versions.
    """
    try:
        # Find text after the first comma
        comma_idx = output.index(",")
        val = output[comma_idx + 1:].strip()
        # Strip surrounding quotes if present
        if (val.startswith("'") and val.endswith("'")) or \
           (val.startswith('"') and val.endswith('"')):
            val = val[1:-1]
        return val if val else None
    except (ValueError, IndexError):
        return None
