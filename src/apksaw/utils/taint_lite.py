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
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass  # Androguard types are imported lazily at call-time

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------- #
# Resolution policy
# ----------------------------------------------------------------------- #


@dataclass(frozen=True)
class TaintPolicy:
    """Resolution-policy knobs for constant-resolution traces.

    Instances are immutable so callers can safely reuse the module-level
    defaults without accidental mutation.  The integer resolver currently
    remains conservative and intra-procedural; inter-procedural int/field
    following is represented here as an explicit future extension point.
    """

    max_depth: int = 2
    """Reserved maximum inter-procedural hop count."""

    follow_calls: bool = False
    """Reserved flag for following method returns across boundaries."""

    follow_fields: bool = True
    """Reserved flag for following one-write static fields."""


DEFAULT_POLICY = TaintPolicy()  # current behaviour — unchanged
DEEP_POLICY = TaintPolicy(max_depth=3, follow_calls=True)

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

# Exception type descriptors considered "catch-all" for swallow detection
_CATCH_ALL_TYPES = frozenset({
    "Ljava/lang/Throwable;",
    "Ljava/lang/Exception;",
    "Ljava/lang/RuntimeException;",
})


# ----------------------------------------------------------------------- #
# Public API
# ----------------------------------------------------------------------- #


def get_const_string_at_callsite(
    analysis,
    method_analysis,
    invoke_offset: int,
    arg_index: int,
    follow_calls: bool = False,
    max_depth: int = 2,
) -> str | None:
    """Walk backwards from an invoke instruction to find the const-string
    that feeds the argument at *arg_index*.

    The function inspects the basic block that contains *invoke_offset*,
    walking backwards from that instruction.  It tracks the register used
    by the invoke for the given argument and looks for a ``const-string``
    (or ``const-string/jumbo``) assignment to that register, following
    ``move-object`` and ``move-result-object`` chains one level deep.

    When *follow_calls* is ``True`` and the intra-procedural trace cannot
    resolve to a constant (e.g. the value comes from a ``move-result-object``),
    the function attempts inter-procedural resolution by calling
    :func:`resolve_constant_interprocedural` and returning the resolved value
    if all return paths of the callee yield the same constant.

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
        follow_calls: When ``True``, follow ``method_return`` traces across
            method boundaries using inter-procedural analysis.  Defaults to
            ``False`` for backward compatibility.
        max_depth: Maximum number of inter-procedural hops to follow when
            *follow_calls* is ``True``.  Defaults to ``2``.

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
        result = _trace_register_backward(instructions, invoke_idx - 1, target_reg)
        if result is not None:
            return result

        # Intra-procedural trace failed — try inter-procedural if requested
        if follow_calls and max_depth > 0:
            value, _src_type, _trace = resolve_constant_interprocedural(
                analysis, method_analysis, invoke_offset, arg_index,
                max_depth=max_depth,
            )
            return value

        return None

    except Exception as exc:
        logger.debug("get_const_string_at_callsite failed: %s", exc)
        return None


def get_const_int_at_callsite(
    analysis,
    method_analysis,
    invoke_offset: int,
    arg_index: int,
    policy: TaintPolicy = DEFAULT_POLICY,
) -> int | None:
    """Walk backwards from an invoke instruction to find the integer/boolean
    constant that feeds the argument at *arg_index*.

    This is the primitive-valued counterpart to
    :func:`get_const_string_at_callsite`.  It resolves ``const/4``,
    ``const/16``, ``const``, ``const/high16``, and the wide variants,
    following one level of ``move`` indirection.  Booleans are represented as
    ``0`` (false) / ``1`` (true) in Dalvik, so this also resolves boolean
    arguments such as the one passed to
    ``WebSettings.setAllowUniversalAccessFromFileURLs(boolean)``.

    ``const/high16`` is resolved as-is: Androguard's ``Instruction21h`` already
    left-shifts the operand for OP 0x15 and renders the full 32-bit value, so no
    extra shift is applied. This covers compile-time constant-folded flags like
    ``FLAG_MUTABLE = 0x02000000`` that have zero low-16 bits. ``or-int`` flag
    composition is also resolved; ``sget`` static-field loads are not followed.

    Conservative by design: anything it cannot prove to be a literal returns
    ``None`` (caller should treat that as "unresolved", not "safe").

    The *policy* parameter is accepted so callers can opt into named resolution
    profiles without changing call signatures, but this integer path currently
    does not follow method returns or static fields.  ``move-result`` and
    ``sget`` remain unresolved.

    Args:
        analysis: Androguard ``Analysis`` object.
        method_analysis: ``MethodAnalysis`` for the *caller* method.
        invoke_offset: Byte offset of the invoke instruction.
        arg_index: Zero-based argument index. For instance methods index 0 is
            ``this``; for a one-arg setter the value is at index 1.
        policy: Resolution policy controlling depth and inter-procedural
            following.  Defaults to :data:`DEFAULT_POLICY`.

    Returns:
        The integer value if it can be resolved, otherwise ``None``.
    """
    try:
        method = method_analysis.get_method()
        if method is None:
            return None

        instructions = list(method.get_instructions())
        if not instructions:
            return None

        offset_map: dict[int, tuple[int, object]] = {}
        current_offset = 0
        invoke_idx: int | None = None

        for idx, instr in enumerate(instructions):
            offset_map[current_offset] = (idx, instr)
            if current_offset == invoke_offset:
                invoke_idx = idx
            current_offset += instr.get_length()

        if invoke_idx is None:
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

        return _trace_int_register_backward(instructions, invoke_idx - 1, target_reg)

    except Exception as exc:
        logger.debug("get_const_int_at_callsite failed: %s", exc)
        return None


def resolve_constant_interprocedural(
    analysis,
    method_analysis,
    invoke_offset: int,
    arg_index: int,
    max_depth: int = 2,
) -> tuple[str | None, str, list[str]]:
    """Resolve a method argument to its constant value, following up to
    *max_depth* levels of method calls.

    This function first performs an intra-procedural trace identical to
    :func:`get_const_string_at_callsite`.  When the trace hits a
    ``move-result-object`` (the value comes from a nested call), it attempts
    to follow into that callee and check whether *all* of its return paths
    yield the same constant string.

    The function also handles the case where the argument originates from a
    field load (``iget-object`` / ``sget-object``): it inspects write
    cross-references for that field and returns the constant if the field is
    written exactly once with a literal string.

    Args:
        analysis: Androguard ``Analysis`` object.
        method_analysis: ``MethodAnalysis`` for the *caller* method.
        invoke_offset: Byte offset of the outer invoke instruction (the one
            whose argument we are resolving).
        arg_index: Zero-based argument index.
        max_depth: Maximum number of inter-procedural hops.  Pass ``0`` to
            disable recursive following.

    Returns:
        A three-tuple ``(value, source_type, trace)`` where:

        - *value* is the constant string if resolved, ``None`` otherwise.
        - *source_type* is one of:
          ``'constant'``, ``'parameter'``, ``'field'``,
          ``'method_return_constant'``, ``'method_return_unknown'``,
          ``'unknown'``.
        - *trace* is a list of ``"Lclass;->method"`` strings showing the
          resolution path from outermost caller inward.
    """
    trace: list[str] = [f"{method_analysis.class_name}->{method_analysis.name}"]

    try:
        method = method_analysis.get_method()
        if method is None:
            return None, "unknown", trace

        instructions = list(method.get_instructions())
        if not instructions:
            return None, "unknown", trace

        # ------------------------------------------------------------------
        # Step 1: locate the invoke instruction and identify the argument reg
        # ------------------------------------------------------------------
        current_offset = 0
        invoke_idx: int | None = None
        offset_map: dict[int, int] = {}  # byte_offset -> list index

        for idx, instr in enumerate(instructions):
            offset_map[current_offset] = idx
            if current_offset == invoke_offset:
                invoke_idx = idx
            current_offset += instr.get_length()

        if invoke_idx is None:
            # Loose match within ±8 bytes
            for offset, idx in offset_map.items():
                if abs(offset - invoke_offset) <= 8 and "invoke" in instructions[idx].get_name():
                    invoke_idx = idx
                    break

        if invoke_idx is None:
            return None, "unknown", trace

        invoke_instr = instructions[invoke_idx]
        target_reg = _get_invoke_arg_register(invoke_instr, arg_index)
        if target_reg is None:
            return None, "unknown", trace

        # ------------------------------------------------------------------
        # Step 2: intra-procedural backward trace
        # ------------------------------------------------------------------
        const_val = _trace_register_backward(instructions, invoke_idx - 1, target_reg)
        if const_val is not None:
            return const_val, "constant", trace

        src_type = _classify_register_source(instructions, invoke_idx - 1, target_reg)

        # ------------------------------------------------------------------
        # Step 3: handle method_return — recurse into the callee
        # ------------------------------------------------------------------
        if src_type == "method_return" and max_depth > 0:
            # Find the invoke instruction that produced move-result-object
            inner_invoke_instr, inner_invoke_offset = _find_preceding_invoke(
                instructions, invoke_idx - 1, target_reg
            )
            if inner_invoke_instr is not None:
                callee_class, callee_method = _parse_invoke_target(inner_invoke_instr)
                if callee_class and callee_method:
                    trace.append(f"{callee_class}->{callee_method}")
                    callee_val, callee_type = _check_callee_returns_constant(
                        analysis, callee_class, callee_method,
                        max_depth=max_depth - 1,
                        visited=set(trace),
                    )
                    if callee_val is not None:
                        return callee_val, "method_return_constant", trace
                    return None, "method_return_unknown", trace

        # ------------------------------------------------------------------
        # Step 4: handle field sources — check field write cross-references
        # ------------------------------------------------------------------
        if src_type == "field":
            field_name, field_class = _find_field_from_register(
                instructions, invoke_idx - 1, target_reg
            )
            if field_name and field_class:
                field_val = _resolve_field_constant(analysis, field_class, field_name)
                if field_val is not None:
                    trace.append(f"{field_class}.{field_name} (field)")
                    return field_val, "field", trace

        return None, src_type if src_type else "unknown", trace

    except Exception as exc:
        logger.debug("resolve_constant_interprocedural failed: %s", exc)
        return None, "unknown", trace


def analyze_exception_handler(
    analysis,
    class_name: str,
    method_name: str,
) -> dict:
    """Analyze what a method's exception handlers do.

    Inspects the try-catch table embedded in the method's Dalvik bytecode and
    classifies each handler.  This is primarily used to detect ``TrustManager``
    implementations that silently swallow certificate validation exceptions
    (e.g. ``catch (Throwable) { /* empty */ return; }``).

    Args:
        analysis: Androguard ``Analysis`` object.
        class_name: Class name in Dalvik (``Lcom/Foo;``) or Java (``com.Foo``)
            format.
        method_name: Simple method name (e.g. ``checkServerTrusted``).

    Returns:
        A dict with the following keys:

        - ``has_catch_all`` (bool): ``True`` if any handler catches
          ``Throwable``, ``Exception``, or ``RuntimeException``.
        - ``swallows_exception`` (bool): ``True`` if at least one handler
          body is empty (only ``move-exception`` + ``return-void``, or
          ``move-exception`` + a single log/no-op + ``return-void``).
        - ``rethrows`` (bool): ``True`` if at least one handler contains a
          ``throw`` instruction.
        - ``handler_actions`` (list[str]): Human-readable description of
          what each handler does.

        On any error, returns a safe default with all booleans ``False`` and
        an empty ``handler_actions`` list.
    """
    result: dict = {
        "has_catch_all": False,
        "swallows_exception": False,
        "rethrows": False,
        "handler_actions": [],
    }

    try:
        dalvik_name = _to_dalvik(class_name)
        class_analysis = analysis.get_class_analysis(dalvik_name)
        if class_analysis is None:
            return result

        target_method = None
        for ma in class_analysis.get_methods():
            if ma.name == method_name:
                target_method = ma.get_method()
                break

        if target_method is None:
            return result

        code = target_method.get_code()
        if code is None:
            return result

        # Collect all instructions with their byte offsets for handler analysis
        instructions = list(target_method.get_instructions())
        offset_to_idx: dict[int, int] = {}
        current_offset = 0
        for idx, instr in enumerate(instructions):
            offset_to_idx[current_offset] = idx
            current_offset += instr.get_length()

        # Try to read try-catch table
        try:
            tries = code.get_tries()
        except Exception:
            tries = []

        if not tries:
            return result

        for try_block in tries:
            try:
                handlers = try_block.get_handlers()
                if handlers is None:
                    continue

                # Handlers is a TryItem-level object; iterate its pairs
                handler_list = handlers.get_handlers()
                if not handler_list:
                    continue

                for handler_pair in handler_list:
                    try:
                        # handler_pair: (exception_type_or_None, handler_offset)
                        exc_type = handler_pair.get_exception_type()
                        handler_offset = handler_pair.get_handler_offset()
                    except AttributeError:
                        # Older Androguard: handler_pair is (exc_type, offset)
                        try:
                            exc_type, handler_offset = handler_pair
                        except (TypeError, ValueError):
                            continue

                    # Classify the exception type
                    is_catch_all = (
                        exc_type is None  # catch-all (no type = covers all)
                        or exc_type in _CATCH_ALL_TYPES
                    )
                    if is_catch_all:
                        result["has_catch_all"] = True

                    # Inspect the handler body starting at handler_offset
                    action = _classify_handler_body(
                        instructions, offset_to_idx, handler_offset
                    )
                    exc_label = exc_type if exc_type else "catch-all"
                    result["handler_actions"].append(f"catch({exc_label}): {action}")

                    if action == "swallows":
                        result["swallows_exception"] = True
                    elif action == "rethrows":
                        result["rethrows"] = True

            except Exception as exc:
                logger.debug("analyze_exception_handler handler parse failed: %s", exc)
                continue

    except Exception as exc:
        logger.debug("analyze_exception_handler failed: %s", exc)

    return result


def get_method_complexity(
    analysis,
    class_name: str,
    method_name: str,
) -> dict:
    """Score a method's complexity to help determine if it is trivial or
    substantial.

    The complexity score is a heuristic on a 0–100 scale:

    - Each instruction contributes 1 point (capped at 50).
    - Each branch instruction (``if-*``, ``packed-switch``, ``sparse-switch``)
      contributes an additional 3 points (capped at 30).
    - Each ``invoke-*`` contributes an additional 2 points (capped at 20).

    A method is considered *trivial* if it has ≤ 5 instructions and no branch
    or invoke instructions.

    Args:
        analysis: Androguard ``Analysis`` object.
        class_name: Class name in Dalvik or Java format.
        method_name: Simple method name.

    Returns:
        A dict with the following keys:

        - ``instruction_count`` (int): Total number of bytecode instructions.
        - ``branch_count`` (int): Number of branching instructions.
        - ``invoke_count`` (int): Number of method-call instructions.
        - ``return_count`` (int): Number of return instructions.
        - ``throws`` (bool): ``True`` if the method contains a ``throw``
          instruction.
        - ``has_try_catch`` (bool): ``True`` if the method has a try-catch
          table.
        - ``is_trivial`` (bool): ``True`` if the method has ≤ 5 instructions
          and no branches or invokes.
        - ``complexity_score`` (int): Heuristic score in [0, 100].

        On any error, returns safe defaults with all counts 0 and booleans
        ``False``.
    """
    defaults: dict = {
        "instruction_count": 0,
        "branch_count": 0,
        "invoke_count": 0,
        "return_count": 0,
        "throws": False,
        "has_try_catch": False,
        "is_trivial": False,
        "complexity_score": 0,
    }

    try:
        dalvik_name = _to_dalvik(class_name)
        class_analysis = analysis.get_class_analysis(dalvik_name)
        if class_analysis is None:
            return defaults

        target_method = None
        for ma in class_analysis.get_methods():
            if ma.name == method_name:
                target_method = ma.get_method()
                break

        if target_method is None:
            return defaults

        code = target_method.get_code()
        instructions = list(target_method.get_instructions()) if code else []

        instr_count = len(instructions)
        branch_count = 0
        invoke_count = 0
        return_count = 0
        throws = False

        for instr in instructions:
            name = instr.get_name()
            if name.startswith("if-") or name in ("packed-switch", "sparse-switch"):
                branch_count += 1
            elif name.startswith("invoke"):
                invoke_count += 1
            elif name.startswith("return"):
                return_count += 1
            elif name == "throw":
                throws = True

        # Check for try-catch table
        has_try_catch = False
        if code is not None:
            try:
                tries = code.get_tries()
                has_try_catch = bool(tries)
            except Exception:
                pass

        is_trivial = (instr_count <= 5) and (branch_count == 0) and (invoke_count == 0)

        # Compute composite score (capped components to avoid runaway scores)
        score_instrs = min(instr_count, 50)
        score_branches = min(branch_count * 3, 30)
        score_invokes = min(invoke_count * 2, 20)
        complexity_score = min(score_instrs + score_branches + score_invokes, 100)

        return {
            "instruction_count": instr_count,
            "branch_count": branch_count,
            "invoke_count": invoke_count,
            "return_count": return_count,
            "throws": throws,
            "has_try_catch": has_try_catch,
            "is_trivial": is_trivial,
            "complexity_score": complexity_score,
        }

    except Exception as exc:
        logger.debug("get_method_complexity failed: %s", exc)
        return defaults


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

    A method is considered "empty" if:

    1. It has no bytecode at all.
    2. Its instruction sequence is a single ``return-void`` / ``return``
       / ``return-object``.
    3. It is two instructions: a zero/null constant load followed by
       ``return`` / ``return-void`` / ``return-object``.
    4. Its entire meaningful logic is wrapped in a try-catch block where
       the catch handler is a *catch-all* (``Throwable`` / ``Exception``)
       that swallows the exception (i.e. only ``move-exception`` +
       ``return-void`` with no re-throw).  This pattern is common in
       broken TrustManager implementations that delegate to a real
       validator but swallow any ``CertificateException`` it raises,
       effectively disabling validation.

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

            # Check for the swallowing catch-all pattern:
            # try { someValidation() } catch (Throwable) { return; }
            handler_info = analyze_exception_handler(analysis, class_name, method_name)
            if handler_info["has_catch_all"] and handler_info["swallows_exception"]:
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
# Private helpers — inter-procedural resolution
# ----------------------------------------------------------------------- #


def _check_callee_returns_constant(
    analysis,
    callee_class: str,
    callee_method: str,
    max_depth: int,
    visited: set[str],
) -> tuple[str | None, str]:
    """Check if ALL return paths of a callee return the same constant string.

    Walks every ``return-object`` instruction in the callee's body and traces
    the returned register backwards.  If every path resolves to the same
    literal, that literal is returned.  If any path is non-constant or
    resolves to a different value, returns ``(None, 'unknown')``.

    To prevent infinite recursion, the *visited* set tracks already-seen
    ``"Lclass;->method"`` strings.

    Args:
        analysis: Androguard ``Analysis`` object.
        callee_class: Dalvik-format class descriptor of the callee.
        callee_method: Simple method name of the callee.
        max_depth: Remaining recursion budget.
        visited: Set of already-visited ``"class->method"`` identifiers.

    Returns:
        ``(constant_value, source_type)`` or ``(None, 'unknown')``.
    """
    key = f"{callee_class}->{callee_method}"
    if key in visited or max_depth < 0:
        return None, "unknown"

    visited = visited | {key}

    try:
        class_analysis = analysis.get_class_analysis(callee_class)
        if class_analysis is None:
            return None, "unknown"

        target_method = None
        for ma in class_analysis.get_methods():
            if ma.name == callee_method:
                target_method = ma.get_method()
                break

        if target_method is None:
            return None, "unknown"

        instructions = list(target_method.get_instructions())
        if not instructions:
            return None, "unknown"

        # Collect all return-object instruction indices
        return_indices: list[int] = []
        for idx, instr in enumerate(instructions):
            if instr.get_name() in ("return-object", "return"):
                return_indices.append(idx)

        if not return_indices:
            return None, "unknown"

        resolved_values: list[str] = []

        for ret_idx in return_indices:
            ret_instr = instructions[ret_idx]
            # The returned register is the first (and only) operand
            output = ret_instr.get_output().strip()
            ret_reg = _get_dest_register(output)
            if ret_reg is None:
                # return-void or malformed — skip
                continue

            # Trace the returned register backwards
            const_val = _trace_register_backward(instructions, ret_idx - 1, ret_reg)
            if const_val is not None:
                resolved_values.append(const_val)
                continue

            # Check if it comes from a nested call (and we have budget)
            src_type = _classify_register_source(instructions, ret_idx - 1, ret_reg)
            if src_type == "method_return" and max_depth > 0:
                inner_invoke, _ = _find_preceding_invoke(
                    instructions, ret_idx - 1, ret_reg
                )
                if inner_invoke is not None:
                    inner_class, inner_method = _parse_invoke_target(inner_invoke)
                    if inner_class and inner_method:
                        nested_val, nested_type = _check_callee_returns_constant(
                            analysis, inner_class, inner_method,
                            max_depth=max_depth - 1,
                            visited=visited,
                        )
                        if nested_val is not None:
                            resolved_values.append(nested_val)
                            continue
            # Non-constant path found — give up
            return None, "unknown"

        if not resolved_values:
            return None, "unknown"

        # All paths must agree on the same constant
        unique_vals = set(resolved_values)
        if len(unique_vals) == 1:
            return resolved_values[0], "method_return_constant"

        return None, "unknown"

    except Exception as exc:
        logger.debug("_check_callee_returns_constant failed: %s", exc)
        return None, "unknown"


def _find_preceding_invoke(
    instructions: list,
    start_idx: int,
    result_reg: str,
) -> tuple[object | None, int]:
    """Walk backwards from *start_idx* to find the invoke instruction whose
    result was stored in *result_reg* via ``move-result-object``.

    Returns ``(invoke_instruction, byte_offset)`` or ``(None, -1)``.
    """
    # First find the move-result-object that wrote to result_reg
    current_reg = result_reg
    for idx in range(start_idx, -1, -1):
        instr = instructions[idx]
        mnemonic = instr.get_name()
        output = instr.get_output()

        # Follow move chains
        if mnemonic in ("move-object", "move", "move-wide",
                        "move-object/from16", "move/from16"):
            dest = _get_dest_register(output)
            if dest == current_reg:
                src = _get_move_source(output)
                if src:
                    current_reg = src
            continue

        dest = _get_dest_register(output)
        if dest != current_reg:
            continue

        if mnemonic in ("move-result-object", "move-result", "move-result-wide"):
            # The very next previous instruction must be the invoke
            for inner_idx in range(idx - 1, -1, -1):
                inner_instr = instructions[inner_idx]
                if "invoke" in inner_instr.get_name():
                    # Compute byte offset of that invoke
                    byte_offset = 0
                    for i, ins in enumerate(instructions):
                        if i == inner_idx:
                            return inner_instr, byte_offset
                        byte_offset += ins.get_length()
                break  # Only look one step back

        break

    return None, -1


def _parse_invoke_target(invoke_instr) -> tuple[str | None, str | None]:
    """Extract the target class and method name from an invoke instruction.

    Androguard formats invoke instructions as::

        invoke-virtual {v0, v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    The part after the ``},`` space contains the full method reference in
    ``Lclass;->method(sig)rettype`` format.

    Returns:
        ``(class_descriptor, method_name)`` or ``(None, None)`` on failure.
    """
    try:
        output = invoke_instr.get_output()
        # Find the method reference after the closing brace
        brace_end = output.find("}")
        if brace_end == -1:
            return None, None
        ref_part = output[brace_end + 1:].strip().lstrip(",").strip()

        # ref_part looks like: Lsome/Class;->methodName(...)RetType
        arrow_idx = ref_part.find("->")
        if arrow_idx == -1:
            return None, None

        class_desc = ref_part[:arrow_idx].strip()  # e.g. "Ljava/lang/String;"
        rest = ref_part[arrow_idx + 2:]             # e.g. "methodName(...)RetType"

        paren_idx = rest.find("(")
        method_name = rest[:paren_idx].strip() if paren_idx != -1 else rest.strip()

        if not class_desc or not method_name:
            return None, None

        return class_desc, method_name

    except Exception:
        return None, None


def _find_field_from_register(
    instructions: list,
    start_idx: int,
    target_reg: str,
) -> tuple[str | None, str | None]:
    """Walk backwards from *start_idx* to find an ``iget-object`` /
    ``sget-object`` instruction that loaded *target_reg*.

    Returns:
        ``(field_name, declaring_class)`` extracted from the instruction
        output, or ``(None, None)`` if not found.

    The Androguard output for ``iget-object`` looks like::

        v2, v0, Lcom/example/Foo;->mKey [Ljava/lang/String;
    """
    current_reg = target_reg
    for idx in range(start_idx, -1, -1):
        instr = instructions[idx]
        mnemonic = instr.get_name()
        output = instr.get_output()

        if mnemonic in ("move-object", "move", "move-wide",
                        "move-object/from16", "move/from16"):
            dest = _get_dest_register(output)
            if dest == current_reg:
                src = _get_move_source(output)
                if src:
                    current_reg = src
            continue

        dest = _get_dest_register(output)
        if dest != current_reg:
            continue

        if mnemonic in ("iget-object", "iget", "iget-boolean", "iget-byte",
                        "iget-char", "iget-short", "iget-wide",
                        "sget-object", "sget", "sget-boolean", "sget-byte",
                        "sget-char", "sget-short", "sget-wide"):
            # Parse field reference from output
            # sget: "v2, Lcom/example/Foo;->FIELD_NAME [type"
            # iget: "v2, v1, Lcom/example/Foo;->FIELD_NAME [type"
            try:
                parts = output.split(",")
                # Field ref is the last comma-separated component before "["
                field_ref_part = parts[-1].strip()
                arrow_idx = field_ref_part.find("->")
                if arrow_idx != -1:
                    class_desc = field_ref_part[:arrow_idx].strip()
                    rest = field_ref_part[arrow_idx + 2:]
                    # rest: "FIELD_NAME [Ljava/lang/String;"
                    space_idx = rest.find(" ")
                    field_name = rest[:space_idx].strip() if space_idx != -1 else rest.strip()
                    return field_name, class_desc
            except Exception:
                pass

        break

    return None, None


def _resolve_field_constant(
    analysis,
    field_class: str,
    field_name: str,
) -> str | None:
    """Attempt to resolve a field's value to a constant string by inspecting
    write cross-references.

    If the field is written exactly once with a ``const-string`` instruction,
    return that string.  Otherwise return ``None``.

    Args:
        analysis: Androguard ``Analysis`` object.
        field_class: Dalvik descriptor of the declaring class.
        field_name: Name of the field.

    Returns:
        The constant string if the field has exactly one constant write,
        ``None`` otherwise.
    """
    try:
        class_analysis = analysis.get_class_analysis(field_class)
        if class_analysis is None:
            return None

        field_analysis = None
        for fa in class_analysis.get_fields():
            if fa.name == field_name:
                field_analysis = fa
                break

        if field_analysis is None:
            return None

        write_xrefs = list(field_analysis.get_xref_write())
        if not write_xrefs:
            return None

        # Each xref_write entry: (ClassAnalysis, MethodAnalysis, offset)
        constant_values: list[str] = []

        for _, writer_ma, write_offset in write_xrefs:
            writer_method = writer_ma.get_method()
            if writer_method is None:
                return None

            writer_instructions = list(writer_method.get_instructions())

            # Find the write instruction at write_offset
            current_offset = 0
            write_idx: int | None = None
            for idx, instr in enumerate(writer_instructions):
                if current_offset == write_offset:
                    write_idx = idx
                    break
                current_offset += instr.get_length()

            if write_idx is None:
                return None

            write_instr = writer_instructions[write_idx]
            write_output = write_instr.get_output()

            # For iput/sput, the source register is the first register in output
            src_reg = _get_dest_register(write_output)
            if src_reg is None:
                return None

            # Trace that register backwards to a const-string
            val = _trace_register_backward(writer_instructions, write_idx - 1, src_reg)
            if val is not None:
                constant_values.append(val)
            else:
                return None  # This write is not a constant — give up

        # All writes must agree on the same value
        unique = set(constant_values)
        if len(unique) == 1:
            return constant_values[0]

        return None

    except Exception as exc:
        logger.debug("_resolve_field_constant failed: %s", exc)
        return None


def _classify_handler_body(
    instructions: list,
    offset_to_idx: dict[int, int],
    handler_offset: int,
) -> str:
    """Classify what a single exception handler body does.

    Starts at *handler_offset* and reads forward until a terminal instruction
    (``return-*``, ``throw``, or ``goto`` leaving the handler) is found.

    Returns:
        One of:

        - ``'swallows'``: handler body is empty (only ``move-exception`` then
          ``return-void``) or has only innocuous logging before the return.
        - ``'rethrows'``: handler body ends with ``throw``.
        - ``'handles'``: handler body does meaningful work (invoke calls,
          puts, etc.) before returning.
        - ``'unknown'``: could not determine.
    """
    try:
        start_idx = offset_to_idx.get(handler_offset)
        if start_idx is None:
            # Try nearest offset
            nearest_offset = min(
                offset_to_idx.keys(),
                key=lambda o: abs(o - handler_offset),
                default=None,
            )
            if nearest_offset is None or abs(nearest_offset - handler_offset) > 4:
                return "unknown"
            start_idx = offset_to_idx[nearest_offset]

        meaningful_ops = 0
        for idx in range(start_idx, min(start_idx + 20, len(instructions))):
            instr = instructions[idx]
            name = instr.get_name()

            if name == "move-exception":
                continue  # boilerplate start of any handler
            if name == "return-void":
                # If we saw no meaningful ops, this is a swallow
                return "swallows" if meaningful_ops == 0 else "handles"
            if name in ("return", "return-object", "return-wide"):
                return "handles"
            if name == "throw":
                return "rethrows"
            if name == "goto" or name.startswith("goto/"):
                # Unconditional branch — conservative: treat as unknown
                return "unknown"
            if name.startswith("invoke"):
                # A log call is the most common "swallow with logging" pattern.
                # Detect common log classes and treat them as non-meaningful.
                output = instr.get_output()
                if any(log_sig in output for log_sig in (
                    "Landroid/util/Log;",
                    "Ljava/util/logging/Logger;",
                    "Lorg/slf4j/Logger;",
                    "Ltimber/log/Timber;",
                    "printStackTrace",
                )):
                    continue  # logging-only call — still a swallow candidate
                meaningful_ops += 1
            else:
                # iput, sput, array ops etc.
                if not name.startswith("move") and not name.startswith("const"):
                    meaningful_ops += 1

        return "unknown"

    except Exception as exc:
        logger.debug("_classify_handler_body failed: %s", exc)
        return "unknown"


# ----------------------------------------------------------------------- #
# Private helpers — existing (unchanged)
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


def _trace_int_register_backward(instructions, start_idx: int, target_reg: str) -> int | None:
    """Walk backwards from *start_idx* to find an integer ``const*`` that last
    wrote to *target_reg*.  Follows one level of ``move`` indirection.

    ``const/high16`` is taken **as-is**: Androguard's ``Instruction21h`` already
    left-shifts the operand for OP 0x15 and ``get_output()`` renders the full
    32-bit value (e.g. ``FLAG_MUTABLE`` 0x02000000 → ``"v0, 33554432"``), so
    applying another shift would corrupt every high16 constant.

    ``or-int`` / ``or-int/2addr`` / ``or-int/lit*`` are resolved by recursively
    tracing the operand registers — covering runtime-composed flag sets like
    ``FLAG_MUTABLE | FLAG_UPDATE_CURRENT`` that the compiler did not fold.
    ``sget`` static-field loads are intentionally not followed (resolving them
    would require field-initialiser analysis); they terminate the trace at None.
    """
    current_reg = target_reg
    for idx in range(start_idx, -1, -1):
        instr = instructions[idx]
        mnemonic = instr.get_name()
        output = instr.get_output()

        dest_reg = _get_dest_register(output)
        if dest_reg != current_reg:
            continue

        if mnemonic in ("const/4", "const/16", "const",
                        "const/high16",
                        "const-wide", "const-wide/16", "const-wide/32"):
            # const/high16 included: Androguard already renders the shifted value.
            return _extract_const_int_value(output)

        if mnemonic in ("or-int", "or-int/2addr"):
            regs, _lit = _split_reg_operands(output)
            if mnemonic == "or-int" and len(regs) >= 3:
                src_a, src_b = regs[1], regs[2]
            elif mnemonic == "or-int/2addr" and len(regs) >= 2:
                src_a, src_b = regs[0], regs[1]
            else:
                return None
            a = _trace_int_register_backward(instructions, idx - 1, src_a)
            b = _trace_int_register_backward(instructions, idx - 1, src_b)
            return (a | b) if (a is not None and b is not None) else None

        if mnemonic in ("or-int/lit8", "or-int/lit16"):
            regs, lit = _split_reg_operands(output)
            if len(regs) >= 2 and lit is not None:
                base = _trace_int_register_backward(instructions, idx - 1, regs[1])
                return (base | lit) if base is not None else None
            return None

        if mnemonic in ("move", "move/from16", "move/16",
                        "move-wide", "move-wide/from16", "move-wide/16"):
            src = _get_move_source(output)
            if src:
                current_reg = src
            continue

        if mnemonic in ("move-result", "move-result-wide"):
            # Value came from a call — not a static constant.
            return None

        # Any other instruction writing to current_reg (incl. sget) terminates.
        return None

    return None


def _extract_const_int_value(output: str) -> int | None:
    """Extract the integer literal from a ``const*`` instruction output.

    Androguard formats these as ``v0, 0x1`` (hex) or occasionally ``v0, 1``
    (decimal).  Returns the parsed integer, or ``None`` if it cannot be parsed.
    """
    try:
        comma_idx = output.index(",")
        val = output[comma_idx + 1:].strip()
        # Keep only the first token (drop any trailing comment/annotation).
        val = val.split()[0].strip().rstrip(",")
        lowered = val.lower()
        if lowered.startswith("0x") or lowered.startswith("-0x"):
            return int(val, 16)
        return int(val, 10)
    except (ValueError, IndexError):
        return None


def _split_reg_operands(output: str) -> tuple[list[str], int | None]:
    """Split a binop instruction output into register tokens and a literal.

    Examples::

        "v0, v1, v2"    -> (["v0", "v1", "v2"], None)
        "v0, v1, 0x2"   -> (["v0", "v1"], 2)
        "v0, v1"        -> (["v0", "v1"], None)

    Returns ``(register_tokens, literal_or_None)``.
    """
    regs: list[str] = []
    lit: int | None = None
    for tok in output.split(","):
        t = tok.strip()
        if len(t) >= 2 and t[0] in ("v", "p") and t[1:].isdigit():
            regs.append(t)
            continue
        head = t.split()[0].strip() if t else ""
        if not head:
            continue
        try:
            lowered = head.lower()
            lit = int(head, 16) if lowered.startswith(("0x", "-0x")) else int(head, 10)
        except ValueError:
            pass
    return regs, lit
