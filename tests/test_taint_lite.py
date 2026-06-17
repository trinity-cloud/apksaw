"""Unit tests for the integer constant resolver in taint_lite.

These lock the Package 02 fixes — most importantly that ``const/high16`` is
NOT double-shifted (Androguard already renders the full 32-bit value), which is
the gate for FLAG_MUTABLE detection in generate_pending_intent_poc.
"""

from apksaw.utils.taint_lite import _trace_int_register_backward


class _Instr:
    """Minimal stand-in for an Androguard instruction (name + output)."""

    def __init__(self, name: str, output: str, length: int = 2):
        self._name = name
        self._output = output
        self._length = length

    def get_name(self) -> str:
        return self._name

    def get_output(self) -> str:
        return self._output

    def get_length(self) -> int:
        return self._length


def _trace(instrs, target_reg):
    return _trace_int_register_backward(instrs, len(instrs) - 1, target_reg)


# --- const/high16: the critical no-double-shift cases -----------------------
# Androguard's Instruction21h left-shifts OP 0x15 internally, so get_output()
# already renders the full value (e.g. FLAG_MUTABLE 0x02000000 -> "v0, 33554432").

def test_const_high16_flag_mutable_not_double_shifted():
    instrs = [_Instr("const/high16", "v0, 33554432")]  # 0x02000000
    assert _trace(instrs, "v0") == 0x02000000


def test_const_high16_flag_immutable():
    instrs = [_Instr("const/high16", "v1, 67108864")]  # 0x04000000
    assert _trace(instrs, "v1") == 0x04000000


# --- plain const forms ------------------------------------------------------

def test_const16_decimal_and_hex():
    assert _trace([_Instr("const/16", "v0, 0x2")], "v0") == 2
    assert _trace([_Instr("const/4", "v3, 0x1")], "v3") == 1
    assert _trace([_Instr("const", "v0, 33554432")], "v0") == 33554432


# --- or-int composition (runtime-built flags, not constant-folded) ----------

def test_or_int_two_register_composition():
    # flags = FLAG_MUTABLE | FLAG_UPDATE_CURRENT, built at runtime
    instrs = [
        _Instr("const/high16", "v1, 33554432"),    # 0x02000000 FLAG_MUTABLE
        _Instr("const/high16", "v2, 134217728"),   # 0x08000000 FLAG_UPDATE_CURRENT
        _Instr("or-int", "v0, v1, v2"),
    ]
    assert _trace(instrs, "v0") == (0x02000000 | 0x08000000)


def test_or_int_2addr_composition():
    instrs = [
        _Instr("const/high16", "v0, 33554432"),    # 0x02000000
        _Instr("const/high16", "v2, 268435456"),   # 0x10000000 FLAG_CANCEL_CURRENT
        _Instr("or-int/2addr", "v0, v2"),          # v0 |= v2
    ]
    assert _trace(instrs, "v0") == (0x02000000 | 0x10000000)


def test_or_int_lit_composition():
    instrs = [
        _Instr("const/16", "v1, 0x2"),
        _Instr("or-int/lit8", "v0, v1, 0x1"),      # 2 | 1
    ]
    assert _trace(instrs, "v0") == 3


# --- unresolved sources return None (conservative) --------------------------

def test_unresolved_move_result_returns_none():
    instrs = [_Instr("move-result", "v0")]
    assert _trace(instrs, "v0") is None


def test_unresolved_sget_returns_none():
    # static-field loads are intentionally not followed in the int path
    instrs = [_Instr("sget", "v0, Lcom/x/Foo;->FLAG I")]
    assert _trace(instrs, "v0") is None
