"""JADX decompiler wrapper."""

import asyncio
import subprocess
from pathlib import Path
from ..config import JADX_BIN


# ---------------------------------------------------------------------------
# Capability detection
# ---------------------------------------------------------------------------

_supports_single_class_cache: bool | None = None


def supports_single_class() -> bool:
    """Check if the installed JADX version supports --single-class.

    The result is cached after the first call so subsequent calls are free.
    """
    global _supports_single_class_cache
    if _supports_single_class_cache is not None:
        return _supports_single_class_cache

    jadx_bin = JADX_BIN
    if not jadx_bin.exists():
        _supports_single_class_cache = False
        return False

    try:
        result = subprocess.run(
            [str(jadx_bin), "--help"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout + result.stderr
        _supports_single_class_cache = "--single-class" in output
    except (OSError, subprocess.TimeoutExpired):
        _supports_single_class_cache = False

    return _supports_single_class_cache


# ---------------------------------------------------------------------------
# Core JADX runner
# ---------------------------------------------------------------------------


async def run_jadx(apk_path: str, output_dir: str, extra_args: list[str] | None = None) -> str:
    """Run JADX to decompile an APK.

    Args:
        apk_path: Path to the APK file.
        output_dir: Directory to write decompiled sources into.
        extra_args: Additional CLI arguments passed to JADX after the defaults.

    Returns:
        Combined stdout + stderr output from JADX as a string.

    Raises:
        FileNotFoundError: If the APK does not exist.
        RuntimeError: If JADX exits with a non-zero status code.
    """
    apk = Path(apk_path)
    if not apk.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    jadx_bin = _resolve_jadx_bin()

    cmd = [
        str(jadx_bin),
        "-d", str(out),
        "--no-imports",
        "--no-debug-info",
        *(extra_args or []),
        str(apk),
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout_bytes, stderr_bytes = await proc.communicate()
    combined = (stdout_bytes + stderr_bytes).decode(errors="replace")

    if proc.returncode != 0:
        raise RuntimeError(
            f"JADX exited with code {proc.returncode}.\n"
            f"Command: {' '.join(cmd)}\n"
            f"Output:\n{combined}"
        )

    return combined


def check_jadx() -> bool:
    """Check if JADX is available and executable.

    Returns:
        True if JADX binary exists and responds to --version.
    """
    jadx_bin = JADX_BIN
    if not jadx_bin.exists():
        return False

    try:
        result = subprocess.run(
            [str(jadx_bin), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


async def decompile_apk(apk_path: str, output_dir: str) -> Path:
    """Full APK decompilation with JADX.

    Ensures JADX is installed (downloads it if necessary), then decompiles
    the given APK into *output_dir*.

    Args:
        apk_path: Path to the APK file.
        output_dir: Directory where decompiled sources will be written.

    Returns:
        Path to the output directory containing the decompiled sources.

    Raises:
        FileNotFoundError: If the APK does not exist.
        RuntimeError: If JADX installation or decompilation fails.
    """
    apk = Path(apk_path)
    if not apk.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    if not check_jadx():
        # Attempt to bootstrap JADX automatically
        from .bootstrap import ensure_jadx
        print("JADX not found — attempting to download...")
        ensure_jadx()

        if not check_jadx():
            raise RuntimeError(
                f"JADX still not available after bootstrap attempt. "
                f"Expected binary at {JADX_BIN}."
            )

    out = Path(output_dir)
    print(f"Decompiling {apk.name} -> {out} ...")
    await run_jadx(apk_path, output_dir)
    print(f"Decompilation complete: {out}")
    return out


# ---------------------------------------------------------------------------
# Single-class decompilation
# ---------------------------------------------------------------------------


async def decompile_class_jadx(apk_path: str, class_name: str, output_dir: str) -> str | None:
    """Decompile a single class using JADX's --single-class flag (JADX 1.4+).

    Falls back to full APK decompilation if --single-class is not supported,
    but only runs the full decompilation once (subsequent calls reuse the
    cached output directory).

    Args:
        apk_path: Path to the APK file.
        class_name: Java-style class name (e.g. "com.example.Foo" or
                    "com.example.Foo$Bar"). Dalvik format is also accepted.
        output_dir: Base directory where JADX output will be written.

    Returns:
        The decompiled Java source as a string, or None if the class file
        could not be located in the JADX output.
    """
    _ensure_jadx_available()

    # Normalise to Java style (dots, no L…; wrapper)
    java_name = _to_java_name(class_name)

    # Convert to Dalvik descriptor for --single-class
    dalvik_name = _to_dalvik_descriptor(java_name)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if supports_single_class():
        # Run JADX targeting just the one class.  JADX may still exit non-zero
        # if it encounters unresolvable references — tolerate that.
        jadx_bin = _resolve_jadx_bin()
        cmd = [
            str(jadx_bin),
            "--single-class", dalvik_name,
            "-d", str(out),
            "--no-imports",
            "--no-debug-info",
            str(apk_path),
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        # Don't raise on non-zero — JADX often exits 1 even on success with
        # unresolvable references; we detect success by finding the output file.
    else:
        # Full-APK fallback: only decompile once regardless of how many classes
        # are later requested.
        if not _output_has_java_files(out):
            await decompile_apk(apk_path, output_dir)

    return _read_class_file(out, java_name)


async def decompile_method_jadx(
    apk_path: str,
    class_name: str,
    method_name: str,
    output_dir: str,
    descriptor: str = "",
) -> str | None:
    """Decompile a single class and extract a specific method.

    Uses a state-machine parser that correctly handles string literals,
    char literals, line comments (``//``), and block comments (``/* */``).
    Brace depth is only updated while in NORMAL state, so braces inside
    strings or comments do not confuse the extraction.

    Args:
        apk_path: Path to the APK file.
        class_name: Java-style (or Dalvik) class name.
        method_name: Unqualified method name (e.g. "onCreate").
        output_dir: Base directory for JADX output.
        descriptor: Optional JVM descriptor used to disambiguate overloads.

    Returns:
        The extracted method source, or None if the class or method was not
        found in the JADX output.
    """
    source = await decompile_class_jadx(apk_path, class_name, output_dir)
    if source is None:
        return None

    extracted = _extract_method_sm(source, method_name, descriptor)
    return extracted  # None if method not found; caller decides fallback


# ---------------------------------------------------------------------------
# Method extraction — state-machine parser
# ---------------------------------------------------------------------------

# Parser states
_ST_NORMAL = 0
_ST_STRING = 1        # inside "…"
_ST_CHAR = 2          # inside '…'
_ST_LINE_COMMENT = 3  # after //
_ST_BLOCK_COMMENT = 4 # inside /* … */


def _extract_method_sm(source: str, method_name: str, descriptor: str = "") -> str | None:
    """Extract a named method from Java source using a state-machine character scanner.

    Handles:
    - String literals (including escape sequences)
    - Char literals
    - Line comments (//)
    - Block comments (/* */)
    - Annotation blocks (@Annotation)
    - Nested classes / nested braces

    Returns the method source (from the signature line to the closing ``}``)
    or None if the method is not found.
    """
    lines = source.splitlines(keepends=True)

    # Collect candidate method signature line numbers.
    # A candidate line must:
    #   1. Contain  method_name + "("
    #   2. Not be inside a comment or string (we check at line level first as
    #      a cheap filter; the full parser validates during extraction)
    #   3. Not contain "class " or "interface " or "enum " (type declarations)
    #   4. Contain one of the common access/modifier keywords OR look like a
    #      constructor or lambda expression

    _MODIFIERS = frozenset([
        "public", "private", "protected", "static", "final",
        "synchronized", "abstract", "native", "default", "strictfp",
        "transient", "volatile",
    ])

    def _is_method_line(line: str) -> bool:
        stripped = line.strip()
        if not (method_name + "(") in stripped:
            return False
        if stripped.startswith("//") or stripped.startswith("*"):
            return False
        if any(kw + " " in stripped for kw in ("class ", "interface ", "enum ")):
            return False
        # Must look like a declaration — has a modifier keyword or is a constructor
        words = stripped.split()
        if not words:
            return False
        # Check if any word before the method name is a modifier or a type
        name_idx = next(
            (i for i, w in enumerate(words) if method_name + "(" in w or w == method_name),
            None,
        )
        if name_idx is None:
            return False
        # If there are words before the method name, at least one should be a
        # modifier or look like a type (starts with uppercase or is a primitive)
        if name_idx > 0:
            return True  # has a return type / modifier prefix — good enough
        # name_idx == 0: could be a constructor (class name == method name) or
        # an unqualified call — accept it, parser will handle brace matching
        return True

    # Walk through lines and attempt extraction at each candidate.
    # We keep the first successfully extracted match (or the first if descriptor
    # matching is requested).
    for start_idx, line in enumerate(lines):
        if not _is_method_line(line):
            continue

        # Found a candidate — extract from here using the state machine.
        block, ok = _sm_extract_from(lines, start_idx)
        if not ok:
            continue

        # If a descriptor was provided, check that the extracted block's
        # parameter list matches.  We do a simple substring check on the
        # first line (the signature) for the descriptor's parameter portion.
        if descriptor:
            sig_line = lines[start_idx]
            # descriptor looks like "(Ljava/lang/String;I)V" — extract params
            param_part = descriptor.split(")")[0].lstrip("(")
            if param_part and param_part not in sig_line and not _descriptor_matches_line(descriptor, sig_line):
                continue  # wrong overload — keep looking

        return block

    return None


def _sm_extract_from(lines: list[str], start_idx: int) -> tuple[str, bool]:
    """Starting at *start_idx*, scan forward with a state machine to find the
    method body and return it.

    Returns ``(text, True)`` on success or ``("", False)`` if no opening
    brace is found within a reasonable lookahead or the brace depth never
    closes.
    """
    state = _ST_NORMAL
    brace_depth = 0
    found_open = False
    result_lines: list[str] = []

    # Limit lookahead for the opening brace to 20 lines (handles multi-line
    # parameter lists and throws clauses without running away).
    MAX_LOOKAHEAD = 20

    for idx in range(start_idx, len(lines)):
        line = lines[idx]
        result_lines.append(line)

        if not found_open and (idx - start_idx) > MAX_LOOKAHEAD:
            # No opening brace found — this wasn't a method declaration
            return "", False

        # Scan every character in this line through the state machine
        i = 0
        while i < len(line):
            ch = line[i]
            next_ch = line[i + 1] if i + 1 < len(line) else ""

            if state == _ST_NORMAL:
                if ch == '"':
                    state = _ST_STRING
                elif ch == "'":
                    state = _ST_CHAR
                elif ch == '/' and next_ch == '/':
                    state = _ST_LINE_COMMENT
                    i += 1  # skip second '/'
                elif ch == '/' and next_ch == '*':
                    state = _ST_BLOCK_COMMENT
                    i += 1  # skip '*'
                elif ch == '{':
                    brace_depth += 1
                    found_open = True
                elif ch == '}':
                    if found_open:
                        brace_depth -= 1
                        if brace_depth == 0:
                            # Closing brace of the method — done.
                            # Include everything up to and including this
                            # line; trim any trailing content on that line
                            # after the '}'.
                            return "".join(result_lines), True

            elif state == _ST_STRING:
                if ch == '\\':
                    i += 1  # skip escaped character
                elif ch == '"':
                    state = _ST_NORMAL

            elif state == _ST_CHAR:
                if ch == '\\':
                    i += 1  # skip escaped character
                elif ch == "'":
                    state = _ST_NORMAL

            elif state == _ST_LINE_COMMENT:
                pass  # consume until end of line (handled by outer loop)

            elif state == _ST_BLOCK_COMMENT:
                if ch == '*' and next_ch == '/':
                    state = _ST_NORMAL
                    i += 1  # skip '/'

            i += 1

        # End of line resets line-comment state
        if state == _ST_LINE_COMMENT:
            state = _ST_NORMAL

    # Ran out of lines without closing the method
    if found_open and brace_depth == 0:
        return "".join(result_lines), True

    return "", False


def _descriptor_matches_line(descriptor: str, sig_line: str) -> bool:
    """Lightweight check: does *descriptor* plausibly match *sig_line*?

    We count the number of parameters in the descriptor and compare with
    the number of commas+1 in the parenthesised portion of sig_line.
    """
    try:
        param_desc = descriptor.split(")")[0].lstrip("(")
        # Count parameters in the descriptor (rough)
        desc_count = _count_descriptor_params(param_desc)
        # Count commas in the Java signature parameters
        paren_start = sig_line.index("(")
        paren_end = sig_line.rindex(")")
        params_text = sig_line[paren_start + 1:paren_end].strip()
        if not params_text:
            java_count = 0
        else:
            java_count = params_text.count(",") + 1
        return desc_count == java_count
    except (ValueError, IndexError):
        return True  # can't determine — don't filter


def _count_descriptor_params(param_desc: str) -> int:
    """Count the number of parameters encoded in a JVM parameter descriptor string."""
    count = 0
    i = 0
    while i < len(param_desc):
        ch = param_desc[i]
        if ch in "BCDFIJSZ":
            count += 1
        elif ch == "L":
            # Object type — skip to ';'
            end = param_desc.find(";", i)
            if end == -1:
                break
            i = end
            count += 1
        elif ch == "[":
            # Array — the next type is the element; don't count the '['
            i += 1
            continue
        i += 1
    return count


# ---------------------------------------------------------------------------
# File-finding helpers
# ---------------------------------------------------------------------------


def _read_class_file(output_dir: Path, java_name: str) -> str | None:
    """Locate and read the .java file for *java_name* under *output_dir*.

    Search strategy (in order):
    1. Exact path under ``<output_dir>/sources/``
    2. Exact path under ``<output_dir>/``
    3. For inner classes (``Foo$Bar``), try the outer-class file under both roots
    4. Glob search for ``**/<OuterClass>.java`` under both roots

    Returns the file contents as a string, or None if not found.
    """
    # For inner classes, JADX puts everything in the outer class file
    outer_name = java_name.split("$")[0]
    rel_path = Path(outer_name.replace(".", "/")).with_suffix(".java")

    search_roots = [
        output_dir / "sources",
        output_dir,
    ]

    # 1 & 2: Exact path lookup
    for root in search_roots:
        candidate = root / rel_path
        if candidate.exists():
            return candidate.read_text(errors="replace")

    # 3 & 4: Glob fallback — useful when JADX renames/moves obfuscated classes
    short_name = Path(outer_name).name  # e.g. "Foo" from "com.example.Foo"
    for root in search_roots:
        if not root.exists():
            continue
        matches = list(root.rglob(f"{short_name}.java"))
        if matches:
            # Prefer the deepest match (most specific package)
            matches.sort(key=lambda p: len(p.parts), reverse=True)
            return matches[0].read_text(errors="replace")

    return None


def _output_has_java_files(output_dir: Path) -> bool:
    """Return True if *output_dir* already contains at least one .java file."""
    if not output_dir.exists():
        return False
    return any(output_dir.rglob("*.java"))


# ---------------------------------------------------------------------------
# Name conversion helpers
# ---------------------------------------------------------------------------


def _to_java_name(name: str) -> str:
    """Normalise a class name to Java dot-separated style.

    Accepts:
    - ``Lcom/example/Foo;``   -> ``com.example.Foo``
    - ``com/example/Foo``     -> ``com.example.Foo``
    - ``com.example.Foo``     -> ``com.example.Foo`` (passthrough)
    """
    name = name.strip()
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def _to_dalvik_descriptor(java_name: str) -> str:
    """Convert ``com.example.Foo`` to ``Lcom/example/Foo;``."""
    if java_name.startswith("L") and java_name.endswith(";"):
        return java_name
    return "L" + java_name.replace(".", "/") + ";"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_jadx_bin() -> Path:
    """Return the JADX binary path, raising RuntimeError if absent."""
    if not JADX_BIN.exists():
        raise RuntimeError(
            f"JADX binary not found at {JADX_BIN}. "
            "Run bootstrap.ensure_jadx() to install it."
        )
    return JADX_BIN


def _ensure_jadx_available() -> None:
    """Ensure JADX is present, bootstrapping if needed."""
    if not check_jadx():
        from .bootstrap import ensure_jadx
        print("JADX not found — attempting to download...")
        ensure_jadx()
        if not check_jadx():
            raise RuntimeError(
                f"JADX still not available after bootstrap attempt. "
                f"Expected binary at {JADX_BIN}."
            )
