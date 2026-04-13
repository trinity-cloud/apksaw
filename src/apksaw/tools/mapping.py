"""ProGuard/R8 mapping file support — load, deobfuscate, and detect obfuscation."""

import math
import re
from collections import Counter

from apksaw.server import mcp
from apksaw.session import get_session, Session


# ---------------------------------------------------------------------------
# Mapping storage helpers
# ---------------------------------------------------------------------------

def _get_obf_to_original(session: Session) -> dict[str, str]:
    """Return the obfuscated -> original mapping dict, creating it if absent."""
    if not hasattr(session, "_obf_to_original"):
        object.__setattr__(session, "_obf_to_original", {})
    return session._obf_to_original  # type: ignore[attr-defined]


def _get_original_to_obf(session: Session) -> dict[str, str]:
    """Return the original -> obfuscated mapping dict, creating it if absent."""
    if not hasattr(session, "_original_to_obf"):
        object.__setattr__(session, "_original_to_obf", {})
    return session._original_to_obf  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# ProGuard mapping parser
# ---------------------------------------------------------------------------

def _parse_mapping(text: str) -> tuple[dict[str, str], dict[str, str], int, int]:
    """Parse a ProGuard/R8 mapping.txt file.

    The format is::

        com.example.OriginalClass -> a.b.c:
            int originalField -> d
            void originalMethod(java.lang.String) -> e

    Returns:
        Tuple of (obf_to_orig, orig_to_obf, class_count, method_count).
    """
    obf_to_orig: dict[str, str] = {}
    orig_to_obf: dict[str, str] = {}

    # Regex patterns
    # Class header:  "original.Name -> obfuscated.Name:"
    class_re = re.compile(r"^([^\s#][^->]*?)\s+->\s+([^:]+)\s*:\s*$")
    # Member line (field or method — may have line-number prefix like "1:5:"):
    # "    [lineinfo] type name[(params)] -> obfName"
    member_re = re.compile(
        r"^\s+"                         # leading whitespace
        r"(?:\d+:\d+:)?"               # optional line-number range
        r"[^\s]+"                       # return type
        r"\s+"
        r"(\S+?(?:\([^)]*\))?)"        # name (optionally with params)
        r"\s+->\s+"
        r"(\w+)"                        # obfuscated name
        r"\s*$"
    )

    class_count = 0
    method_count = 0
    current_orig_class = ""
    current_obf_class  = ""

    for raw_line in text.splitlines():
        # Skip comments
        stripped = raw_line.strip()
        if stripped.startswith("#") or not stripped:
            continue

        class_match = class_re.match(raw_line)
        if class_match:
            current_orig_class = class_match.group(1).strip()
            current_obf_class  = class_match.group(2).strip()
            obf_to_orig[current_obf_class]  = current_orig_class
            orig_to_obf[current_orig_class] = current_obf_class
            class_count += 1
            continue

        if current_orig_class:
            member_match = member_re.match(raw_line)
            if member_match:
                orig_member = member_match.group(1).strip()
                obf_member  = member_match.group(2).strip()
                # Store as "OriginalClass.originalMember -> ObfClass.obfMember"
                orig_key = f"{current_orig_class}.{orig_member}"
                obf_key  = f"{current_obf_class}.{obf_member}"
                if orig_key not in orig_to_obf:
                    orig_to_obf[orig_key] = obf_key
                    obf_to_orig[obf_key]  = orig_key
                    method_count += 1

    return obf_to_orig, orig_to_obf, class_count, method_count


# ---------------------------------------------------------------------------
# Shannon entropy helper
# ---------------------------------------------------------------------------

def _shannon_entropy(chars: list[str]) -> float:
    """Compute Shannon entropy (bits) of a character sequence."""
    if not chars:
        return 0.0
    total = len(chars)
    freq = Counter(chars)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in freq.values()
    )


# ---------------------------------------------------------------------------
# Obfuscation heuristics
# ---------------------------------------------------------------------------

# Pattern: purely alphabetic, 1–3 chars — the classic R8/ProGuard output
_R8_SEQ_CHARSET = "abcdefghijklmnopqrstuvwxyz"

def _obfuscation_heuristics(class_names: list[str]) -> dict:
    """Analyse *class_names* and infer the obfuscator type and confidence.

    Heuristics (applied in priority order):
    1. All names are 1 char long and form a sequential alphabet → R8
    2. Many 1-char lowercase names → R8/ProGuard
    3. Short (≤4 char) mixed-case names with consecutive upper+lower → DexGuard
    4. Random-looking names (high entropy, medium length) → custom obfuscator
    5. Otherwise → not obfuscated

    Returns a dict with keys:
        obfuscator, confidence, obfuscated_class_ratio,
        avg_name_length, entropy, single_char_ratio, short_name_ratio
    """
    if not class_names:
        return {
            "obfuscator": "unknown",
            "confidence": "low",
            "obfuscated_class_ratio": 0.0,
            "avg_name_length": 0.0,
            "entropy": 0.0,
        }

    total = len(class_names)

    # Strip package prefix — use only the simple class name (last segment)
    simple_names = [n.rsplit(".", 1)[-1] for n in class_names]

    lengths = [len(n) for n in simple_names]
    avg_len = sum(lengths) / total

    single_char  = sum(1 for ln in lengths if ln == 1)
    short_names  = sum(1 for ln in lengths if ln <= 3)
    single_ratio = single_char / total
    short_ratio  = short_names / total

    # Entropy: operate over all characters in all simple names concatenated
    all_chars = list("".join(simple_names))
    entropy = _shannon_entropy(all_chars)

    # Mixed-case detection (alternating case like aB, cD)
    mixed_case = sum(
        1 for n in simple_names
        if len(n) == 2 and n[0].islower() and n[1].isupper()
    )
    mixed_case_ratio = mixed_case / total

    # Sequential alphabet detection: names match the R8 pattern
    # a, b, …, z, aa, ab, …
    def _is_r8_sequential(names: list[str]) -> bool:
        """Return True if sorted simple names follow R8's sequential pattern."""
        lower = [n.lower() for n in names if n.isalpha()]
        if len(lower) < 5:
            return False
        # Check that first few names are single lowercase letters
        singles = sorted(n for n in lower if len(n) == 1)
        expected = list(_R8_SEQ_CHARSET[: len(singles)])
        return singles == expected

    sequential = _is_r8_sequential(simple_names)

    # ------------------------------------------------------------------
    # Classify
    # ------------------------------------------------------------------
    obfuscator = "none"
    confidence = "low"

    # Count "obfuscated-looking" names: length ≤ 3 and all-alpha
    obf_count = sum(
        1 for n in simple_names
        if len(n) <= 3 and n.replace("_", "").isalpha()
    )
    obf_ratio = obf_count / total

    if sequential or single_ratio > 0.5:
        obfuscator = "R8/ProGuard"
        confidence = "high" if single_ratio > 0.3 or sequential else "medium"
    elif mixed_case_ratio > 0.15 and avg_len <= 4:
        obfuscator = "DexGuard"
        confidence = "medium"
    elif short_ratio > 0.6 and entropy > 3.5:
        # High entropy + short names but not purely sequential → custom
        obfuscator = "custom"
        confidence = "medium"
    elif obf_ratio > 0.4:
        obfuscator = "R8/ProGuard"
        confidence = "low"
    else:
        obfuscator = "none"
        confidence = "high"

    return {
        "obfuscator": obfuscator,
        "confidence": confidence,
        "obfuscated_class_ratio": round(obf_ratio, 3),
        "avg_name_length": round(avg_len, 2),
        "entropy": round(entropy, 3),
        "single_char_ratio": round(single_ratio, 3),
        "short_name_ratio": round(short_ratio, 3),
    }


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@mcp.tool()
def load_mapping(session_id: str, mapping_path: str) -> dict:
    """Load a ProGuard/R8 mapping.txt file into the current session.

    Once loaded, the deobfuscate_name tool can look up any obfuscated class
    or member name.  The mapping is stored on the session object and persists
    for the lifetime of the session.

    The expected format is standard ProGuard/R8 output::

        com.example.OriginalClass -> a.b.c:
            int originalField -> d
            void originalMethod(java.lang.String) -> e

    Args:
        session_id:   Session ID returned by load_apk.
        mapping_path: Absolute path to the ``mapping.txt`` file on disk.

    Returns:
        A dict reporting how many classes and members were successfully parsed.
    """
    try:
        from pathlib import Path

        session = get_session(session_id)
        p = Path(mapping_path)
        if not p.exists():
            return {
                "status": "error",
                "message": f"Mapping file not found: {mapping_path}",
                "suggestion": (
                    "Provide the full path to a ProGuard/R8 mapping.txt file. "
                    "This is typically found in the build output directory."
                ),
            }

        text = p.read_text(encoding="utf-8", errors="replace")
        obf_to_orig, orig_to_obf, class_count, method_count = _parse_mapping(text)

        # Attach to session using object.__setattr__ to bypass dataclass frozen
        # semantics (Session is not frozen, but _fields are set via assignment)
        session._obf_to_original = obf_to_orig  # type: ignore[attr-defined]
        session._original_to_obf = orig_to_obf  # type: ignore[attr-defined]

        return {
            "status": "ok",
            "data": {
                "mapping_path": str(p),
                "mapped_classes": class_count,
                "mapped_members": method_count,
                "total_entries": len(obf_to_orig),
                "message": (
                    f"Loaded {class_count} class mappings and "
                    f"{method_count} member mappings. "
                    "Use deobfuscate_name to look up individual names."
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
            "message": f"Failed to load mapping file: {exc}",
            "suggestion": "Ensure the file is a valid ProGuard/R8 mapping.txt.",
        }


@mcp.tool()
def deobfuscate_name(session_id: str, obfuscated_name: str) -> dict:
    """Look up an obfuscated class or method name in the loaded mapping.

    Supports both directions:
    * Obfuscated  -> original  (e.g. ``a.b.c``          -> ``com.example.Foo``)
    * Original    -> obfuscated (e.g. ``com.example.Foo`` -> ``a.b.c``)

    Also tries a fuzzy member lookup if an exact match is not found:
    the *obfuscated_name* is split on ``.`` and each component is looked up
    independently.

    Args:
        session_id:      Session ID returned by load_apk.
        obfuscated_name: The name to look up.  Can be a fully-qualified class
                         name, a ``Class.member`` string, or a bare short name.

    Returns:
        A dict with ``original_name``, ``obfuscated_name``, and ``direction``.
    """
    try:
        session = get_session(session_id)

        obf_to_orig = _get_obf_to_original(session)
        orig_to_obf = _get_original_to_obf(session)

        if not obf_to_orig and not orig_to_obf:
            return {
                "status": "error",
                "message": "No mapping loaded for this session.",
                "suggestion": "Call load_mapping with the path to mapping.txt first.",
            }

        name = obfuscated_name.strip()

        # 1. Direct obf->orig lookup
        if name in obf_to_orig:
            return {
                "status": "ok",
                "data": {
                    "input": name,
                    "original_name": obf_to_orig[name],
                    "obfuscated_name": name,
                    "direction": "obf_to_original",
                    "found": True,
                },
            }

        # 2. Direct orig->obf lookup
        if name in orig_to_obf:
            return {
                "status": "ok",
                "data": {
                    "input": name,
                    "original_name": name,
                    "obfuscated_name": orig_to_obf[name],
                    "direction": "original_to_obf",
                    "found": True,
                },
            }

        # 3. Partial / fuzzy: search all keys that contain the input as a substring
        matches_obf  = {k: v for k, v in obf_to_orig.items()  if name in k}
        matches_orig = {k: v for k, v in orig_to_obf.items()  if name in k}

        all_matches = [
            {"query": k, "result": v, "direction": "obf_to_original"}
            for k, v in matches_obf.items()
        ] + [
            {"query": k, "result": v, "direction": "original_to_obf"}
            for k, v in matches_orig.items()
        ]

        if all_matches:
            return {
                "status": "ok",
                "data": {
                    "input": name,
                    "found": False,
                    "exact_match": False,
                    "partial_matches": all_matches[:20],
                    "partial_match_count": len(all_matches),
                    "message": (
                        f"No exact match; found {len(all_matches)} partial match(es)."
                    ),
                },
            }

        return {
            "status": "ok",
            "data": {
                "input": name,
                "found": False,
                "message": (
                    f"'{name}' not found in the loaded mapping. "
                    "Ensure load_mapping has been called and the name is correct."
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
            "message": f"Failed to deobfuscate name: {exc}",
            "suggestion": "Ensure the name is a valid class or member string.",
        }


@mcp.tool()
def detect_obfuscation(session_id: str) -> dict:
    """Analyse class naming patterns to detect what obfuscator was used.

    Examines all class names in the APK and applies a set of heuristics to
    estimate the obfuscation tool and coverage level:

    * **R8/ProGuard** — single-letter or sequential-alphabetic names
      (``a``, ``b``, …, ``aa``, ``ab``, …)
    * **DexGuard** — short mixed-case names (``aB``, ``cD``)
    * **Custom** — high-entropy medium-length names with no obvious pattern
    * **None** — names appear human-readable

    Additionally computes:
    * Obfuscated class ratio
    * Average simple class name length
    * Shannon entropy of the character distribution across all class names

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        ``{"obfuscator", "confidence", "obfuscated_class_ratio",
           "avg_name_length", "entropy", "single_char_ratio",
           "short_name_ratio", "total_classes", "sample_classes"}``
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        # Collect all class names (Java dotted form)
        all_classes: list[str] = []
        try:
            for ca in analysis.get_classes():
                try:
                    raw = ca.name
                    if raw.startswith("L") and raw.endswith(";"):
                        raw = raw[1:-1]
                    java_name = raw.replace("/", ".")
                    all_classes.append(java_name)
                except Exception:
                    continue
        except Exception as exc:
            return {
                "status": "error",
                "message": f"Failed to enumerate classes: {exc}",
                "suggestion": "Ensure the APK was loaded successfully.",
            }

        if not all_classes:
            return {
                "status": "error",
                "message": "No classes found in the APK.",
                "suggestion": "Verify the APK was loaded correctly with load_apk.",
            }

        heuristics = _obfuscation_heuristics(all_classes)

        # Provide a small sample of class names for manual inspection
        # Prefer short names as they are most diagnostic
        sample = sorted(all_classes, key=lambda n: len(n.rsplit(".", 1)[-1]))[:15]

        return {
            "status": "ok",
            "data": {
                **heuristics,
                "total_classes": len(all_classes),
                "sample_classes": sample,
                "has_mapping_loaded": bool(_get_obf_to_original(session)),
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
            "message": f"Failed to detect obfuscation: {exc}",
            "suggestion": "Ensure the APK was loaded successfully.",
        }
