"""YARA rule scanning tools for Android APK analysis."""

import zipfile
from pathlib import Path
from typing import Any

from apksaw.server import mcp
from apksaw.session import get_session

# Rules directory is two levels up from this file: src/apksaw/rules/
_RULES_DIR = Path(__file__).parent.parent / "rules"

# Canonical rule set names and their corresponding .yar files
_RULE_SETS: dict[str, str] = {
    "credentials": "credentials.yar",
    "crypto":      "crypto.yar",
    "obfuscation": "obfuscation.yar",
    "suspicious":  "suspicious.yar",
}

# Severity ordering for sorting
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Files inside the APK zip that we always want to scan
_MANIFEST_ENTRY   = "AndroidManifest.xml"
_DEX_SUFFIX       = ".dex"
_SO_SUFFIX        = ".so"
_ASSETS_PREFIX    = "assets/"
_LIB_PREFIX       = "lib/"

# Max bytes to scan per file (16 MB) — keeps memory usage bounded for huge DEX
_MAX_SCAN_BYTES = 16 * 1024 * 1024


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_ruleset(name: str):
    """Load and compile a single YARA rule set by name.

    Returns a compiled ``yara.Rules`` object or raises ``FileNotFoundError`` /
    ``yara.SyntaxError`` if the file is missing or broken.
    """
    try:
        import yara  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "yara-python is not installed. Run: pip install yara-python"
        ) from exc

    if name not in _RULE_SETS:
        raise KeyError(f"Unknown rule set '{name}'. Available: {list(_RULE_SETS)}")

    rule_file = _RULES_DIR / _RULE_SETS[name]
    if not rule_file.exists():
        raise FileNotFoundError(f"Rule file not found: {rule_file}")

    return yara.compile(str(rule_file))


def _load_all_rulesets() -> dict[str, Any]:
    """Load all available rule sets. Returns a mapping name -> compiled Rules."""
    try:
        import yara  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "yara-python is not installed. Run: pip install yara-python"
        ) from exc

    compiled: dict[str, Any] = {}
    for name, filename in _RULE_SETS.items():
        rule_file = _RULES_DIR / filename
        if rule_file.exists():
            compiled[name] = yara.compile(str(rule_file))
    return compiled


def _load_custom_rules(path: str) -> Any:
    """Compile a user-supplied YARA rule file."""
    try:
        import yara  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "yara-python is not installed. Run: pip install yara-python"
        ) from exc

    rule_path = Path(path)
    if not rule_path.exists():
        raise FileNotFoundError(f"Custom rules file not found: {path}")
    return yara.compile(str(rule_path))


def _scan_data(rules_map: dict[str, Any], data: bytes, source_file: str) -> list[dict]:
    """Run all compiled rule sets against *data* and return match dicts."""
    matches: list[dict] = []

    for ruleset_name, compiled_rules in rules_map.items():
        try:
            hits = compiled_rules.match(data=data)
        except Exception:  # noqa: BLE001
            continue

        for hit in hits:
            severity = hit.meta.get("severity", "info")
            description = hit.meta.get("description", "")

            matched_strings: list[dict] = []
            for string_match in hit.strings:
                # string_match is a StringMatch with .identifier, .instances
                identifier = string_match.identifier
                for instance in string_match.instances:
                    matched_strings.append(
                        {
                            "identifier": identifier,
                            "offset": instance.offset,
                            "matched_data": _safe_decode(bytes(instance.matched_data)[:128]),
                        }
                    )

            matches.append(
                {
                    "rule": hit.rule,
                    "ruleset": ruleset_name,
                    "severity": severity,
                    "description": description,
                    "file": source_file,
                    "matched_strings": matched_strings,
                    "tags": list(hit.tags),
                    "meta": dict(hit.meta),
                }
            )

    return matches


def _safe_decode(data: bytes) -> str:
    """Decode bytes to a printable string, escaping non-printable bytes."""
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return data.hex()


def _select_rulesets(rule_set: str, custom_path: str) -> dict[str, Any]:
    """Return a compiled rules map based on *rule_set* selector and optional custom path."""
    compiled: dict[str, Any] = {}

    if custom_path:
        compiled["custom"] = _load_custom_rules(custom_path)
        # custom_path always supplements; if rule_set is "" we only run custom
        if not rule_set or rule_set == "custom":
            return compiled

    if rule_set == "all":
        compiled.update(_load_all_rulesets())
    elif rule_set in _RULE_SETS:
        compiled[rule_set] = _load_ruleset(rule_set)
    elif rule_set == "malware":
        # "malware" is an alias for obfuscation + suspicious combined
        for name in ("obfuscation", "suspicious"):
            if (_RULES_DIR / _RULE_SETS[name]).exists():
                compiled[name] = _load_ruleset(name)
    else:
        raise ValueError(
            f"Unknown rule_set '{rule_set}'. "
            f"Use: 'all', 'malware', 'credentials', 'crypto', 'obfuscation', 'suspicious'."
        )

    return compiled


def _collect_apk_components(apk_path: Path) -> list[tuple[str, bytes]]:
    """Open the APK zip and yield (entry_name, bytes) for scannable components.

    Scans:
    - AndroidManifest.xml
    - classes*.dex
    - lib/**/*.so  (native libraries)
    - assets/**    (arbitrary assets)
    """
    components: list[tuple[str, bytes]] = []

    try:
        with zipfile.ZipFile(str(apk_path), "r") as zf:
            for info in zf.infolist():
                name = info.filename
                # Skip directories
                if name.endswith("/"):
                    continue

                should_scan = (
                    name == _MANIFEST_ENTRY
                    or name.endswith(_DEX_SUFFIX)
                    or (name.startswith(_LIB_PREFIX) and name.endswith(_SO_SUFFIX))
                    or name.startswith(_ASSETS_PREFIX)
                )

                if not should_scan:
                    continue

                try:
                    raw = zf.read(name)
                    # Clamp to avoid OOM on huge files
                    if len(raw) > _MAX_SCAN_BYTES:
                        raw = raw[:_MAX_SCAN_BYTES]
                    components.append((name, raw))
                except Exception:  # noqa: BLE001
                    continue  # skip unreadable entries silently
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Could not open APK as zip: {exc}") from exc

    return components


def _severity_counts(matches: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for m in matches:
        sev = m.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


@mcp.tool()
def scan_yara(
    session_id: str,
    rule_set: str = "all",
    custom_rules_path: str = "",
) -> dict:
    """Scan APK components with YARA rules.

    Extracts every scannable component from the APK zip archive and runs
    the selected YARA rules against the raw bytes of each component:

    - ``AndroidManifest.xml``
    - ``classes*.dex`` (Dalvik bytecode — all multidex shards)
    - ``lib/**/*.so`` (native shared libraries)
    - ``assets/**``   (all asset files)

    Each match records the rule name, rule set, severity, a human-readable
    description, the file within the APK where the match occurred, the byte
    offset, and the matched string snippet.

    Args:
        session_id:         Active analysis session ID returned by ``load_apk``.
        rule_set:           Which built-in rule set(s) to use. One of:
                            ``"all"`` (default), ``"malware"``, ``"credentials"``,
                            ``"crypto"``, ``"obfuscation"``, ``"suspicious"``.
                            ``"malware"`` is an alias for obfuscation + suspicious combined.
        custom_rules_path:  Optional path to a custom ``.yar`` file on disk.
                            If provided it is compiled and run alongside (or instead of,
                            when ``rule_set`` is empty) the built-in rules.

    Returns:
        dict: ``{"status": "ok", "data": {"matches": [...], "total": N,
                 "severity_counts": {...}, "scanned_files": [...]}}``

        Each match contains:
        - ``rule``            — YARA rule name
        - ``ruleset``         — source rule set (credentials / crypto / …)
        - ``severity``        — critical / high / medium / low / info
        - ``description``     — human-readable finding description
        - ``file``            — APK-relative path of the scanned file
        - ``matched_strings`` — list of ``{identifier, offset, matched_data}``
        - ``tags``            — YARA tags on the rule (if any)
        - ``meta``            — full YARA metadata dict
    """
    try:
        import yara  # noqa: F401  (trigger ImportError early with a nice message)
    except ImportError:
        return {
            "status": "error",
            "message": "yara-python is not installed.",
            "suggestion": "Run: pip install yara-python",
        }

    try:
        session = get_session(session_id)

        # Build the compiled rules map
        try:
            rules_map = _select_rulesets(rule_set or "all", custom_rules_path)
        except (KeyError, ValueError, FileNotFoundError) as exc:
            return {
                "status": "error",
                "message": str(exc),
                "suggestion": "Check rule_set name or custom_rules_path.",
            }
        except Exception as exc:  # noqa: BLE001 — yara.SyntaxError etc.
            return {
                "status": "error",
                "message": f"Failed to compile YARA rules: {exc}",
                "suggestion": "Check the YARA rule syntax in the rules/ directory.",
            }

        if not rules_map:
            return {
                "status": "error",
                "message": "No YARA rules could be loaded.",
                "suggestion": f"Ensure rule files exist in {_RULES_DIR}.",
            }

        # Collect APK components
        try:
            components = _collect_apk_components(session.apk_path)
        except ValueError as exc:
            return {
                "status": "error",
                "message": str(exc),
                "suggestion": "Ensure the APK file is a valid zip archive.",
            }

        scanned_files: list[str] = []
        all_matches: list[dict] = []

        for entry_name, data in components:
            scanned_files.append(entry_name)
            file_matches = _scan_data(rules_map, data, entry_name)
            all_matches.extend(file_matches)

        # Sort: critical first, then high, medium, low, info; then by rule name
        all_matches.sort(
            key=lambda m: (_SEV_ORDER.get(m["severity"], 99), m["rule"])
        )

        return {
            "status": "ok",
            "data": {
                "matches": all_matches,
                "total": len(all_matches),
                "severity_counts": _severity_counts(all_matches),
                "scanned_files": scanned_files,
                "rule_sets_used": list(rules_map.keys()),
            },
        }

    except KeyError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Call load_apk first to create a valid session.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error: {exc}",
            "suggestion": "Ensure the session is valid and the APK was successfully loaded.",
        }


@mcp.tool()
def list_yara_rules() -> dict:
    """List all available YARA rule sets and their individual rules.

    Reads every ``*.yar`` file from the rules directory, parses rule
    names and their ``meta`` blocks, and returns a structured inventory.
    No APK session is required.

    Returns:
        dict: ``{"status": "ok", "data": {"rule_sets": [...], "total_rules": N,
                 "rules_dir": "..."}}}``

        Each rule set entry contains:
        - ``name``        — rule set identifier used in ``scan_yara``
        - ``file``        — full path to the ``.yar`` file
        - ``rules``       — list of ``{name, severity, description}`` dicts
        - ``rule_count``  — number of rules in the set
    """
    import re as _re

    # Simple regex parser for YARA rule headers (no yara-python required)
    _RE_RULE_HEADER = _re.compile(r"^\s*rule\s+(\w+)\s*\{", _re.MULTILINE)
    _RE_META_BLOCK = _re.compile(
        r"rule\s+\w+\s*\{.*?meta\s*:\s*(.*?)(?:strings|condition)\s*:",
        _re.DOTALL,
    )
    _RE_META_PAIR = _re.compile(r'(\w+)\s*=\s*"([^"]*)"')

    try:
        rule_sets: list[dict] = []
        total_rules = 0

        for set_name, filename in _RULE_SETS.items():
            rule_file = _RULES_DIR / filename
            entry: dict = {
                "name": set_name,
                "file": str(rule_file),
                "rules": [],
                "rule_count": 0,
                "available": rule_file.exists(),
            }

            if not rule_file.exists():
                rule_sets.append(entry)
                continue

            try:
                content = rule_file.read_text(encoding="utf-8")
            except OSError:
                rule_sets.append(entry)
                continue

            # Find all rule names
            rule_names = _RE_RULE_HEADER.findall(content)

            # Parse meta blocks — split on "rule <Name>" boundaries
            # for each rule block, extract meta pairs
            rule_blocks = _re.split(r"(?=\brule\s+\w+\s*\{)", content)

            meta_by_name: dict[str, dict] = {}
            for block in rule_blocks:
                name_match = _RE_RULE_HEADER.search(block)
                if not name_match:
                    continue
                rule_name = name_match.group(1)
                meta: dict[str, str] = {}
                meta_match = _RE_META_BLOCK.search(block)
                if meta_match:
                    for k, v in _RE_META_PAIR.findall(meta_match.group(1)):
                        meta[k] = v
                meta_by_name[rule_name] = meta

            rules_list: list[dict] = []
            for rule_name in rule_names:
                meta = meta_by_name.get(rule_name, {})
                rules_list.append(
                    {
                        "name": rule_name,
                        "severity": meta.get("severity", "info"),
                        "description": meta.get("description", ""),
                    }
                )

            entry["rules"] = rules_list
            entry["rule_count"] = len(rules_list)
            total_rules += len(rules_list)
            rule_sets.append(entry)

        # Also surface any extra .yar files in the rules dir not in _RULE_SETS
        if _RULES_DIR.exists():
            known_files = set(_RULE_SETS.values())
            for extra_yar in sorted(_RULES_DIR.glob("*.yar")):
                if extra_yar.name not in known_files:
                    rule_sets.append(
                        {
                            "name": extra_yar.stem,
                            "file": str(extra_yar),
                            "rules": [],
                            "rule_count": 0,
                            "available": True,
                            "note": "Extra rule file (not in built-in rule_set list)",
                        }
                    )

        return {
            "status": "ok",
            "data": {
                "rule_sets": rule_sets,
                "total_rules": total_rules,
                "rules_dir": str(_RULES_DIR),
                "valid_rule_set_names": list(_RULE_SETS.keys()) + ["all", "malware"],
            },
        }

    except Exception as exc:  # noqa: BLE001
        return {
            "status": "error",
            "message": f"Unexpected error listing rules: {exc}",
            "suggestion": f"Ensure the rules directory exists at {_RULES_DIR}.",
        }
