"""Protobuf / gRPC schema extraction tools.

Reconstructs ``.proto`` definitions from generated Java/Kotlin protobuf classes
baked into DEX bytecode.  Generated classes follow predictable patterns that
this module exploits:

- Message classes extend ``GeneratedMessageLite`` / ``GeneratedMessageV3``
- Field serialisation happens in ``writeTo(CodedOutputStream)`` with calls like
  ``output.writeString(fieldNum, value)``
- Enum classes implement ``EnumLite`` or extend ``ProtocolMessageEnum``
- gRPC stubs extend ``AbstractStub`` and declare ``MethodDescriptor`` constants
  whose string name encodes the full service path
  ``"/package.ServiceName/MethodName"``
"""

from __future__ import annotations

import re
import traceback

from apksaw.server import mcp
from apksaw.session import get_session

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Superclass simple names that indicate a generated protobuf message class
_PROTO_MESSAGE_SUPERS = frozenset(
    {
        "GeneratedMessageLite",
        "GeneratedMessageV3",
        "AbstractMessageLite",
        "ExtendableMessageLite",
        "ExtendableMessage",
    }
)

# Superclass simple names that indicate a gRPC stub
_GRPC_STUB_SUPERS = frozenset({"AbstractStub", "AbstractBlockingStub", "AbstractFutureStub"})

# Interface simple names that indicate a proto enum
_PROTO_ENUM_IFACES = frozenset({"EnumLite", "ProtocolMessageEnum", "Internal.EnumLite"})

# Map CodedOutputStream write-method names to proto3 field types
_WRITE_METHOD_TO_PROTO_TYPE: dict[str, str] = {
    "writeString": "string",
    "writeInt32": "int32",
    "writeInt64": "int64",
    "writeUInt32": "uint32",
    "writeUInt64": "uint64",
    "writeSInt32": "sint32",
    "writeSInt64": "sint64",
    "writeFixed32": "fixed32",
    "writeFixed64": "fixed64",
    "writeSFixed32": "sfixed32",
    "writeSFixed64": "sfixed64",
    "writeBool": "bool",
    "writeFloat": "float",
    "writeDouble": "double",
    "writeBytes": "bytes",
    "writeMessage": "message",
    "writeEnum": "enum",
    "writeGroup": "group",
    # repeated helpers (singular write inside a loop)
    "writeRepeatedString": "string",
    "writeRepeatedInt32": "int32",
    "writeRepeatedInt64": "int64",
    "writeRepeatedBool": "bool",
    "writeRepeatedFloat": "float",
    "writeRepeatedDouble": "double",
    "writeRepeatedBytes": "bytes",
    "writeRepeatedMessage": "message",
    "writeRepeatedEnum": "enum",
    # packed variants
    "writePackedInt32": "int32",
    "writePackedInt64": "int64",
    "writePackedBool": "bool",
    "writePackedFloat": "float",
    "writePackedDouble": "double",
    "writePackedEnum": "enum",
    # messageSetExtension
    "writeMessageNoTag": "message",
}

# Regex: Smali invoke-virtual or invoke-interface containing a CodedOutputStream write call
# Captures: (writeMethodName)
_RE_WRITE_CALL = re.compile(
    r"invoke-(?:virtual|interface)\s+[^,]+(?:,\s*[^,]+)*,\s*"
    r"(?:com/google/protobuf/)?CodedOutputStream->(\w+)"
)

# Regex: const/4 or const/16 or const instruction loading an integer literal into a register
# e.g.  const/4 v0, 0x1    or   const v0, 0x5
_RE_CONST_INT = re.compile(
    r"^\s*const(?:/4|/16|/high16|)?\s+(\w+)\s*,\s*(-?0x[\da-fA-F]+|-?\d+)"
)

# Regex: iget-* to extract a field name from "this.fieldName_" pattern
# e.g.  iget-object v2, p0, Lcom/example/Foo;->userId_:Ljava/lang/String;
_RE_IGET_FIELD = re.compile(
    r"^\s*iget(?:-\w+)?\s+(\w+),\s*\w+,\s*L[\w/$]+;->([\w$]+):"
)

# Regex: gRPC service path  "/package.ServiceName/MethodName"
_RE_GRPC_PATH = re.compile(r"^/[\w.]+/\w+$")

# Regex: strip trailing underscore from generated proto field names
_RE_TRAILING_UNDERSCORE = re.compile(r"_+$")

# ---------------------------------------------------------------------------
# Name conversion helpers
# ---------------------------------------------------------------------------


def _dalvik_to_java(name: str) -> str:
    """Convert Dalvik class descriptor to dotted Java name."""
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def _simple_name(dalvik_or_java: str) -> str:
    """Return the simple (unqualified) class name."""
    java = _dalvik_to_java(dalvik_or_java)
    # Handle inner classes: Foo$Bar -> Bar
    return java.rsplit(".", 1)[-1].rsplit("$", 1)[-1]


def _proto_message_name(dalvik_class: str) -> str:
    """Best-effort proto message name from a generated class name.

    Generated inner class path: ``Lcom/example/proto/UserProfile;`` -> ``UserProfile``
    Handles ``$`` inner-class separators: ``Lcom/example/Outer$Inner;`` -> ``Inner``
    """
    return _simple_name(dalvik_class)


def _camel_to_snake(name: str) -> str:
    """Convert camelCase / PascalCase to snake_case for field names."""
    # Strip trailing underscores first (generated proto fields end in _)
    name = _RE_TRAILING_UNDERSCORE.sub("", name)
    s1 = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s2 = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s1)
    return s2.lower()


# ---------------------------------------------------------------------------
# Superclass / interface inspection helpers
# ---------------------------------------------------------------------------


def _get_superclass_simple(class_analysis) -> str:
    """Return the simple name of the direct superclass, or empty string."""
    try:
        vm = class_analysis.get_vm_class()
        raw = vm.get_superclassname()  # e.g. "Lcom/google/protobuf/GeneratedMessageLite;"
        if raw:
            return _simple_name(raw)
    except Exception:
        pass
    return ""


def _get_interfaces_simple(class_analysis) -> list[str]:
    """Return list of simple interface names implemented by this class."""
    try:
        vm = class_analysis.get_vm_class()
        raw_list = vm.get_interfaces() or []
        return [_simple_name(i) for i in raw_list]
    except Exception:
        return []


def _superclass_chain_includes(class_analysis, analysis, targets: frozenset[str]) -> bool:
    """Walk up to 6 levels of superclass chain checking for target simple names."""
    current = class_analysis
    for _ in range(6):
        super_simple = _get_superclass_simple(current)
        if not super_simple:
            break
        if super_simple in targets:
            return True
        # Try to resolve the parent class
        try:
            vm = current.get_vm_class()
            raw_super = vm.get_superclassname()
            if not raw_super:
                break
            parent = None
            for ca in analysis.find_classes(name=re.escape(raw_super)):
                parent = ca
                break
            if parent is None or parent.is_external():
                break
            current = parent
        except Exception:
            break
    return False


def _implements_any(class_analysis, targets: frozenset[str]) -> bool:
    """Return True if the class directly implements any of the target interfaces."""
    return bool(set(_get_interfaces_simple(class_analysis)) & targets)


# ---------------------------------------------------------------------------
# Instruction-level parsing helpers
# ---------------------------------------------------------------------------


def _get_instructions(class_analysis, method_name: str) -> list[str]:
    """Return a list of smali instruction strings for a named method."""
    for ma in class_analysis.get_methods():
        if ma.name != method_name:
            continue
        if ma.is_external():
            continue
        try:
            em = ma.get_method()
            code = em.get_code()
            if code is None:
                continue
            return [str(instr) for instr in code.get_bc().get_instructions()]
        except Exception:
            continue
    return []


def _parse_write_to_fields(instructions: list[str]) -> list[dict]:
    """Parse smali instructions from a ``writeTo`` method and extract field info.

    Strategy:
    1. Walk instructions sequentially tracking register -> integer constant mappings.
    2. When a CodedOutputStream->write* call is seen, look back through recent
       const assignments for the field number register.
    3. Extract the field name from accompanying iget instructions that load the value.

    Returns a list of field dicts:
      {"number": int, "name": str, "type": str, "repeated": bool}
    """
    # Register -> most recently assigned int constant
    reg_consts: dict[str, int] = {}
    # Register -> most recently loaded field name
    reg_field_names: dict[str, str] = {}

    fields: list[dict] = []
    seen_numbers: set[int] = set()

    for instr_str in instructions:
        instr_str = instr_str.strip()

        # Track const assignments: const/4 v0, 0x1
        m = _RE_CONST_INT.match(instr_str)
        if m:
            reg, val_str = m.group(1), m.group(2)
            try:
                reg_consts[reg] = int(val_str, 16) if val_str.startswith(("0x", "-0x")) else int(val_str)
            except ValueError:
                pass
            continue

        # Track iget instructions loading instance fields
        m = _RE_IGET_FIELD.match(instr_str)
        if m:
            dest_reg, field_name = m.group(1), m.group(2)
            reg_field_names[dest_reg] = field_name
            continue

        # Look for write* calls
        m = _RE_WRITE_CALL.search(instr_str)
        if not m:
            continue

        write_method = m.group(1)
        proto_type = _WRITE_METHOD_TO_PROTO_TYPE.get(write_method)
        if proto_type is None:
            continue

        repeated = write_method.startswith("writeRepeated") or write_method.startswith("writePackedI") or write_method.startswith("writePackedB") or write_method.startswith("writePackedF") or write_method.startswith("writePackedD") or write_method.startswith("writePackedE")

        # Extract register arguments from the invoke instruction
        # Format: invoke-virtual {vA, vB, vC, ...}, Class->method
        args_match = re.search(r"\{([^}]*)\}", instr_str)
        arg_regs: list[str] = []
        if args_match:
            arg_regs = [r.strip() for r in args_match.group(1).split(",") if r.strip()]

        # For CodedOutputStream.writeXxx(int fieldNumber, T value):
        #   arg_regs[0] = 'this' (the output stream object)
        #   arg_regs[1] = fieldNumber register
        #   arg_regs[2] = value register
        field_number: int | None = None
        field_name = ""

        if len(arg_regs) >= 2:
            num_reg = arg_regs[1]
            field_number = reg_consts.get(num_reg)

        if len(arg_regs) >= 3:
            val_reg = arg_regs[2]
            field_name = reg_field_names.get(val_reg, "")

        if field_number is None:
            # Also try scanning the last few const instructions for any int in a small range
            # Fall back: use the largest const seen recently that looks like a field number
            candidates = [v for v in reg_consts.values() if 1 <= v <= 536870911]
            if candidates:
                field_number = max(candidates)

        if field_number is None or field_number <= 0:
            continue

        if field_number in seen_numbers:
            continue
        seen_numbers.add(field_number)

        # Clean up field name: strip trailing underscores and convert to snake_case
        if field_name:
            field_name = _camel_to_snake(field_name)
        else:
            field_name = f"field_{field_number}"

        fields.append(
            {
                "number": field_number,
                "name": field_name,
                "type": proto_type,
                "repeated": repeated,
            }
        )

    # Sort by field number
    fields.sort(key=lambda f: f["number"])
    return fields


# ---------------------------------------------------------------------------
# Proto message extraction
# ---------------------------------------------------------------------------


def _extract_messages(analysis) -> list[dict]:
    """Find all proto message classes and reconstruct their field definitions."""
    messages: list[dict] = []
    seen_classes: set[str] = set()

    for class_analysis in analysis.get_classes():
        if class_analysis.is_external():
            continue

        dalvik_name = class_analysis.name

        # Skip inner Builder classes — they're not the message itself
        simple = _simple_name(dalvik_name)
        if simple in ("Builder", "Parser", "GeneratedExtension"):
            continue

        # Check direct superclass first (fast path)
        super_simple = _get_superclass_simple(class_analysis)
        is_proto_message = super_simple in _PROTO_MESSAGE_SUPERS

        # Slower: walk superclass chain if direct super not recognised
        if not is_proto_message:
            is_proto_message = _superclass_chain_includes(
                class_analysis, analysis, _PROTO_MESSAGE_SUPERS
            )

        if not is_proto_message:
            continue

        java_class = _dalvik_to_java(dalvik_name)
        if java_class in seen_classes:
            continue
        seen_classes.add(java_class)

        # Parse the writeTo method for field definitions
        instructions = _get_instructions(class_analysis, "writeTo")
        fields = _parse_write_to_fields(instructions)

        # If writeTo not found, try dynamicMethod (Lite runtime uses a switch)
        if not fields:
            instructions = _get_instructions(class_analysis, "dynamicMethod")
            fields = _parse_write_to_fields(instructions)

        messages.append(
            {
                "name": _proto_message_name(dalvik_name),
                "java_class": java_class,
                "fields": fields,
            }
        )

    return messages


# ---------------------------------------------------------------------------
# Proto enum extraction
# ---------------------------------------------------------------------------


def _extract_enum_values(class_analysis) -> list[dict]:
    """Extract enum values from a proto enum class.

    Protobuf-generated enum classes have static final int fields named after
    each value (e.g., ``ACTIVE_VALUE = 0``) alongside the object fields.
    We prefer the ``*_VALUE`` int constants for reliable number extraction.
    Also handles static fields of the enum's own type.
    """
    values: list[dict] = []
    seen_names: set[str] = set()

    if class_analysis.is_external():
        return values

    try:
        vm_class = class_analysis.get_vm_class()
    except Exception:
        return values

    # Walk static fields
    for field in (vm_class.get_fields() or []):
        try:
            flags = field.get_access_flags_string() or ""
            if "static" not in flags:
                continue
            fname = field.get_name()
            ftype = field.get_descriptor()

            # Prefer *_VALUE int fields (they carry the number directly)
            if fname.endswith("_VALUE") and ftype in ("I", "J"):
                base_name = fname[: -len("_VALUE")]
                if base_name in seen_names:
                    continue
                seen_names.add(base_name)
                # Try to read the initial value from the class's static init
                # We can't easily read the integer without running the code,
                # so we just record position from ordering.
                values.append({"name": base_name, "number": None})

        except Exception:
            continue

    # If we couldn't get numbers, assign sequential 0-based values
    for idx, v in enumerate(values):
        if v["number"] is None:
            v["number"] = idx

    return values


def _extract_enums(analysis) -> list[dict]:
    """Find all proto enum classes and extract their values."""
    enums: list[dict] = []
    seen_classes: set[str] = set()

    for class_analysis in analysis.get_classes():
        if class_analysis.is_external():
            continue

        # Check if implements EnumLite or ProtocolMessageEnum
        ifaces = _get_interfaces_simple(class_analysis)
        is_enum = bool(set(ifaces) & _PROTO_ENUM_IFACES)

        # Also check if the class itself is declared as an enum (access flags)
        if not is_enum:
            try:
                vm = class_analysis.get_vm_class()
                flags = vm.get_access_flags_string() or ""
                is_enum = "enum" in flags and bool(set(ifaces) & {"EnumLite"})
            except Exception:
                pass

        # Final check: superclass named ProtocolMessageEnum
        if not is_enum:
            super_simple = _get_superclass_simple(class_analysis)
            is_enum = super_simple in {"ProtocolMessageEnum"}

        if not is_enum:
            continue

        dalvik_name = class_analysis.name
        java_class = _dalvik_to_java(dalvik_name)
        if java_class in seen_classes:
            continue
        seen_classes.add(java_class)

        values = _extract_enum_values(class_analysis)
        enums.append(
            {
                "name": _proto_message_name(dalvik_name),
                "java_class": java_class,
                "values": values,
            }
        )

    return enums


# ---------------------------------------------------------------------------
# gRPC service extraction
# ---------------------------------------------------------------------------


def _parse_grpc_path(path: str) -> tuple[str, str]:
    """Split ``/package.ServiceName/MethodName`` into (service_name, method_name)."""
    # e.g. "/chat.v1.ChatService/SendMessage"
    parts = path.lstrip("/").split("/", 1)
    if len(parts) == 2:
        svc_full, method = parts
        return svc_full, method
    return path, ""


def _extract_services_from_strings(analysis) -> dict[str, dict]:
    """Scan the DEX string pool for gRPC service path strings.

    Returns a dict keyed by ``full_service_name`` mapping to:
    ``{"name": str, "full_name": str, "methods": [{"name": str, "full_path": str}]}``
    """
    services: dict[str, dict] = {}

    for sa in analysis.get_strings():
        value = sa.get_value()
        if not _RE_GRPC_PATH.match(value):
            continue

        full_svc, method_name = _parse_grpc_path(value)
        if not full_svc or not method_name:
            continue

        svc_simple = full_svc.rsplit(".", 1)[-1]

        if full_svc not in services:
            services[full_svc] = {
                "name": svc_simple,
                "full_name": full_svc,
                "java_class": "",
                "methods": [],
            }

        # Avoid duplicate methods
        existing_methods = {m["name"] for m in services[full_svc]["methods"]}
        if method_name not in existing_methods:
            services[full_svc]["methods"].append(
                {
                    "name": method_name,
                    "full_path": value,
                    "input_type": "",
                    "output_type": "",
                }
            )

    return services


def _enrich_services_from_stub_classes(analysis, services: dict[str, dict]) -> None:
    """Walk gRPC stub classes (AbstractStub subclasses) to attach java_class and
    attempt to resolve input/output types from MethodDescriptor fields."""

    # We'll also look for classes with 'Grpc' in the name as a heuristic
    for class_analysis in analysis.get_classes():
        if class_analysis.is_external():
            continue

        dalvik_name = class_analysis.name
        java_class = _dalvik_to_java(dalvik_name)
        simple = _simple_name(dalvik_name)

        super_simple = _get_superclass_simple(class_analysis)
        is_stub = (
            super_simple in _GRPC_STUB_SUPERS
            or "Grpc" in simple
            or _superclass_chain_includes(class_analysis, analysis, _GRPC_STUB_SUPERS)
        )

        if not is_stub:
            continue

        # Match this stub to a service by name similarity
        for svc_key, svc in services.items():
            svc_simple = svc["name"]
            # e.g. ChatServiceGrpc matches ChatService
            if svc_simple in simple or simple.replace("Grpc", "") == svc_simple:
                if not svc["java_class"]:
                    svc["java_class"] = java_class

                # Try to pick up input/output types from static MethodDescriptor fields
                try:
                    vm = class_analysis.get_vm_class()
                    for field in (vm.get_fields() or []):
                        fname = field.get_name() or ""
                        ftype = field.get_descriptor() or ""
                        # MethodDescriptor field names often match the RPC method name
                        if "MethodDescriptor" in ftype:
                            for method_entry in svc["methods"]:
                                if (
                                    method_entry["name"].lower() in fname.lower()
                                    or fname.lower() in method_entry["name"].lower()
                                ):
                                    # We can't easily resolve the generic types from bytecode,
                                    # so leave them as a hint
                                    if not method_entry["input_type"]:
                                        method_entry["input_type"] = f"(see {java_class}.{fname})"
                except Exception:
                    pass


def _extract_services(analysis) -> list[dict]:
    """Combine string-pool discovery and stub-class enrichment for gRPC services."""
    services_map = _extract_services_from_strings(analysis)
    _enrich_services_from_stub_classes(analysis, services_map)
    return list(services_map.values())


# ---------------------------------------------------------------------------
# Proto text generation
# ---------------------------------------------------------------------------


def _generate_proto_text(messages: list[dict], enums: list[dict], services: list[dict]) -> str:
    """Generate a proto3 text representation from extracted schemas."""
    lines: list[str] = [
        "// Reconstructed .proto — generated by apksaw protobuf extractor",
        "// WARNING: field names and some types are best-effort approximations.",
        'syntax = "proto3";',
        "",
    ]

    # Enums
    for enum in enums:
        lines.append(f"enum {enum['name']} {{")
        for val in enum["values"]:
            lines.append(f"  {val['name']} = {val['number']};")
        if not enum["values"]:
            lines.append("  // (no values extracted)")
        lines.append("}")
        lines.append("")

    # Messages
    for msg in messages:
        lines.append(f"message {msg['name']} {{")
        for f in msg["fields"]:
            repeated_kw = "repeated " if f["repeated"] else ""
            proto_type = f["type"]
            lines.append(f"  {repeated_kw}{proto_type} {f['name']} = {f['number']};")
        if not msg["fields"]:
            lines.append("  // (no fields extracted — writeTo not found or empty)")
        lines.append("}")
        lines.append("")

    # Services
    for svc in services:
        lines.append(f"service {svc['name']} {{")
        for method in svc["methods"]:
            in_type = method["input_type"] or "google.protobuf.Any"
            out_type = method["output_type"] or "google.protobuf.Any"
            lines.append(f"  rpc {method['name']} ({in_type}) returns ({out_type});")
        if not svc["methods"]:
            lines.append("  // (no methods extracted)")
        lines.append("}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


@mcp.tool()
def extract_protobuf_schemas(session_id: str) -> dict:
    """Extract protobuf message definitions from generated classes in the APK.

    Finds classes whose superclass chain includes ``GeneratedMessageLite``,
    ``GeneratedMessageV3``, or ``AbstractMessageLite``, then analyses their
    ``writeTo(CodedOutputStream)`` (and ``dynamicMethod`` for the Lite runtime)
    methods to reconstruct field numbers and types.

    Also finds:
    - Enum classes implementing ``EnumLite`` / ``ProtocolMessageEnum``
    - gRPC service path strings in the DEX string pool
    - gRPC stub classes extending ``AbstractStub``

    The ``proto_text`` field in the response contains a complete,
    syntactically valid ``.proto3`` file that can be fed to ``protoc`` or
    gRPC tooling for API analysis and fuzzing.

    Args:
        session_id: Active analysis session ID returned by ``load_apk``.

    Returns:
        dict with status and data containing messages, enums, services, proto_text.
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        messages = _extract_messages(analysis)
        enums = _extract_enums(analysis)
        services = _extract_services(analysis)

        proto_text = _generate_proto_text(messages, enums, services)

        return {
            "status": "ok",
            "data": {
                "messages": messages,
                "enums": enums,
                "services": services,
                "proto_text": proto_text,
                "total_messages": len(messages),
                "total_enums": len(enums),
                "total_services": len(services),
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
            "traceback": traceback.format_exc(),
            "suggestion": "Ensure the session is valid and the APK was successfully loaded.",
        }


@mcp.tool()
def find_grpc_services(session_id: str) -> dict:
    """Find all gRPC service definitions and their RPC methods.

    Uses two complementary strategies:

    1. **String pool scan** — searches every DEX string for patterns matching
       ``/package.ServiceName/MethodName`` (the canonical gRPC full method
       name format).

    2. **Stub class scan** — finds classes extending ``AbstractStub``,
       ``AbstractBlockingStub``, or ``AbstractFutureStub`` (and classes with
       ``Grpc`` in their name) to attach Java class names and attempt to
       resolve ``MethodDescriptor`` field types.

    Args:
        session_id: Active analysis session ID returned by ``load_apk``.

    Returns:
        dict: ``{"status": "ok", "data": {"services": [...], "total": N}}``

        Each service entry contains:
        - ``name``       — simple service name (e.g. ``ChatService``)
        - ``full_name``  — fully qualified name (e.g. ``chat.v1.ChatService``)
        - ``java_class`` — Java class of the stub, if found
        - ``methods``    — list of ``{"name", "full_path", "input_type", "output_type"}``
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        services_map = _extract_services_from_strings(analysis)
        _enrich_services_from_stub_classes(analysis, services_map)
        services = list(services_map.values())

        return {
            "status": "ok",
            "data": {
                "services": services,
                "total": len(services),
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
            "traceback": traceback.format_exc(),
            "suggestion": "Ensure the session is valid and the APK was successfully loaded.",
        }


@mcp.tool()
def export_proto_file(session_id: str, package_filter: str = "") -> dict:
    """Generate a .proto file from extracted schemas and save it to the session workspace.

    Runs the full extraction (``extract_protobuf_schemas`` logic) then writes
    the result to ``<workspace>/proto/reconstructed.proto``.

    Optionally filter to a specific Java package prefix so only types from
    that namespace appear in the output (useful for large apps with many
    vendored proto libraries).

    Args:
        session_id: Active analysis session ID returned by ``load_apk``.
        package_filter: Optional Java package prefix to restrict output
                        (e.g. ``"com.example.myapp"``).  When empty, all
                        extracted types are included.

    Returns:
        dict: ``{"status": "ok", "data": {"proto_file": "...", "total_messages": N,
              "total_enums": N, "total_services": N}}``
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        messages = _extract_messages(analysis)
        enums = _extract_enums(analysis)
        services = _extract_services(analysis)

        # Apply package filter
        if package_filter:
            pkg = package_filter.rstrip(".")
            messages = [m for m in messages if m["java_class"].startswith(pkg)]
            enums = [e for e in enums if e["java_class"].startswith(pkg)]
            # Services are matched by any method referencing a filtered class; keep all
            # since service paths are independent of Java package structure.

        proto_text = _generate_proto_text(messages, enums, services)

        # Write to workspace
        proto_dir = session.workspace / "proto"
        proto_dir.mkdir(parents=True, exist_ok=True)
        proto_file = proto_dir / "reconstructed.proto"
        proto_file.write_text(proto_text, encoding="utf-8")

        return {
            "status": "ok",
            "data": {
                "proto_file": str(proto_file),
                "proto_text": proto_text,
                "total_messages": len(messages),
                "total_enums": len(enums),
                "total_services": len(services),
                "package_filter": package_filter or "(none)",
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
            "traceback": traceback.format_exc(),
            "suggestion": "Ensure the session is valid and the APK was successfully loaded.",
        }
