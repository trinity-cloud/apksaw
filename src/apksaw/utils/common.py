"""Shared utility helpers for Dalvik/Java name conversion.

These functions are used across multiple tools (dex.py, xrefs.py, etc.).
Import from here rather than duplicating in each module.
"""


def dalvik_to_java(name: str) -> str:
    """Convert a Dalvik type descriptor to a Java-style class name.

    Handles both the standard ``L...;`` form and the already-converted
    dot-notation form gracefully.

    Examples:
        ``Lcom/example/Foo;``     -> ``com.example.Foo``
        ``Lcom/example/Foo$Bar;`` -> ``com.example.Foo$Bar``
        ``com.example.Foo``       -> ``com.example.Foo``  (passthrough)
    """
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def java_to_dalvik(name: str) -> str:
    """Convert a Java-style class name to a Dalvik type descriptor.

    Already-Dalvik names are passed through unchanged.

    Examples:
        ``com.example.Foo``   -> ``Lcom/example/Foo;``
        ``Lcom/example/Foo;`` -> ``Lcom/example/Foo;``  (passthrough)
    """
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"


def normalize_class_name(name: str) -> str:
    """Coerce a class name in either format to canonical Dalvik form.

    Accepts Java-style (``com.example.Foo``) or Dalvik-style
    (``Lcom/example/Foo;``) input and always returns the Dalvik form
    suitable for Androguard lookups.

    Examples:
        ``com.example.Foo``   -> ``Lcom/example/Foo;``
        ``Lcom/example/Foo;`` -> ``Lcom/example/Foo;``
    """
    name = name.strip()
    if name.startswith("L") and name.endswith(";"):
        return name
    return java_to_dalvik(name)
