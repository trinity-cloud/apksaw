# Decompilation Tools

Tools for navigating and decompiling Dalvik bytecode using Androguard.

## `list_classes`

List all class names in the APK. Supports a filter prefix (e.g., `com/example`).

```
list_classes(session_id="abc123", filter="com/example/payment")
→ ["com/example/payment/CardProcessor;", "com/example/payment/TokenVault;", ...]
```

## `list_methods`

List all methods in a given class with their descriptor strings.

```
list_methods(session_id="abc123", class_name="com/example/payment/CardProcessor;")
→ ["processCard(Ljava/lang/String;)V", "tokenize(...)Ljava/lang/String;", ...]
```

## `get_class_info`

Return fields, methods, superclass, interfaces, and access flags for a class.

```
get_class_info(session_id="abc123", class_name="Lcom/example/payment/CardProcessor;")
→ {"superclass": "...", "fields": [...], "methods": [...], "access_flags": "public"}
```

## `decompile_class`

Decompile an entire class to pseudo-Java source using Androguard's decompiler.

```
decompile_class(session_id="abc123", class_name="Lcom/example/payment/CardProcessor;")
→ "public class CardProcessor {\n    ..."
```

## `decompile_method`

Decompile a single method. Faster than `decompile_class` when you know the target.

```
decompile_method(
    session_id="abc123",
    class_name="Lcom/example/payment/CardProcessor;",
    method_name="processCard"
)
→ "public void processCard(String card) {\n    ..."
```
