# Cross-Reference Tools

Tools for tracing how code is connected — who calls what, who uses what.

## `get_xrefs_to`

Find all callers of a method (reverse call graph lookup).

```
get_xrefs_to(
    session_id="abc123",
    class_name="Lcom/example/Crypto;",
    method_name="encrypt"
)
→ [{"caller_class": "...", "caller_method": "...", "offset": 42}, ...]
```

## `get_xrefs_from`

Find all methods called by a given method (forward call graph).

```
get_xrefs_from(session_id="abc123", class_name="...", method_name="onCreate")
→ [{"callee_class": "...", "callee_method": "..."}, ...]
```

## `find_method_usage`

Search for usage of a method by simple name across all classes. Useful when you don't know the full class path.

```
find_method_usage(session_id="abc123", method_name="getSharedPreferences")
→ [{"class": "...", "method": "...", "line": 120}, ...]
```

## `get_call_graph`

Generate a call graph rooted at a given method, up to a configurable depth.

```
get_call_graph(session_id="abc123", class_name="...", method_name="processPayment", depth=3)
→ {"nodes": [...], "edges": [...]}
```

## `find_api_calls`

Find all calls to a specific Android or Java API class/method pattern.

```
find_api_calls(session_id="abc123", api="Ljava/net/HttpURLConnection;->openConnection")
```

## `search_code`

Full-text search across decompiled method bodies.
