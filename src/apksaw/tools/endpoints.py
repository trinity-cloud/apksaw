"""API endpoint extraction and auth interceptor detection tools."""

import re
from urllib.parse import urlparse

from apksaw.server import mcp
from apksaw.session import get_session

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# URLs that look like API endpoints (path segment starts with api/, v1, graphql, etc.)
_RE_API_URL = re.compile(
    r"https?://[^\s\"'<>]+/(?:api|v\d+|graphql|rest|ws|rpc|gql)(?:/[^\s\"'<>]*)?",
    re.IGNORECASE,
)

# Any http/https URL (broader sweep for base-URL detection)
_RE_HTTP_URL = re.compile(r"https?://[^\s\"'<>{}\[\]\\]+", re.IGNORECASE)

# Path parameter placeholders: {param} or :param
_RE_PATH_PARAM_BRACES = re.compile(r"\{(\w+)\}")
_RE_PATH_PARAM_COLON = re.compile(r"(?<=/):(\w+)")

# Format-string positional params in URL paths
_RE_FORMAT_PARAM = re.compile(r"%s|%d|%\d+\$s")

# HTTP verb annotations (Retrofit-style strings in DEX string pool)
_RETROFIT_VERB_ANNOTATIONS = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
    # Retrofit annotation class names also appear as strings
    "retrofit2/http/GET", "retrofit2/http/POST", "retrofit2/http/PUT",
    "retrofit2/http/DELETE", "retrofit2/http/PATCH",
}

# Annotation descriptor substrings for Retrofit HTTP verbs
_RETROFIT_ANNOTATION_DESCS = (
    "Lretrofit2/http/GET;",
    "Lretrofit2/http/POST;",
    "Lretrofit2/http/PUT;",
    "Lretrofit2/http/DELETE;",
    "Lretrofit2/http/PATCH;",
    "Lretrofit2/http/HEAD;",
    "Lretrofit2/http/OPTIONS;",
    "Lretrofit2/http/HTTP;",
)

# Auth-related header strings we look for inside interceptors
_AUTH_HEADER_PATTERNS = re.compile(
    r"Authorization|Bearer|X-Api-Key|X-API-KEY|X-Auth|X-Token|"
    r"api[_\-]?key|access[_\-]?token|secret[_\-]?key|client[_\-]?secret",
    re.IGNORECASE,
)

# OkHttp / Retrofit builder method names
_OKHTTP_BUILDER_CLASSES = (
    "okhttp3/OkHttpClient",
    "okhttp3/OkHttpClient$Builder",
    "retrofit2/Retrofit",
    "retrofit2/Retrofit$Builder",
)

_BASE_URL_METHODS = {"baseUrl", "setBaseUrl"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dalvik_to_java(name: str) -> str:
    """Convert Dalvik descriptor to dotted Java name."""
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def _extract_params(path: str) -> list[str]:
    """Return path parameters found in a URL path string."""
    params = _RE_PATH_PARAM_BRACES.findall(path)
    params += _RE_PATH_PARAM_COLON.findall(path)
    # format-string params get positional names
    fmt_count = len(_RE_FORMAT_PARAM.findall(path))
    for i in range(fmt_count):
        params.append(f"arg{i}")
    return list(dict.fromkeys(params))  # deduplicate, preserve order


def _parse_url(url: str) -> tuple[str, str]:
    """Return (base_url, path) for a URL string."""
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        if parsed.query:
            path = path + "?" + parsed.query
        return base, path
    except Exception:  # noqa: BLE001
        return url, "/"


def _verb_from_annotation_desc(desc: str) -> str:
    """Extract HTTP verb from a Retrofit annotation descriptor like Lretrofit2/http/GET;."""
    # e.g. "Lretrofit2/http/POST;" -> "POST"
    last = desc.rstrip(";").rsplit("/", 1)[-1]
    return last.upper() if last.upper() in {
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
    } else "UNKNOWN"


def _infer_auth_required(path: str, class_name: str) -> bool:
    """Heuristic: assume auth required unless path looks like login/register/health."""
    no_auth_keywords = re.compile(
        r"/(?:login|register|signup|sign-up|auth|oauth|token|health|status|ping|version|public)",
        re.IGNORECASE,
    )
    return not bool(no_auth_keywords.search(path))


# ---------------------------------------------------------------------------
# Core extraction logic
# ---------------------------------------------------------------------------


def _scan_string_pool_for_urls(analysis) -> list[dict]:
    """Walk the DEX string pool and collect API-like URLs with xref metadata."""
    results: list[dict] = []
    seen_urls: set[str] = set()

    for sa in analysis.get_strings():
        value = sa.get_value()
        matches = _RE_API_URL.findall(value)
        if not matches:
            # Also pick up plain http/https URLs that may be base URLs
            if _RE_HTTP_URL.match(value.strip()):
                matches = [value.strip()]
        for url in matches:
            # Strip trailing punctuation that may have been captured
            url = url.rstrip(".,;)\"]'")
            if url in seen_urls:
                continue
            seen_urls.add(url)

            base_url, path = _parse_url(url)
            params = _extract_params(path)

            # Find referencing classes/methods from string xrefs
            source_class = ""
            source_method = ""
            for class_analysis, method_analysis in sa.get_xref_from():
                source_class = _dalvik_to_java(class_analysis.name)
                source_method = method_analysis.name
                break  # take first referencing method

            results.append(
                {
                    "url": url,
                    "method": "UNKNOWN",  # will be refined by annotation scan
                    "base_url": base_url,
                    "path": path,
                    "params": params,
                    "source_class": source_class,
                    "source_method": source_method,
                    "auth_required": _infer_auth_required(path, source_class),
                    "source": "string_pool",
                }
            )

    return results


def _scan_retrofit_annotations(analysis) -> list[dict]:
    """Find Retrofit-annotated interface methods and extract endpoint info."""
    results: list[dict] = []

    for class_analysis in analysis.get_classes():
        class_name = class_analysis.name

        # Iterate methods on the class
        for method_analysis in class_analysis.get_methods():
            method = method_analysis.get_method()
            if method is None:
                continue

            # Check method annotations for Retrofit HTTP verb annotations
            try:
                annotations = method.get_annotations()
            except Exception:  # noqa: BLE001
                continue
            if annotations is None:
                continue

            for annotation in annotations:
                try:
                    ann_type = annotation.get_type()
                except Exception:  # noqa: BLE001
                    continue

                if ann_type not in _RETROFIT_ANNOTATION_DESCS:
                    continue

                verb = _verb_from_annotation_desc(ann_type)
                path = ""

                # Extract the path value from the annotation elements
                try:
                    elements = annotation.get_elements()
                    for elem in elements:
                        try:
                            elem_name = elem.get_name()
                            if elem_name in ("value", "path"):
                                raw_val = elem.get_value()
                                # Value may be a string like '"v1/users/{id}"'
                                path = str(raw_val).strip('"\'')
                                break
                        except Exception:  # noqa: BLE001
                            continue
                except Exception:  # noqa: BLE001
                    pass

                params = _extract_params(path)
                java_class = _dalvik_to_java(class_name)
                method_name = method_analysis.name

                results.append(
                    {
                        "url": path,  # relative; base_url filled in separately
                        "method": verb,
                        "base_url": "",
                        "path": path if path.startswith("/") else f"/{path}",
                        "params": params,
                        "source_class": java_class,
                        "source_method": method_name,
                        "auth_required": _infer_auth_required(path, java_class),
                        "source": "retrofit_annotation",
                    }
                )

    return results


def _find_builder_base_urls(analysis) -> list[str]:
    """Trace Retrofit.Builder / OkHttpClient.Builder baseUrl() calls to string arguments."""
    base_urls: list[str] = []
    seen: set[str] = set()

    for builder_class in _OKHTTP_BUILDER_CLASSES:
        for method_analysis in analysis.find_methods(
            classname=builder_class.replace("/", r"\/"),
            methodname="baseUrl|setBaseUrl",
        ):
            # Look at callers and find the string passed as argument
            for _, caller_method, _ in method_analysis.get_xref_from():
                encoded = caller_method.get_method()
                if encoded is None:
                    continue
                code = encoded.get_code()
                if code is None:
                    continue
                try:
                    instructions = list(code.get_bc().get_instructions())
                except Exception:  # noqa: BLE001
                    continue

                # Walk instructions looking for const-string before invoke
                for idx, instr in enumerate(instructions):
                    try:
                        instr_str = str(instr)
                    except Exception:  # noqa: BLE001
                        continue
                    if "const-string" in instr_str:
                        # Extract string value: const-string vX, "..."
                        m = re.search(r'"([^"]+)"', instr_str)
                        if m:
                            candidate = m.group(1)
                            if _RE_HTTP_URL.match(candidate) and candidate not in seen:
                                seen.add(candidate)
                                base_urls.append(candidate)

    return base_urls


def _merge_results(string_pool: list[dict], retrofit: list[dict], base_urls: list[str]) -> list[dict]:
    """Merge string-pool and Retrofit results; attach base_urls to relative paths."""
    merged: list[dict] = []
    seen_keys: set[str] = set()

    # For Retrofit relative paths, try to attach a discovered base URL
    primary_base = base_urls[0] if base_urls else ""

    for entry in retrofit:
        if not entry["base_url"] and primary_base:
            entry["base_url"] = primary_base.rstrip("/")
            if entry["path"]:
                entry["url"] = entry["base_url"] + entry["path"]
        key = f"{entry['method']}:{entry['url']}"
        if key not in seen_keys:
            seen_keys.add(key)
            merged.append(entry)

    for entry in string_pool:
        key = f"{entry['method']}:{entry['url']}"
        if key not in seen_keys:
            seen_keys.add(key)
            merged.append(entry)

    return merged


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------


@mcp.tool()
def extract_api_endpoints(session_id: str) -> dict:
    """Extract all API endpoints from the APK including REST URLs, Retrofit annotations, and OkHttp configurations.

    Combines three discovery strategies:
    1. String pool scan - finds all http/https URLs matching API path patterns
       (``/api``, ``/v1``, ``/graphql``, ``/rest``, ``/ws``, etc.)
    2. Retrofit annotation scan - finds interface methods annotated with
       ``@GET``, ``@POST``, ``@PUT``, ``@DELETE``, ``@PATCH`` etc. and extracts
       the declared path and HTTP verb directly from DEX annotations
    3. Builder base-URL tracing - follows ``Retrofit.Builder.baseUrl()`` and
       ``OkHttpClient`` usages to discover the runtime base URL

    Results are deduplicated and enriched with:
    - Path parameter names extracted from ``{param}`` / ``:param`` / ``%s`` patterns
    - A heuristic auth_required flag (false only for login/health/public paths)
    - The source class and method where the endpoint was referenced
    - The source strategy used to find each endpoint

    Args:
        session_id: Active analysis session ID returned by ``load_apk``.

    Returns:
        dict: ``{"status": "ok", "data": {"endpoints": [...], "base_urls": [...], "total": N}}``
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        string_pool_results = _scan_string_pool_for_urls(analysis)
        retrofit_results = _scan_retrofit_annotations(analysis)
        base_urls = _find_builder_base_urls(analysis)

        endpoints = _merge_results(string_pool_results, retrofit_results, base_urls)

        # Collect unique base URLs from all sources
        all_bases: list[str] = list(dict.fromkeys(
            [e["base_url"] for e in endpoints if e["base_url"]] + base_urls
        ))

        return {
            "status": "ok",
            "data": {
                "endpoints": endpoints,
                "base_urls": all_bases,
                "total": len(endpoints),
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
def find_auth_interceptors(session_id: str) -> dict:
    """Find OkHttp interceptors that add authentication headers.

    Searches for classes that implement ``okhttp3.Interceptor`` (both
    application and network interceptors).  For each implementing class it
    decompiles the ``intercept()`` method and searches for strings that indicate
    authentication header injection:
    ``Authorization``, ``Bearer``, ``X-Api-Key``, ``X-Auth-Token``, etc.

    Also detects classes added via ``OkHttpClient.Builder.addInterceptor()`` /
    ``addNetworkInterceptor()`` call sites.

    Args:
        session_id: Active analysis session ID returned by ``load_apk``.

    Returns:
        dict: ``{"status": "ok", "data": {"interceptors": [...], "total": N}}``

        Each interceptor entry contains:
        - ``class_name``         - Java class name of the interceptor
        - ``intercept_method``   - fully qualified method that was inspected
        - ``auth_headers_found`` - list of header-name strings detected
        - ``added_via``          - where it's registered (builder call site or "implements")
        - ``suspicious_strings`` - any other sensitive strings in the method
    """
    try:
        session = get_session(session_id)
        analysis = session.analysis

        interceptors: list[dict] = []
        seen_classes: set[str] = set()

        # Strategy 1: classes that implement okhttp3.Interceptor
        interceptor_iface = "Lokhttp3/Interceptor;"
        for class_analysis in analysis.get_classes():
            try:
                implements = class_analysis.implements
            except Exception:  # noqa: BLE001
                implements = []
            if interceptor_iface not in implements:
                continue

            class_name = _dalvik_to_java(class_analysis.name)
            if class_name in seen_classes:
                continue
            seen_classes.add(class_name)

            auth_headers: list[str] = []
            suspicious: list[str] = []
            intercept_sig = ""

            # Look for the intercept(Chain) method
            for method_analysis in class_analysis.get_methods():
                if method_analysis.name != "intercept":
                    continue
                intercept_sig = f"{class_name}.{method_analysis.name}{method_analysis.descriptor}"

                encoded = method_analysis.get_method()
                if encoded is None:
                    continue
                code = encoded.get_code()
                if code is None:
                    continue

                try:
                    instructions = list(code.get_bc().get_instructions())
                except Exception:  # noqa: BLE001
                    continue

                for instr in instructions:
                    try:
                        instr_str = str(instr)
                    except Exception:  # noqa: BLE001
                        continue
                    # Extract string literal from const-string instructions
                    if "const-string" in instr_str:
                        m = re.search(r'"([^"]+)"', instr_str)
                        if m:
                            val = m.group(1)
                            if _AUTH_HEADER_PATTERNS.search(val):
                                if val not in auth_headers:
                                    auth_headers.append(val)
                            elif len(val) > 3 and val not in suspicious:
                                suspicious.append(val)

            interceptors.append(
                {
                    "class_name": class_name,
                    "intercept_method": intercept_sig,
                    "auth_headers_found": auth_headers,
                    "added_via": "implements okhttp3.Interceptor",
                    "suspicious_strings": suspicious[:20],
                }
            )

        # Strategy 2: call sites of addInterceptor / addNetworkInterceptor
        for target_method in ("addInterceptor", "addNetworkInterceptor"):
            for method_analysis in analysis.find_methods(
                classname=r"okhttp3/OkHttpClient\$Builder",
                methodname=target_method,
            ):
                for _, caller_method, _ in method_analysis.get_xref_from():
                    call_site = (
                        f"{_dalvik_to_java(caller_method.class_name)}->{caller_method.name}"
                    )
                    # Find what class is being passed — look at the preceding new-instance
                    encoded = caller_method.get_method()
                    if encoded is None:
                        continue
                    code = encoded.get_code()
                    if code is None:
                        continue
                    try:
                        instructions = list(code.get_bc().get_instructions())
                    except Exception:  # noqa: BLE001
                        continue

                    for instr in instructions:
                        try:
                            instr_str = str(instr)
                        except Exception:  # noqa: BLE001
                            continue
                        if "new-instance" in instr_str:
                            m = re.search(r"L([\w/$]+);", instr_str)
                            if m:
                                candidate = _dalvik_to_java("L" + m.group(1) + ";")
                                if candidate not in seen_classes:
                                    seen_classes.add(candidate)
                                    interceptors.append(
                                        {
                                            "class_name": candidate,
                                            "intercept_method": "",
                                            "auth_headers_found": [],
                                            "added_via": f"{target_method}() at {call_site}",
                                            "suspicious_strings": [],
                                        }
                                    )

        return {
            "status": "ok",
            "data": {
                "interceptors": interceptors,
                "total": len(interceptors),
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
