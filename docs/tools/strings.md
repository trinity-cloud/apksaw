# String Extraction Tools

Tools for extracting and searching string literals from APK resources and DEX bytecode.

## `search_strings`

Search all string constants in the APK for a pattern (substring or regex).

```
search_strings(session_id="abc123", pattern="api.example.com")
→ [{"string": "https://api.example.com/v2", "class": "Lcom/example/Api;", ...}]
```

## `extract_urls`

Extract all HTTP/HTTPS/custom-scheme URLs found in string constants.

```
extract_urls(session_id="abc123")
→ ["https://api.example.com/v2/", "https://cdn.example.com/", ...]
```

## `extract_interesting_strings`

Heuristically find strings likely to be secrets, endpoints, or sensitive data. Categories include:
- API keys and tokens
- Hardcoded credentials
- Internal hostnames and IPs
- Firebase and cloud config values

```
extract_interesting_strings(session_id="abc123")
→ {
    "api_keys": ["AIzaSy..."],
    "urls": ["https://internal.corp/..."],
    "credentials": [...]
  }
```

See also [`extract_secrets`](security.md) in the Security tools for a more targeted scan.
