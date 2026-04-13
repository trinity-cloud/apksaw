# APK Analysis Tools

Tools for loading APKs and inspecting their top-level metadata.

## `load_apk`

Load a local APK file and create a persistent analysis session.

```
load_apk(apk_path="/path/to/app.apk")
→ {"session_id": "abc123", "package_name": "com.example.app", "sha256": "..."}
```

Returns immediately; Androguard analysis is deferred until first use.

## `app_info`

High-level summary: package name, version, SDK targets, declared features, and file size.

```
app_info(session_id="abc123")
→ {"package_name": "...", "version_name": "4.2.1", "min_sdk": 26, "target_sdk": 34, ...}
```

## `get_manifest`

Parse and return the full `AndroidManifest.xml` as a structured dict.

```
get_manifest(session_id="abc123")
→ {"package": "...", "activities": [...], "services": [...], "receivers": [...], ...}
```

## `get_permissions`

List all permissions declared in the manifest, with protection level where available.

```
get_permissions(session_id="abc123")
→ ["android.permission.INTERNET", "android.permission.READ_CONTACTS", ...]
```

## `get_components`

Return all Android components (activities, services, receivers, providers) with their intent filters and exported status.

## `list_files`

List all files inside the APK archive with their sizes and compression ratios.

## `get_signing_info`

Return certificate subject, issuer, algorithm, validity dates, and fingerprints. See also [Certificates](certificates.md).
