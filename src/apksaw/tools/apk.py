"""APK loading and manifest analysis tools."""

import fnmatch
import os
from typing import Any

from apksaw.server import mcp
from apksaw.session import Session, create_session, get_session

# Android manifest XML namespace
_ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Permissions that carry dangerous protection level
_DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.UWB_RANGING",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_PRECISE_PHONE_STATE",
}


def _attr(element, name: str, default: Any = None) -> Any:
    """Get an android: namespaced attribute from an lxml element."""
    return element.get(f"{{{_ANDROID_NS}}}{name}", default)


def _parse_intent_filter(filter_elem) -> dict:
    """Parse a single <intent-filter> lxml element into a dict."""
    actions = [_attr(a, "name", "") for a in filter_elem.findall("action")]
    categories = [_attr(c, "name", "") for c in filter_elem.findall("category")]
    data_list = []
    for d in filter_elem.findall("data"):
        entry: dict[str, str] = {}
        for attr_name in ("scheme", "host", "port", "path", "pathPrefix",
                          "pathPattern", "mimeType"):
            val = _attr(d, attr_name)
            if val is not None:
                entry[attr_name] = val
        if entry:
            data_list.append(entry)
    return {
        "actions": actions,
        "categories": categories,
        "data": data_list,
    }


def _parse_component(elem, tag: str, target_sdk: int) -> dict:
    """Extract structured info from an activity/service/receiver/provider element."""
    name = _attr(elem, "name", "")
    exported_raw = _attr(elem, "exported")
    permission = _attr(elem, "permission")

    intent_filters = [
        _parse_intent_filter(f) for f in elem.findall("intent-filter")
    ]

    # Determine effective exported status
    if exported_raw is not None:
        exported = exported_raw.lower() in ("true", "1")
    else:
        # If no explicit value, it is considered exported if it has intent-filters
        # AND targetSdk < 31 (Android 12 changed the default)
        if intent_filters and target_sdk < 31:
            exported = True
        else:
            exported = False

    component: dict[str, Any] = {
        "name": name,
        "exported": exported,
        "permission": permission,
        "intent_filters": intent_filters,
    }

    # Provider-specific extras
    if tag == "provider":
        component["authorities"] = _attr(elem, "authorities")
        component["read_permission"] = _attr(elem, "readPermission")
        component["write_permission"] = _attr(elem, "writePermission")
        component["grant_uri_permissions"] = _attr(elem, "grantUriPermissions", "false")

    return component


@mcp.tool()
def load_apk(apk_path: str) -> dict:
    """Load an APK file for analysis and return a session ID.

    Args:
        apk_path: Absolute path to the APK file on disk.

    Returns:
        A dict with status, session_id, package name, SHA-256, version info,
        file count, and file size in MB.
    """
    try:
        session: Session = create_session(apk_path)
        apk = session.apk  # triggers Androguard loading

        file_size_bytes = os.path.getsize(str(session.apk_path))
        file_size_mb = round(file_size_bytes / (1024 * 1024), 3)

        return {
            "status": "ok",
            "data": {
                "session_id": session.session_id,
                "package_name": apk.get_package(),
                "sha256": session.sha256,
                "version_name": apk.get_androidversion_name(),
                "version_code": apk.get_androidversion_code(),
                "min_sdk": apk.get_min_sdk_version(),
                "target_sdk": apk.get_target_sdk_version(),
                "file_count": len(apk.get_files()),
                "file_size_mb": file_size_mb,
            },
        }
    except FileNotFoundError as exc:
        return {
            "status": "error",
            "message": str(exc),
            "suggestion": "Verify the path exists and is accessible.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Failed to load APK: {exc}",
            "suggestion": (
                "Ensure the file is a valid APK. "
                "Check that androguard is installed (pip install androguard)."
            ),
        }


@mcp.tool()
def get_manifest(session_id: str) -> dict:
    """Return the parsed AndroidManifest.xml as structured JSON.

    Includes package info, permissions, application attributes, and all
    components (activities, services, receivers, providers) with their
    exported status and intent filters.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict containing the structured manifest data.
    """
    try:
        session = get_session(session_id)
        apk = session.apk
        manifest_elem = apk.get_android_manifest_xml()

        target_sdk_raw = apk.get_target_sdk_version()
        try:
            target_sdk = int(target_sdk_raw) if target_sdk_raw else 0
        except (ValueError, TypeError):
            target_sdk = 0

        # Application element attributes
        app_elem = manifest_elem.find("application")
        app_attrs: dict[str, Any] = {}
        if app_elem is not None:
            for attr_name in (
                "debuggable",
                "allowBackup",
                "usesCleartextTraffic",
                "networkSecurityConfig",
                "theme",
                "label",
                "icon",
                "roundIcon",
                "appComponentFactory",
                "extractNativeLibs",
                "requestLegacyExternalStorage",
                "preserveLegacyExternalStorage",
                "testOnly",
            ):
                val = _attr(app_elem, attr_name)
                if val is not None:
                    app_attrs[attr_name] = val

        # Components
        def parse_all(tag: str) -> list[dict]:
            if app_elem is None:
                return []
            return [_parse_component(e, tag, target_sdk) for e in app_elem.findall(tag)]

        activities = parse_all("activity")
        # Also pick up activity-aliases
        aliases = parse_all("activity-alias")
        services = parse_all("service")
        receivers = parse_all("receiver")
        providers = parse_all("provider")

        # uses-permission list
        permissions = [
            _attr(p, "name", "")
            for p in manifest_elem.findall("uses-permission")
        ]
        # uses-permission-sdk-23
        permissions += [
            _attr(p, "name", "")
            for p in manifest_elem.findall("uses-permission-sdk-23")
        ]
        permissions = [p for p in permissions if p]

        # uses-feature
        features = [
            {
                "name": _attr(f, "name", ""),
                "required": _attr(f, "required", "true"),
            }
            for f in manifest_elem.findall("uses-feature")
        ]

        return {
            "status": "ok",
            "data": {
                "package": apk.get_package(),
                "version_name": apk.get_androidversion_name(),
                "version_code": apk.get_androidversion_code(),
                "min_sdk": apk.get_min_sdk_version(),
                "target_sdk": apk.get_target_sdk_version(),
                "max_sdk": apk.get_max_sdk_version(),
                "main_activity": apk.get_main_activity(),
                "permissions": permissions,
                "features": features,
                "application": app_attrs,
                "components": {
                    "activities": activities,
                    "activity_aliases": aliases,
                    "services": services,
                    "receivers": receivers,
                    "providers": providers,
                },
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
            "message": f"Failed to parse manifest: {exc}",
            "suggestion": "The APK manifest may be malformed or obfuscated.",
        }


@mcp.tool()
def get_permissions(session_id: str) -> dict:
    """Analyse APK permissions: requested, declared custom, and dangerous subset.

    Args:
        session_id: Session ID returned by load_apk.

    Returns:
        A dict with requested, declared, dangerous permissions and summary counts.
    """
    try:
        session = get_session(session_id)
        apk = session.apk

        requested: list[str] = apk.get_permissions()
        declared_details: dict = apk.get_declared_permissions_details()

        # Build declared list with protection level info
        declared: list[dict] = []
        for perm_name, details in declared_details.items():
            declared.append(
                {
                    "name": perm_name,
                    "protection_level": details.get("protectionLevel"),
                    "label": details.get("label"),
                    "description": details.get("description"),
                }
            )

        dangerous: list[str] = [
            p for p in requested if p in _DANGEROUS_PERMISSIONS
        ]

        return {
            "status": "ok",
            "data": {
                "requested": sorted(requested),
                "declared": declared,
                "dangerous": sorted(dangerous),
                "counts": {
                    "requested": len(requested),
                    "declared": len(declared),
                    "dangerous": len(dangerous),
                },
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
            "message": f"Failed to analyse permissions: {exc}",
            "suggestion": "Check that the APK was loaded successfully.",
        }


@mcp.tool()
def get_components(session_id: str, component_type: str = "all") -> dict:
    """List APK components with exported status, permissions, and intent filters.

    Args:
        session_id: Session ID returned by load_apk.
        component_type: One of "all", "activity", "service", "receiver", "provider".

    Returns:
        A dict mapping component type names to lists of component details.
    """
    valid_types = {"all", "activity", "service", "receiver", "provider"}
    if component_type not in valid_types:
        return {
            "status": "error",
            "message": (
                f"Invalid component_type '{component_type}'. "
                f"Must be one of: {sorted(valid_types)}."
            ),
            "suggestion": "Use 'all' to retrieve every component type at once.",
        }

    try:
        session = get_session(session_id)
        apk = session.apk
        manifest_elem = apk.get_android_manifest_xml()

        target_sdk_raw = apk.get_target_sdk_version()
        try:
            target_sdk = int(target_sdk_raw) if target_sdk_raw else 0
        except (ValueError, TypeError):
            target_sdk = 0

        app_elem = manifest_elem.find("application")

        def parse_all(tag: str) -> list[dict]:
            if app_elem is None:
                return []
            return [_parse_component(e, tag, target_sdk) for e in app_elem.findall(tag)]

        type_map = {
            "activity": parse_all("activity"),
            "service": parse_all("service"),
            "receiver": parse_all("receiver"),
            "provider": parse_all("provider"),
        }

        if component_type == "all":
            result = type_map
        else:
            result = {component_type: type_map[component_type]}

        # Attach counts
        counts = {k: len(v) for k, v in result.items()}

        return {
            "status": "ok",
            "data": {
                "components": result,
                "counts": counts,
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
            "message": f"Failed to list components: {exc}",
            "suggestion": "Check that the APK was loaded successfully.",
        }


@mcp.tool()
def list_files(session_id: str, filter: str = "") -> dict:  # noqa: A002
    """List all files contained in the APK archive.

    Args:
        session_id: Session ID returned by load_apk.
        filter: Optional glob pattern or substring to restrict results
                (e.g. "*.dex", "lib/", "assets").

    Returns:
        A dict with the list of matching files (path and size in bytes)
        and a total count.
    """
    try:
        session = get_session(session_id)
        apk = session.apk

        raw_files = apk.get_files()  # list of paths (strings)

        results: list[dict] = []
        for file_path in raw_files:
            # Apply filter: try glob first, then substring
            if filter:
                glob_match = fnmatch.fnmatch(file_path, filter)
                substr_match = filter.lower() in file_path.lower()
                if not (glob_match or substr_match):
                    continue

            # Attempt to retrieve file size
            try:
                data = apk.get_file(file_path)
                size = len(data) if data is not None else 0
            except Exception:
                size = 0

            results.append({"path": file_path, "size_bytes": size})

        return {
            "status": "ok",
            "data": {
                "files": results,
                "count": len(results),
                "filter_applied": filter or None,
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
            "message": f"Failed to list APK files: {exc}",
            "suggestion": "Check that the APK was loaded successfully.",
        }
