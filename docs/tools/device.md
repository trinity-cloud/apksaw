# Device Tools

Tools for interacting with a connected Android device via ADB.

## `device_info`

Returns device model, Android version, SDK level, CPU ABI, and connected ADB serial.

```
device_info()
→ {"model": "Pixel 10a", "android_version": "16", "sdk": 36, "abi": "arm64-v8a"}
```

## `list_packages`

Lists all installed package names on the device. Accepts an optional filter string.

```
list_packages(filter="bank")
→ ["com.bank.mobile", "com.neobank.app"]
```

## `pull_apk`

Pulls an installed APK from the device to the local workspace and creates an analysis session.

```
pull_apk(package_name="com.example.app")
→ {"session_id": "abc123", "apk_path": "/...", "package_name": "com.example.app"}
```

## `install_apk` / `uninstall_app`

Install or remove an APK on the connected device.

## `start_activity`

Launch an activity by component name or intent URI.

## `send_broadcast`

Send an implicit or explicit broadcast intent.

## `force_stop` / `clear_app_data`

Kill the app process or wipe its data directory.

## `screenshot`

Capture the current device screen and save it locally.

## `monitor_logcat`

Stream logcat output, optionally filtered by tag or package. Returns buffered lines.
