# Dynamic Analysis Tools

Tools for runtime interaction with a running app on a connected device.

## `get_runtime_info`

Retrieve live process information for a running app: PID, memory usage, open file descriptors, active threads, and network connections.

```
get_runtime_info(session_id="abc123")
→ {
    "pid": 12345,
    "memory_mb": 128,
    "threads": 24,
    "fd_count": 80,
    "network_connections": [{"remote": "api.example.com:443", "state": "ESTABLISHED"}]
  }
```

Requires a connected ADB device with the app running.

## `prepare_frida_apk`

Repackage the APK with the Frida gadget embedded, ready for sideloading and dynamic instrumentation.

```
prepare_frida_apk(session_id="abc123", output_path="/tmp/app-frida.apk")
→ {"output_apk": "/tmp/app-frida.apk", "gadget_arch": "arm64-v8a"}
```

Prerequisites: `apktool` and `zipalign` in PATH, and a debug keystore for re-signing.

## `take_screenshot`

Capture the current device screen and return the local file path.

```
take_screenshot(session_id="abc123")
→ {"path": "/Users/me/.apksaw/workspaces/abc123/screenshot_20260413_120000.png"}
```

Differs from `screenshot` in the device tools module in that it associates the capture with the session workspace.
