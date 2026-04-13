/*
 * suspicious.yar — Runtime abuse, root detection, dynamic loading, and
 * reflection-based attack patterns
 */

rule RuntimeExecShellCommand {
    meta:
        severity    = "high"
        description = "Runtime.exec() used to run shell commands — command injection risk"
    strings:
        $exec1 = "Runtime.getRuntime().exec("
        $exec2 = "Runtime.exec("
        $exec3 = "ProcessBuilder"
        $sh1   = "/bin/sh"
        $sh2   = "/system/bin/sh"
        $sh3   = "cmd.exe"
    condition:
        ($exec1 or $exec2 or $exec3) and any of ($sh1, $sh2, $sh3)
}

rule DynamicDexLoading {
    meta:
        severity    = "high"
        description = "App downloads and dynamically loads a DEX/JAR at runtime"
    strings:
        $dcl   = "DexClassLoader"
        $http  = /https?:\/\//
        $down  = "download"    nocase
        $load  = "loadDex"     nocase
        $path  = "/data/data/"
    condition:
        $dcl and ($http or $down or $load) and $path
}

rule ReflectionMethodInvoke {
    meta:
        severity    = "medium"
        description = "Heavy use of Java reflection to invoke methods by name at runtime"
    strings:
        $ref1  = "getDeclaredMethod"
        $ref2  = "getMethod"
        $ref3  = "invoke("
        $ref4  = "getDeclaredField"
        $ref5  = "setAccessible(true)"
    condition:
        3 of them
}

rule RootDetectionBusybox {
    meta:
        severity    = "low"
        description = "Root detection — checks for busybox or su binary"
    strings:
        $bb   = "busybox"
        $su1  = "/system/xbin/su"
        $su2  = "/system/bin/su"
        $su3  = "/sbin/su"
        $su4  = "which su"
    condition:
        $bb or 2 of ($su1, $su2, $su3, $su4)
}

rule RootDetectionSuperUser {
    meta:
        severity    = "low"
        description = "Root detection — checks for Superuser / Magisk / KingUser APK"
    strings:
        $s1 = "com.noshufou.android.su"
        $s2 = "com.koushikdutta.superuser"
        $s3 = "eu.chainfire.supersu"
        $s4 = "com.topjohnwu.magisk"
        $s5 = "io.github.huskydg.magisk"
        $s6 = "KingUser"
        $s7 = "SuperSU"
    condition:
        2 of them
}

rule RootDetectionTestKeys {
    meta:
        severity    = "low"
        description = "Root detection via build tag / test-keys check"
    strings:
        $tk1 = "test-keys"
        $tk2 = "BUILD.TAGS"     nocase
        $tk3 = "ro.build.tags"
    condition:
        2 of them
}

rule NativeCodeExecution {
    meta:
        severity    = "medium"
        description = "Native library loaded and System.loadLibrary called — check for unsafe native code"
    strings:
        $ll1  = "System.loadLibrary("
        $ll2  = "System.load("
        $jni  = "JNI_OnLoad"
    condition:
        ($ll1 or $ll2) and $jni
}

rule ContentProviderInjection {
    meta:
        severity    = "medium"
        description = "Raw SQL query built from user input via ContentProvider (SQLi risk)"
    strings:
        $sel   = "selection"
        $query = "rawQuery"
        $cp    = "ContentProvider"
        $concat= "+"
    condition:
        $cp and $query and $sel and $concat
}

rule InsecureWebViewJavascript {
    meta:
        severity    = "high"
        description = "WebView with JavaScript enabled and addJavascriptInterface — XSS/RCE risk"
    strings:
        $js  = "setJavaScriptEnabled(true)"
        $ifc = "addJavascriptInterface"
    condition:
        $js and $ifc
}

rule IntentExtraDeserialization {
    meta:
        severity    = "medium"
        description = "Deserializing objects from Intent extras (potential unsafe deserialization)"
    strings:
        $ser1 = "getSerializableExtra"
        $ser2 = "getParcelableExtra"
        $cast = "ObjectInputStream"
    condition:
        ($ser1 or $ser2) and $cast
}

rule DynamicCodeBroadcastReceiver {
    meta:
        severity    = "medium"
        description = "BroadcastReceiver registered dynamically with no permission — interception risk"
    strings:
        $reg  = "registerReceiver"
        $ifl  = "IntentFilter"
        $null = "null"           // second arg (permission) is null
    condition:
        $reg and $ifl and $null
}

rule FileWorldReadableWritable {
    meta:
        severity    = "medium"
        description = "File created with MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE"
    strings:
        $wr1 = "MODE_WORLD_READABLE"
        $wr2 = "MODE_WORLD_WRITEABLE"
        $wr3 = "0644"
        $wr4 = "0666"
    condition:
        any of ($wr1, $wr2) or ($wr3 or $wr4)
}

rule AndroidDebugBridgeCommands {
    meta:
        severity    = "medium"
        description = "ADB-related strings that may indicate debuggable or exploit-related behaviour"
    strings:
        $adb1 = "adb shell"
        $adb2 = "adbd"
        $adb3 = "android.permission.ACCESS_SUPERUSER"
        $adb4 = "tcp:5555"
    condition:
        any of them
}

rule SSLPinningBypass {
    meta:
        severity    = "high"
        description = "TrustManager that accepts all certificates — SSL pinning disabled"
    strings:
        $tm1 = "X509TrustManager"
        $tm2 = "checkServerTrusted"
        $tm3 = "getAcceptedIssuers"
    condition:
        $tm1 and $tm2 and $tm3
}

rule FridaAntiHooking {
    meta:
        severity    = "low"
        description = "Frida / Xposed detection strings"
    strings:
        $f1 = "frida"            nocase
        $f2 = "gadget"           nocase
        $f3 = "xposed"           nocase
        $f4 = "XposedBridge"
        $f5 = "de.robv.android.xposed"
        $f6 = "frida-agent"
    condition:
        2 of them
}
