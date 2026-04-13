/*
 * obfuscation.yar — Packer, protector, and obfuscation fingerprinting rules
 * Detects known Android packer signatures, encrypted DEX markers, and
 * anti-analysis artefacts.
 */

rule PackerBangcle {
    meta:
        severity    = "high"
        description = "Bangcle (SecNeo) packer signature"
        reference   = "https://github.com/strazzere/android-unpacker"
    strings:
        $s1 = "com/secneo/apkwrapper"
        $s2 = "libsecexe.so"
        $s3 = "libsecmain.so"
        $s4 = "libDexHelper.so"
    condition:
        2 of them
}

rule PackerJiaguBaidu {
    meta:
        severity    = "high"
        description = "Baidu Jiagu packer signature"
    strings:
        $s1 = "com/baidu/protect"
        $s2 = "libBDJNI.so"
        $s3 = "jiagu"           nocase
        $s4 = "baiduprotect"    nocase
    condition:
        2 of them
}

rule PackerQihoo360 {
    meta:
        severity    = "high"
        description = "Qihoo 360 Jiagu / Legu packer"
    strings:
        $s1 = "com/qihoo/util"
        $s2 = "libprotectClass.so"
        $s3 = "360legu"        nocase
        $s4 = "com.stub.StubApp"
    condition:
        2 of them
}

rule PackerDexGuard {
    meta:
        severity    = "high"
        description = "DexGuard commercial obfuscator (Guardsquare)"
        reference   = "https://www.guardsquare.com/dexguard"
    strings:
        $s1 = "com/guardsquare/dexguard"
        $s2 = "DexGuard"
        $s3 = "guardsquare"   nocase
    condition:
        any of them
}

rule PackerTencent {
    meta:
        severity    = "high"
        description = "Tencent Legu / msec packer"
    strings:
        $s1 = "com/tencent/StubShell"
        $s2 = "libshella"
        $s3 = "libshellx"
        $s4 = "com.tencent.fakepath"
    condition:
        2 of them
}

rule PackerAliYunOS {
    meta:
        severity    = "high"
        description = "Alibaba / Ali YunOS packer"
    strings:
        $s1 = "com/alibaba/wireless/security"
        $s2 = "libsgmain.so"
        $s3 = "com.taobao.android.dexposed"
    condition:
        2 of them
}

rule EncryptedDEXMagic {
    meta:
        severity    = "high"
        description = "Non-standard DEX magic bytes — possible encrypted/transformed DEX"
    strings:
        // Standard DEX magic is "dex\n035\0" or "dex\n036\0" etc.
        // Any other magic at offset 0 is suspicious
        $dex_magic_035 = { 64 65 78 0A 30 33 35 00 }
        $dex_magic_036 = { 64 65 78 0A 30 33 36 00 }
        $dex_magic_037 = { 64 65 78 0A 30 33 37 00 }
        $dex_magic_038 = { 64 65 78 0A 30 33 38 00 }
        $dex_magic_039 = { 64 65 78 0A 30 33 39 00 }
    condition:
        none of them and filesize > 1024
}

rule EmbeddedDEXInAssets {
    meta:
        severity    = "medium"
        description = "DEX or ODEX file embedded inside assets (runtime loader pattern)"
    strings:
        $dex   = { 64 65 78 0A }    // "dex\n"
        $odex  = { 64 65 79 0A }    // "dey\n"
        $path1 = "assets/"
    condition:
        ($dex or $odex) and $path1
}

rule AntiEmulatorStrings {
    meta:
        severity    = "medium"
        description = "Anti-emulator / anti-analysis string fingerprints"
    strings:
        $em1 = "ro.kernel.qemu"
        $em2 = "generic_x86"
        $em3 = "goldfish"
        $em4 = "sdk_gphone"
        $em5 = "Android SDK built for x86"
        $em6 = "Emulator"       nocase
        $em7 = "isEmulator"
        $em8 = "Build.FINGERPRINT"
        $em9 = "QEMU"
    condition:
        3 of them
}

rule StringEncryptionPattern {
    meta:
        severity    = "medium"
        description = "Likely string encryption stub (characteristic XOR/AES decrypt loop near string usage)"
    strings:
        $xor1 = "xor"           nocase
        $aes1 = "AES/CBC/PKCS"  nocase
        $stub = "decrypt"       nocase
        $arr  = "toCharArray"
    condition:
        ($xor1 or $aes1) and $stub and $arr
}

rule ReflectiveClassLoading {
    meta:
        severity    = "high"
        description = "DexClassLoader or PathClassLoader used to load classes at runtime (common unpacker step)"
    strings:
        $dcl  = "DexClassLoader"
        $pcl  = "PathClassLoader"
        $bcl  = "BaseDexClassLoader"
        $load = "loadClass"
    condition:
        ($dcl or $pcl or $bcl) and $load
}
