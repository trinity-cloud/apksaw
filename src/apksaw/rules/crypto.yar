/*
 * crypto.yar — Weak cryptography detection rules
 * Flags ECB mode, broken algorithms, weak PRNG seeds, and insecure key sizes.
 */

rule WeakCipherECBMode {
    meta:
        severity    = "high"
        description = "AES or DES in ECB mode (no IV, deterministic ciphertext)"
    strings:
        $ecb1 = "AES/ECB"     nocase
        $ecb2 = "DES/ECB"     nocase
        $ecb3 = "AES_ECB"     nocase
        $ecb4 = "Cipher/ECB"  nocase
    condition:
        any of them
}

rule WeakCipherDES {
    meta:
        severity    = "high"
        description = "DES or 3DES usage — algorithm is deprecated and broken"
    strings:
        $des1 = "DES/CBC"          nocase
        $des2 = "DESede"           nocase
        $des3 = "DES/ECB"          nocase
        $des4 = "TripleDES"        nocase
        $des5 = "DESKeySpec"       nocase
        $des6 = "SecretKeyFactory" nocase
    condition:
        $des6 and (1 of ($des1, $des2, $des3, $des4, $des5))
}

rule WeakHashMD5 {
    meta:
        severity    = "medium"
        description = "MD5 used as cryptographic hash (collision vulnerable)"
    strings:
        $md5a = "MessageDigest.getInstance(\"MD5\")"
        $md5b = /MD5["']/
        $md5c = "getMD5"     nocase
        $md5d = "DigestUtils" nocase
    condition:
        any of ($md5a, $md5b) or ($md5c and $md5d)
}

rule WeakHashSHA1 {
    meta:
        severity    = "low"
        description = "SHA-1 used (collision attacks demonstrated)"
    strings:
        $sha1a = "\"SHA-1\""
        $sha1b = "\"SHA1\""
        $sha1c = "SHA_1"
    condition:
        any of them
}

rule WeakRandomSeed {
    meta:
        severity    = "high"
        description = "java.util.Random seeded with predictable value (time, constant)"
    strings:
        $rand1 = "new Random("           nocase
        $rand2 = "setSeed("              nocase
        $rand3 = "currentTimeMillis"
        $rand4 = "System.nanoTime"
    condition:
        ($rand1 or $rand2) and ($rand3 or $rand4)
}

rule InsecureRandom {
    meta:
        severity    = "medium"
        description = "java.util.Random used instead of SecureRandom for security-sensitive operation"
    strings:
        $rand  = "java/util/Random"
        $nexti = "nextInt"
        $secure = "SecureRandom"
    condition:
        $rand and $nexti and not $secure
}

rule HardcodedIV {
    meta:
        severity    = "high"
        description = "Hardcoded initialization vector (IV) — defeats semantic security"
    strings:
        // Common hardcoded IV patterns: 0000000000000000 or short repeated sequences
        $iv1 = /IvParameterSpec\(new byte\[\]\{0,0,0,0/
        $iv2 = /new byte\[16\]\s*;\s*\/\//
        $iv3 = "0000000000000000"
        $iv4 = /IvParameterSpec\(\"[^\"]{8,32}\"\./
    condition:
        any of them
}

rule HardcodedEncryptionKey {
    meta:
        severity    = "high"
        description = "Hardcoded AES/DES key material"
    strings:
        $aes1 = /SecretKeySpec\([^\)]{0,40}\"AES\"\)/
        $aes2 = /new SecretKeySpec\(.*"AES"\)/
        $des1 = /SecretKeySpec\([^\)]{0,40}\"DES\"\)/
    condition:
        any of them
}

rule WeakKeySize {
    meta:
        severity    = "medium"
        description = "RSA or DSA key size below 2048 bits"
    strings:
        $k512  = "512"
        $k1024 = "1024"
        $rsa   = "RSA"
        $kpg   = "KeyPairGenerator"
    condition:
        $kpg and $rsa and ($k512 or $k1024)
}

rule NoPaddingMode {
    meta:
        severity    = "medium"
        description = "NoPadding mode — susceptible to padding oracle and bit-flip attacks"
    strings:
        $np1 = "NoPadding"   nocase
        $np2 = "/NoPadding"  nocase
    condition:
        any of them
}
