/*
 * credentials.yar — Hardcoded credential and secret detection rules
 * Severity levels: critical, high, medium, low
 */

rule HardcodedAWSAccessKey {
    meta:
        severity    = "high"
        description = "AWS Access Key ID (AKIA...)"
        reference   = "https://docs.aws.amazon.com/general/latest/gr/aws-security-credentials.html"
    strings:
        $key = /AKIA[0-9A-Z]{16}/
    condition:
        $key
}

rule HardcodedAWSSecretKey {
    meta:
        severity    = "high"
        description = "AWS Secret Access Key context (40-char base62 after keyword)"
    strings:
        $kw1 = "aws_secret_access_key" nocase
        $kw2 = "AWS_SECRET"            nocase
        $kw3 = "SecretAccessKey"       nocase
        // 40-char base64 value following an = or : assignment
        $val = /[=:]\s*[A-Za-z0-9\/+]{40}/
    condition:
        any of ($kw1, $kw2, $kw3) and $val
}

rule HardcodedGoogleAPIKey {
    meta:
        severity    = "high"
        description = "Google / Firebase API Key (AIza...)"
    strings:
        $key = /AIza[0-9A-Za-z\-_]{35}/
    condition:
        $key
}

rule HardcodedFirebaseURL {
    meta:
        severity    = "medium"
        description = "Firebase Realtime Database URL"
    strings:
        $url = /[a-z0-9\-]{3,}\.firebaseio\.com/ nocase
    condition:
        $url
}

rule HardcodedFirebaseProjectConfig {
    meta:
        severity    = "medium"
        description = "Firebase project ID in google-services.json format"
    strings:
        $proj = /"project_id"\s*:\s*"[a-z0-9\-]+"/ nocase
        $sender = /"gcm_defaultSenderId"\s*:\s*"[0-9]+"/ nocase
    condition:
        $proj and $sender
}

rule PEMPrivateKey {
    meta:
        severity    = "critical"
        description = "PEM-encoded private key block"
    strings:
        $rsa  = "-----BEGIN RSA PRIVATE KEY-----"
        $ec   = "-----BEGIN EC PRIVATE KEY-----"
        $pkcs = "-----BEGIN PRIVATE KEY-----"
    condition:
        any of them
}

rule HardcodedBearerToken {
    meta:
        severity    = "high"
        description = "Hardcoded Bearer token"
    strings:
        $bearer = /Bearer [A-Za-z0-9\-._~+\/]{20,}={0,2}/ nocase
    condition:
        $bearer
}

rule HardcodedJWTToken {
    meta:
        severity    = "high"
        description = "Hardcoded JSON Web Token (three base64url segments)"
    strings:
        // JWT = base64url.base64url.base64url
        $jwt = /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/
    condition:
        $jwt
}

rule HardcodedGenericAPIKey {
    meta:
        severity    = "medium"
        description = "Generic API key assignment pattern"
    strings:
        $assign = /[Aa][Pp][Ii][_\-]?[Kk][Ee][Yy]\s*[=:]\s*["'][A-Za-z0-9]{16,}["']/
    condition:
        $assign
}

rule HardcodedPassword {
    meta:
        severity    = "medium"
        description = "Hardcoded password value in assignment"
    strings:
        $pwd1 = /password\s*[=:]\s*["'][^"']{6,}["']/ nocase
        $pwd2 = /passwd\s*[=:]\s*["'][^"']{6,}["']/ nocase
        $pwd3 = /pwd\s*=\s*["'][^"']{6,}["']/ nocase
    condition:
        any of them
}

rule HardcodedSlackWebhook {
    meta:
        severity    = "high"
        description = "Slack incoming webhook URL"
    strings:
        $wh = /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/
    condition:
        $wh
}

rule HardcodedStripeKey {
    meta:
        severity    = "high"
        description = "Stripe publishable or secret API key"
    strings:
        $pub  = /pk_live_[A-Za-z0-9]{24,}/
        $sec  = /sk_live_[A-Za-z0-9]{24,}/
        $test = /pk_test_[A-Za-z0-9]{24,}/
    condition:
        any of them
}

rule HardcodedTwilioCredentials {
    meta:
        severity    = "high"
        description = "Twilio Account SID or Auth Token"
    strings:
        $sid   = /AC[a-f0-9]{32}/
        $token = /SK[a-f0-9]{32}/
    condition:
        any of them
}

rule Base64EncodedSecret {
    meta:
        severity    = "low"
        description = "Large base64-encoded blob (possible embedded credential or key)"
    strings:
        // At least 64 chars of valid base64 with padding
        $b64 = /[A-Za-z0-9+\/]{64,}={0,2}/
    condition:
        $b64
}
