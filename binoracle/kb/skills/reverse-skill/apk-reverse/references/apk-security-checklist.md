# APK Security Testing Quick Reference

> Based on OWASP MASTG (Mobile Application Security Testing Guide).
> Covers six dimensions: static analysis, dynamic analysis, network communication, data storage, authentication and authorization, and code protection.

---

## Static Analysis Checklist

### Manifest Audit

```text
□ android:debuggable="true" → Debuggable (should not appear in production)
□ android:allowBackup="true" → Data can be backed up and extracted
□ android:exported="true" components → Exported Activity/Service/Receiver/Provider
□ Custom permissions protectionLevel → Should be signature (not normal)
□ intent-filter schemes → Custom deep link susceptibility to hijacking
□ android:usesCleartextTraffic="true" → Allows cleartext HTTP
□ minSdkVersion too low → May lack security features
```

### Key Points in Code Audit

```text
□ Hardcoded keys/tokens (search for "key", "secret", "password", "api_key")
□ Insecure random number generation (java.util.Random instead of SecureRandom)
□ Insecure encryption (ECB mode, DES, MD5 for passwords)
□ WebView configuration (setJavaScriptEnabled + addJavascriptInterface = RCE risk)
□ SQL injection (rawQuery with user input)
□ Path traversal (ContentProvider's openFile without path validation)
□ Log leak (Log.d/Log.i outputting sensitive information)
□ Clipboard leak (ClipboardManager storing sensitive data)
□ Implicit Intent leak (sendBroadcast without specifying package name)
```

### Third-Party Library Audit

```text
□ Outdated OkHttp/Retrofit version (known vulnerabilities)
□ Outdated WebView kernel
□ SDKs with known vulnerabilities (check CVEs)
□ Ad SDK data collection scope
□ Push SDK configuration (whether token leakage occurs)
```

---

## Dynamic Analysis Checklist

### Prior Targets for Frida Hooking

| Target | Hook Point | Purpose |
|------|---------|------|
| Login Authentication | `LoginActivity.login()` | Observe credential handling |
| Signature Generation | `*Sign*`、`*sign*`、`*encrypt*` | Restore signature algorithm |
| SSL Pinning | `CertificatePinner.check` | Bypass packet capture |
| Root Detection | `*root*`、`*su*`、`*magisk*` | Bypass detection |
| Encryption Operations | `javax.crypto.Cipher` | Extract key/IV |
| Token Storage | `SharedPreferences.getString` | Observe token read/write |
| Network Requests | `OkHttpClient.newCall` | Observe request construction |

### Common Frida One-Liner Commands

```bash
# Trace all encryption operations
frida-trace -U -f com.target.app -j '*Cipher*!*'

# Trace all HTTP requests
frida-trace -U -f com.target.app -j '*OkHttp*!*'

# Trace SharedPreferences read/write
frida-trace -U -f com.target.app -j '*SharedPreferences*!*'

# Trace all native function calls
frida-trace -U -f com.target.app -i 'Java_*'
```

### Objection Quick Commands

```bash
# Connect
objection -g com.target.app explore

# Common commands
android hooking list activities
android hooking list services
android sslpinning disable
android root disable
android clipboard monitor
env                              # View app directory
sqlite connect <db_path>         # Connect to database
```

## Network Communication Security

### Packet Capture Configuration

```text
Method 1: System Proxy + Burp/mitmproxy
- Set WiFi proxy → Burp listening address
- Install CA certificate to device
- Android 7+ requires network_security_config or Frida bypass

Method 2: VPN Mode (Recommended)
- Use HttpCanary / Packet Capture
- No root required, no need for proxy configuration
- But cannot decrypt SSL Pinning traffic

Method 3: Frida + r2frida
- Intercept network calls directly in the process
- Not restricted by proxy/VPN
```

### Check Items

```text
□ Whether using HTTPS (all API calls)
□ Whether there is SSL Pinning (certificate binding)
□ Whether certificate verification is correct (does not accept self-signed certificates)
□ Whether there is Certificate Transparency (CT) check
□ Whether the API key is transmitted in plain text in requests
□ Whether there is an expiration mechanism for tokens
□ Whether there is a request signature anti-tamper protection
□ Whether there is replay attack protection (nonce/timestamp)
□ Whether WebSocket is encrypted
□ Whether sensitive data is in URL parameters (will be logged)
```

---

## Data Storage Security

### Check Locations

| Location | Risk | Check Command |
|----------|------|---------------|
| SharedPreferences | Plain text storage of token/password | `adb shell cat /data/data/pkg/shared_prefs/*.xml` |
| SQLite Database | Unencrypted sensitive data | `adb pull /data/data/pkg/databases/` |
| External Storage | Any app can read | `adb shell ls /sdcard/Android/data/pkg/` |
| App Logs | Leak debug information | `adb logcat \| grep pkg` |
| Backup Files | allowBackup=true | `adb backup -f backup.ab pkg` |
| Keyboard Cache | Input history | Check if `inputType` is `textPassword` |
| Screenshot Protection | Sensitive pages can be screenshots | Check for `FLAG_SECURE` |

### Encryption Storage Scheme Comparison

| Scheme | Security | Description |
|--------|----------|-------------|
| SharedPreferences plain text | ❌ | Can be read directly after rooting |
| EncryptedSharedPreferences | ✓ | AndroidX Security library |
| SQLCipher | ✓ | Encrypts SQLite database |
| Android Keystore | ✓✓ | Hardware-level key protection |
| Custom AES encryption | ⚠️ | Depends on key management |

---

## Authentication and Authorization

### Common Vulnerabilities

| Vulnerability | Testing Method |
|---------------|----------------|
| Weak password policy | Try 123456, password, etc. |
| No lockout mechanism | Brute force login interface |
| Token does not expire | Replay old token after logout |
| Privilege escalation | Modify user_id in request |
| SMS verification code can be brute-forced | 4/6 digit numbers with no frequency limit |
| OAuth configuration error | redirect_uri can be tampered with |
| Biometric authentication bypass | Hook BiometricPrompt |
| Device binding bypass | Modify device_id |

### Testing Payloads

```bash
# Privilege escalation test
curl -H "Authorization: Bearer USER_A_TOKEN" \
     "https://api.target.com/users/USER_B_ID/profile"

# Token replay
# 1. Normal login to get token
# 2. Logout
# 3. Use old token for request → Should return 401

# SMS verification code brute-force
for code in $(seq 0000 9999); do
    curl -X POST "https://api.target.com/verify" \
         -d "phone=13800138000&code=$code"
done
```

---

## Code Protection Assessment

| Protection Measure | Detection Method | Bypass Difficulty |
|--------------------|------------------|-------------------|
| ProGuard Obfuscation | jadx check if class names are a/b/c | Low (just renaming) |
| String Encryption | Search for decryption functions, Hook to get plaintext | Medium |
| Anti-Debugging | Try attaching debugger | Medium (Frida can bypass) |
| Root Detection | Run on rooted device | Medium (generic scripts can bypass) |
| Emulator Detection | Run on emulator | Low-Medium |
| Integrity Check | Install modified APK | Medium (patch check function) |
| Hardening/Shield | Check entry class and .so files | Medium-High (requires de-shielding) |
| Native Protection | Core logic in .so file | High (requires IDA analysis) |
| VMP Virtualization | Code is virtualized for execution | Extremely High |

---

## Quick Testing Process (30 Minutes)

```text
1. [5min] Unpacking + Manifest Audit
   apktool d app.apk
   Check debuggable/allowBackup/exported/cleartext

2. [10min] Code Quick Audit
   jadx -d out app.apk
   Search for: password, key, secret, token, http://

3. [5min] Network Testing
   Configure proxy → Operate the APP → Check for plaintext/weak encryption

4. [5min] Storage Inspection
   adb shell → Check shared_prefs and databases

5. [5min] Dynamic Verification
   Frida hook key functions → Confirm findings
```