# [Seed] APK Frida Bypass OkHttp SSL Pinning

## Scenario Classification
APK Reversing / Mobile Security Testing

## Target Overview
To dynamically bypass certificate validation on an Android app that uses OkHttp + custom CertificatePinner, allowing Burp to capture plaintext traffic.

## Complete Execution Chain

1. Install Frida + frida-server, start the target App, and confirm the process name
   ```bash
   adb shell "ps -A | grep com.target.app"
   frida-ps -U | grep target
   ```
2. Try capturing with Burp → Get a certificate error, indicating Pinning is enabled
3. Open APK with jadx for decompilation → Search for `CertificatePinner` or `checkServerTrusted`
4. Confirm if it's the built-in OkHttp `CertificatePinner` or a custom `X509TrustManager`
5. Write a Frida script to hook key validation points
6. Start Frida injection: `frida -U -f com.target.app -l bypass.js --no-pause`
7. Recapture → Burp can see plaintext HTTPS

## Pitfall Records

| Issue | Reason | Solution | Time |
|-------|--------|----------|------|
| Frida startup error `unable to connect to remote frida-server` | Server not started or port occupied | `adb forward tcp:27042 tcp:27042` + start server | 10min |
| Hook not working | App starts too fast, Frida injection is late | Use `-f` parameter spawn mode, with `--no-pause` | 15min |
| Some requests still SSL errors after hooking | App uses both OkHttp and native HttpsURLConnection | Add hooks for `X509TrustManager.checkServerTrusted` and `HostnameVerifier.verify` | 20min |
| Anti-detection: App exits after detecting Frida | App self-checks frida-server port / `/data/local/tmp/re.frida.server` | Use frida-gadget (inject .so into APK) or magisk + zygisk-frida | 30min+ |
| ProGuard obfuscation causes class name not found | Class names become `a.b.c` short signatures | In jadx, use `Find Usages` to reverse-find who instantiates OkHttpClient.Builder | 25min |

## Tool Chain Discovery

- **objection** has a built-in command `android sslpinning disable` that solves 80% of scenarios without needing to write a Frida script
- **frida-multiple-unpinning** (GitHub: WithSecureLabs) covers OkHttp 3/4, Retrofit, HttpsURLConnection, Conscrypt, Cordova, universal script
- **MEDUSA** framework comes with various Android bypass modules, faster to get started than bare Frida

## Key Code/Commands

Minimal usable OkHttp Pin bypass script:

```javascript
Java.perform(function () {
    // 1. OkHttp 3/4 内置 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, peers) {
            console.log('[+] OkHttp CertificatePinner.check bypassed: ' + host);
            return;
        };
    } catch (e) {}

    // 2. 自定义 X509TrustManager.checkServerTrusted
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrusted, holdHost, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] TrustManagerImpl.verifyChain bypassed: ' + host);
            return untrusted;
        };
    } catch (e) {}

    // 3. HostnameVerifier 全过
    var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
    // 用 objection 自带模板补完...
});
```

One-click command (recommended):

```bash
objection --gadget com.target.app explore -s "android sslpinning disable"
```

## Suggestions for Improvements to This Package

- `apk-reverse/references/` should have a dedicated `ssl-pinning-bypass.md`, consolidating the four mainstream cases of OkHttp 3/4, Conscrypt, custom TrustManager, and Flutter (boringssl) into a quick reference guide.
- Add `objection` to the bootstrap manifest (pip package).

## Reusable Patterns/Script Snippets

**General Bypass Workflow**:

```text
1. Capture traffic → Determine the type of error (CertPin / Hostname / TrustManager)
2. Search for key classes with jadx (CertificatePinner / X509TrustManager / HostnameVerifier)
3. Prefer objection one-click → Fallback to frida-multiple-unpinning if it doesn't work → Handwrite if necessary
4. If there's anti-Frida detection → Switch to frida-gadget or zygisk
5. Handle Flutter apps separately (hook libflutter.so's ssl_verify_peer_cert)
```

## Evolution Actions
- [x] Route matrix covered (apk-reverse + Frida)
- [x] Check Frida status in tool-index
- [ ] Suggest adding ssl-pinning-bypass.md quick reference guide

## Environment Information
- Kali / Windows + adb + frida-tools 16.x
- Target Android: 8-14 (different versions of TrustManagerImpl paths vary)
- Injection method: USB debugging + frida-server / or zygisk-frida hidden

## Desensitization Requirements
This entry is seed data, written based on public technical patterns and does not involve real targets. The package name `com.target.app` is a placeholder.