# Root / Escalation / Anti-Tampering / SSL Pinning Bypass

## Detection Layer Model

```
Layer 1: Static Detection (at Installation/Startup)
  ├─ Package Manager Detection (Cydia, apt, Magisk)
  ├─ File Detection (su, busybox, frida-server)
  └─ Permission Detection (ro.debuggable, ro.secure)

Layer 2: Runtime Detection (Continuous)
  ├─ Process Detection (frida-server, magiskd)
  ├─ Port Detection (27042 frida default)
  ├─ Memory Detection (/proc/self/maps injection traces)
  └─ Stack Detection (Frida call frames)

Layer 3: Environment Detection (Triggered as Needed)
  ├─ ptrace Detection (TracerPid)
  ├─ /proc/self/status Detection
  ├─ build.prop Detection (test-keys)
  └─ Syscall Direct Detection (Bypass libc)
```

## Android Root Detection and Bypass

### Common Detection Libraries and Bypass Methods

| Detection Library | Detection Method | Bypass Method |
|--------------------|------------------|---------------|
| RootBeer            | 8 Combination of Detection Methods | Hook Each Detection Method to Return False |
| SafetyNet           | Remote Authentication by Google Play Services | Use Magisk Hide / Shamiko / Play Integrity Fix |
| Google Play Integrity | Replace SafetyNet | TrickStore + PIF |
| Custom Native Detection | Syscall Read from `/proc/self/status` | Hook Syscall or Modify `/proc` Mount |

### Frida Comprehensive Bypass

```javascript
Java.perform(function() {
    // RootBeer
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    var methods = ["isRooted", "isRootedWithBusyBox", "checkSuExists",
        "detectRootManagementApps", "detectPotentiallyDangerousApps",
        "detectTestKeys", "checkForDangerousProps", "checkForRWPaths"];
    methods.forEach(function(m) {
        RootBeer[m].implementation = function() { return false; };
    });

    // General Build.TAGS Detection
    var Build = Java.use("android.os.Build");
    var original = Build.TAGS.value;
    Build.TAGS.value = "release-keys";
```

```
// PackageManager → hide package name
var PackageManager = Java.use("android.content.pm.PackageManager");
PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {
    if (pkg == "de.robv.android.xposed.installer" || 
        pkg.includes("magisk") || pkg.includes("frida")) {
        throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
    }
    return this.getPackageInfo(pkg, flags);
};
```
```

## iOS Jailbreak Detection and Bypass

### Multi-layer Frida Hook

```javascript
// 1. Filesystem Detection
var NSFileManager = ObjC.classes.NSFileManager;
var paths = [
    "/Applications/Cydia.app", "/var/lib/apt", "/bin/bash",
    "/usr/sbin/sshd", "/etc/apt", "/Library/MobileSubstrate"
];
// Hook fileExistsAtPath to return NO

// 2. Fork Detection (Prohibited in Sandbox)
var fork_ptr = Module.findExportByName("libSystem.B.dylib", "fork");
Interceptor.replace(fork_ptr, new NativeCallback(function() {
    return -1;
}, 'int', []));

// 3. Scheme Detection
// Through MobileSubstrate Hooking
var LSApplicationWorkspace = ObjC.classes.LSApplicationWorkspace;
// Hook defaultWorkspace → canOpenURL → returns NO for cydia://

// 4. Signature Validation Detection
var MISValidateSignature = Module.findExportByName(null, "MISValidateSignature");
Interceptor.attach(MISValidateSignature, {
    onLeave: function(retval) { retval.replace(0); }
});
```

## Anti-Debugging Bypass

### Android

```javascript
// 1. Self-Ptrace → Prevent Attach
// Native: ptrace(PTRACE_TRACEME, 0, NULL, 0)
// Bypass: Hook ptrace → Return 0

// 2. TracerPid Detection
// /proc/self/status → TracerPid: 0
var fopen = Module.findExportByName(null, "fopen");
Interceptor.attach(fopen, {
    onEnter: function(args) {
        this.path = Memory.readUtf8String(args[0]);
    },
    onLeave: function(retval) {
        if (this.path && this.path.includes("status")) {
            // Modify the returned FILE*, return fake content
        }
    }
});

// 3. isDebuggerConnected (Java)
var Debug = Java.use("android.os.Debug");
Debug.isDebuggerConnected.implementation = function() { return false; };
```

### iOS

```javascript
// 1. PT_DENY_ATTACH
// ptrace(PT_DENY_ATTACH, 0, NULL, 0) → Prevent Debugger Attach
var ptrace = Module.findExportByName(null, "ptrace");
Interceptor.replace(ptrace, new NativeCallback(function(request, pid, addr, data) {
    if (request == 31) return 0; // PT_DENY_ATTACH → Ignore
    return ptrace(request, pid, addr, data);
}, 'int', ['int', 'int', 'pointer', 'int']));
```

# 2. sysctl Detection

```javascript
var sysctl = Module.findExportByName(null, "sysctl");
Interceptor.attach(sysctl, {
    onLeave: function(retval) {
        // Modify the p_flag field of kinfo_proc to clear P_TRACED
    }
});
```

# 3. getppid Detection (Check if the parent process is launchd)

```javascript
// Debugging when getppid() != 1
```

## SSL Pinning 绕过

### Android 五层绕过

```text
Layer 1 — TrustManager: Accept all certificates
Layer 2 — OkHttp CertificatePinner: Hook to clear the pins list
Layer 3 — WebView SSL Error Handler: Ignore certificate errors
Layer 4 — Network Security Config: Modify xml → trust user certificates
Layer 5 — Native SSL (OpenSSL/BoringSSL): Hook SSL_get_verify_result → X509_V_OK
```

### iOS 四层绕过

```text
Layer 1 — NSURLSession: Hook SecTrustEvaluate → kSecTrustResultProceed
Layer 2 — Alamofire: Hook ServerTrustManager
Layer 3 — AFNetworking: Hook AFSecurityPolicy
Layer 4 — libcurl: LD_PRELOAD to replace SSL verification callback
```

### General Objection Commands

```bash
# Android
objection -g "com.app" explore
android sslpinning disable
# Equivalent to automatically hooking the above 5 layers

# iOS
objection -g "com.app" explore
ios sslpinning disable
# Equivalent to automatically hooking the above 4 layers
```

Source: OWASP MSTG, Frida CodeShare, objection wiki