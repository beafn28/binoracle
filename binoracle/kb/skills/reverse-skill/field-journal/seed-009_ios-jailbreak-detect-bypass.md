# [Seed] iOS Jailbreak Detection Bypass + Packet Capture

## Scenario Classification
iOS Reverse Engineering / Mobile Security Testing

## Target Overview
A certain iOS app crashes or displays "Environment Exception" when launched on a jailbroken device. It is necessary to bypass the jailbreak detection to further analyze its HTTP requests.

## Complete Execution Chain

1. Jailbreak Device Preparation (Dopamine / palera1n / unc0ver) → Install frida-server (Cydia source `build.frida.re`)
2. Drag IPA to machine, AppSync Unified sign → Confirm able to run `frida-ps -U`
3. Launch App → Crashes or pops "Environment Exception"
4. Use `frida-trace -U -i 'open' -i 'stat' -i 'access' -i 'fork' com.target.app` to trace detection calls
5. Common hits:探测 `/Applications/Cydia.app`、`/private/var/lib/apt`、`/usr/sbin/sshd`、`fork()` 是否成功、`/etc/apt`
6. Use objection to bypass with one command: `objection --gadget com.target.app explore -s "ios jailbreak disable"`
7. After successful launch, use frida to hook NSURLSession for packet capture, or configure mitmproxy to install system certificates

## Pitfall Records

| Issue | Reason | Solution | Time |
|-------|--------|----------|------|
| objection bypass still crashes | App uses SSL Pinning + double jailbreak detection | Enable both `ios sslpinning disable` and `ios jailbreak disable` simultaneously | 15min |
| App detects before launch, hook too late | Jailbreak detection in `+load` or `__attribute__((constructor))` | Use `-f` spawn mode + `frida-trace --aux 'spawn=1'` | 20min |
| Hooking stat causes app to hang | Some system calls are affected when stat is hooked | Only hook stat triggered by application bundle code (filter by caller) | 30min |
| App still detects after frida-server starts | App checks port 27042 and frida string | Rename `frida-server` + change default port (`-l 0.0.0.0:1234`), client uses `-H ip:1234` | 25min |
| mitmproxy certificate installation still causes SSL errors | iOS 14+ system certificates need to be enabled in "General → About This Mac → Certificate Trust Settings" | Go to trust settings and check the box | 10min |

## Toolchain Discovery

- **objection** is a Swiss Army Knife for iOS security testing, with built-in modules like jailbreak / sslpin / clipboard / keychain dump
- **r2frida** connects radare2 to frida, allowing runtime disassembly + register modification, much stronger than pure frida
- **Hopper / IDA** decompile iOS binaries (use IDA 7+ or Ghidra for iOS Mach-O)
- **dumpdecrypted** is outdated; now use **frida-ios-dump** for unstripping

## Key Code/Commands

General jailbreak detection hook template:

```javascript
// Intercept NSFileManager fileExistsAtPath to detect jailbreak directories
var NSFileManager = ObjC.classes.NSFileManager;
Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function (args) {
        var path = ObjC.Object(args[2]).toString();
        var jbPaths = [
            '/Applications/Cydia.app',
            '/Library/MobileSubstrate/MobileSubstrate.dylib',
            '/bin/bash', '/usr/sbin/sshd',
            '/etc/apt', '/private/var/lib/apt/'
        ];
        if (jbPaths.indexOf(path) !== -1) {
            this.shouldFake = true;
            console.log('[+] Hide JB path: ' + path);
        }
    },
    onLeave: function (retval) {
        if (this.shouldFake) retval.replace(0);
    }
});

// Intercept fork() —— Jailbreaks can fork, non-jailbreaks return -1
var fork = Module.findExportByName(null, 'fork');
Interceptor.replace(fork, new NativeCallback(function () {
    return -1;
}, 'int', []));
```

One-click deobfuscation (for uploading to jadx and other decompilers):

```bash
frida-ios-dump -l com.target.app
# Output Payload/TargetApp.app + already deobfuscated Mach-O
```

## Suggestions for Improvements

- Add a new sub-skill `ios-reverse/` (parallel to `apk-reverse/`) covering: deobfuscation, jailbreak detection bypass, SSL Pinning, Keychain dump, frida-ios-dump,时机 of `+load`
- The current `apk-reverse/` should not handle iOS content to avoid confusion

## Reusable Patterns/Script Snippets

**iOS Security Testing Quick Reference**:

```text
1. Jailbreak environment preparation (Dopamine 16.x / palera1n old version)
2. frida-ios-dump deobfuscation
3. otool / class-dump to view class hierarchy
4. objection to start console
5. ios jailbreak disable
6. ios sslpinning disable
7. mitmproxy to capture packets (system certificates + trust settings dual open)
8. After finding key logic, use IDA / Hopper for static deep digging
```

## Evolution Actions
- [ ] **Suggest adding ios-reverse skill** (current routing matrix iOS walks reverse-engineering/platforms.md, not detailed enough)
- [ ] Add frida-ios-dump to bootstrap manifest
- [ ] Add "iOS Security Testing Checklist" to references/

## Environment Information
- Jailbroken device: iPhone X (iOS 16.5) + Dopamine 1.1.7
- Host: macOS 13+ / Kali (mitmproxy + frida-tools)
- frida-server-ios: 16.x

## Desensitization Requirements
This entry is seed data, written based on public technical patterns and does not involve real targets. Bundle ID `com.target.app` is a placeholder.