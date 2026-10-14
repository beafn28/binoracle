# Flutter APK Ad Banner Removal on Server Side (Third-party Impostor Package)

## Scenario Classification
APK Reverse Engineering / Flutter AOT Patching

## Target Overview
Remove server-side driven banners and pop-ups from the third-party imposter package's local native application (`{target_app}` 1.0.8) and output it with a new signature.

## Scope Summary (De-Identification)
- auth_basis: Local files, personal modifications.
- network_profile: Pure static analysis + local build, no external system ACT.
- asset_types: [android_apk, flutter_aot_libapp.so]

## Roles
- lead_role: lead
- specialists: []

## Complete Execution Chain

1. Target Identification: `{target}.apk` — Flutter 3.4.4 (libapp.so 13MB) + Qihoo 360加固 shell (`com.frezrik.jiagu.StubApp`, real dex encrypted in payload at the end of classes.dex, 2.58MB)
2. Static Reconnaissance: apktool d / jadx → manifest has no third-party ad SDK; scan libapp.so strings → discover server-side advertising system (ad_slot_key/ad_show/wcstream_* slots, `system/banner/bannerListByMAcct` API)
3. Toolchain Setup: gitee precompiled Flutter for ARM64-Linux (unavailable) → download blutter-unmgr source code → Windows MSVC build (VS2026 BuildTools + cmake + ninja) → compile dartvm3.4.4_android_arm64 static library (~15min) → blutter.exe analyze libapp.so → output pp.txt/objs.txt/asm/ + frida script
4. Ad System Restoration: class `qya` (ad model, 11 fields), `pya` (banner list), `GBg` (Map<String,dynamic>→Map<String,List<qya>> parser), all slot keys and API endpoints.
5. Patches Design (v2 Revision): **Equal-length string replacement** (31 ad strings × 2 ABIs): JSON key → garbage string (parse null), slot key → garbage string (lookup failure), report tag → garbage string. **API path string retention no replacement** (initial patching caused a 404 on the device, see the last note in the debugging record).
6. String Table Format Adaptation: arm64 packed table `[0x80|(len<<1)][chars]`; armv7 object table `[len*2 u32le][chars]`. Prefix validation + long strings prioritized to avoid substring overlap (welfare_ad_top/welfare_ad, ad_click:/ad_click).
7. Re-packaging: Python zipfile copy 1010 entries (replace libapp.so×2, remove old signature) → zipalign -p 4 → apksigner v1+v2+v3 (debug keystore)
8. Verification: Blutter re-analyze patched libapp.so passes (snapshot intact); apksigner verify passes; aapt badging matches; APK difference only includes libapp.so+signature; zero ad strings in the APK
9. **True Device Runtime Verification (Supplement)**: ARM64 true device installation → normal entry to main interface, ads disappear; logcat confirms no Flutter anomalies (see debugging record for details)

## Evidence Chain Summary
| E-id | source_type | Reusable Command Mode | Associated Finding |
|------|-------------|-----------------------|--------------------|
| E-001 | blutter_out/pp.txt | `[pp+0x210a8] String: "wcstream_banner_top"` | F-001 |
| E-002 | Patching script | `work/patch_libapp.py` | F-001 |
| E-003 | Re-analyze Blutter | `python blutter.py <patched_dir> <out>` exit 0 | F-002 |

## Finding / Path Summary
- Top Finding: Server-side driven ad Flutter application, removing ads does not require changing code logic — equal-length replacement of string tables' JSON keys/slot keys suffices, client internally self-consistent while server contract is broken; **but API path strings cannot be replaced** (requesting 404 → jsonDecode exception → device hangs)
- Path Type: solve
- One-liner Path: Locate string table → equal-length replacement of ad JSON keys/slot keys (retaining API paths) → re-packaging and signing → true device logcat verification

## Bug Tracking Record

| Problem | Reason | Solution | Time Spent |
|---------|---------|-----------|-------------|
| 360加固：Real Java dex 加密 | jadx 只见壳类（com.frezrik.jiagu + a\*) | Ad logic is in the Flutter Dart layer (libapp.so), no need to decompile | 0.5h |
| Gitee Precompiled Blutter cannot run | Binary is ARM64-Linux (used by Termux) | Download blutter-unmgr source code and compile x64 on my own | 1h |
| Windows Build of CMake fails to find cl | %PATH% expands during cmd parsing, overrides vcvars environment | Use `cmd /V:ON` + `set PATH=...;!PATH!` to delay expansion | 0.2h |
| `string(REPLACE "/EHsc" ...)` CMake error | REPLACE parameter is insufficient when CMAKE_CXX_FLAGS is empty (newer CMake) | Apply a patch with an `if(CMAKE_CXX_FLAGS)` guard (template + generated files) | 0.2h |
| Decrypted app ad function asm missing (size=-1) | Blutter fails to analyze/decompile obfuscated or complex functions | Abandon code-level patches and use string table replacement instead | 0.5h |
| Manual pool entry references fail | Snapshot pool entries are encoded as compressed pointers relative to the pool base address | Abandon manual reverse engineering, directly use Blutter pp.txt to locate string objects | 1h |
| Substring mis-matches | "welfare_ad" matches "welfare_ad_top" internally | Prioritize long strings for replacement + validate prefix bytes (arm64: 0x80 \| len<<1; armv7: len*2) | 0.3h |
| [WARN] **API paths replaced after boot fail on real device** | Initial version also replaced `system/banner/bannerListByMAcct` → Boot pulls ad request hits non-existent endpoint → Server returns 404 (invalid JSON error body) → Boot flow's `jsonDecode` throws `FormatException` (logcat `E flutter`) → UI permanently stays in the boot screen | **Do not replace API paths/URLs**; only replace JSON keys/slot keys/report tags. Use variable isolation for debugging (only re-signing the package) + `adb logcat -d \| grep "E flutter"`; MIUI installation interception requires `settings put global verifier_verify_adb_installs 0` | 1h |

## Toolchain Discovery
- blutter-unmgr (gitee.com/fest_1/blutter-unmgr): Precompiled package is ARM64-Linux; source code contains `blutter.py` (automatically detects Dart version + builds + runs in one)
- Blutter Windows build dependencies: VS BuildTools (contains cl) + CMake (≥3.20) + ninja + ICU/capstone (init_env_win.py automatically downloads)
- CMakeLists REPLACE bug needs to be fixed (see above)

## Reusable Patterns
**Generic flow for removing ad drivers from the server-side** (Flutter or native):
1. Reverse-engineer to find ad API endpoint/model key/slot key strings
2. Confirm string table format (arm64 packed / armv7 object / general length-prefixed)
3. Replace **JSON keys/slot keys/report tags** of equal length ASCII → Server contract breaks; **Keep the API path/URL unchanged**
4. Re-package + zipalign + apksigner (make sure to remove old signatures first)
5. Install on real device and verify with `adb logcat` (focus on `E flutter` uncaught exceptions, ensure no 404s in boot flow)