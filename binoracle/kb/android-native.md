# Android nativo (JNI / .so / ART) (cheat sheet)

Explotacion y reversing de la capa NATIVA de Android (librerias .so en C/C++, no el bytecode
Java/Kotlin). El codigo nativo corre bajo ART/Zygote en ARM/AArch64 (a veces x86 en emulador).

## Arquitectura
- APK = classes.dex (bytecode, corre en ART) + lib/<abi>/*.so (nativo, via JNI) + recursos.
- JNI: el puente Java<->nativo. `System.loadLibrary("foo")` carga libfoo.so; `JNI_OnLoad` se
  ejecuta al cargar (buen sitio para logica/anti-tamper). Metodos `native` mapean a
  `Java_paquete_Clase_metodo(JNIEnv*, jobject, ...)`.
- ABIs: arm64-v8a (lo normal hoy), armeabi-v7a, x86_64. Elige la .so segun el device/emulador.

## Reversing
- desempaqueta el APK (unzip / apktool), saca lib/<abi>/*.so.
- Ghidra/IDA para la .so (ARM/AArch64). Busca JNI_OnLoad y los Java_* exports (`readelf -s`).
- ART/DEX: jadx (dex->java), baksmali. La logica sensible suele estar en la .so para dificultar.
- frida es el rey en Android: hooks en runtime de funciones Java y nativas sin recompilar.

## Superficie de explotacion nativa
- las mismas clases de bug que en Linux userland (overflow, UAF, format string) dentro de la
  .so, explotadas en el contexto de la app (o de un servicio con mas privilegios).
- IPC: Binder (drivers /dev/binder), servicios del sistema, content providers, intents mal
  validados -> superficie para pasar datos controlados al codigo nativo.
- mitigaciones: NX, PIE (obligatorio desde Android 5), ASLR, stack canary, FORTIFY, y
  SELinux (confina cada app). scudo/jemalloc como allocator (heap distinto de glibc).

## Anti-tamper / anti-frida
Apps protegidas detectan root, frida (puertos/hilos "gum-js-loop"), debuggers (ptrace),
integridad del APK (firma), y emulador. Bypass: parcheo de la .so, frida gadget, o hooks que
anulan la comprobacion (ver [[anti-debug]]).

## Herramientas
apktool, jadx, frida/objection, Ghidra/IDA, adb, `readelf`/rabin2 sobre la .so, unicorn/qiling
para emular trozos de la .so sin device.

## Notas
- El heap es scudo (Android moderno), no ptmalloc: las tecnicas de [[heap]] glibc NO aplican
  igual; scudo tiene checksums y quarantine propios.
- Root/kernel de Android = kernel Linux -> ver [[kernel-pwn]] (drivers de vendor son el objetivo).
