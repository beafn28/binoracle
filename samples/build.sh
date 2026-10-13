#!/usr/bin/env bash
# Build the practice corpus as real Linux x86-64 ELFs.
# Prefers the gcc:13 Docker image; falls back to the HOST gcc when the image is unavailable
# (CI / cloud / any box without `make pwn-image`), so the corpus still builds with no Docker.
# The host fallback only engages on Linux -- a macOS `gcc` is clang and would emit Mach-O, not
# Linux ELFs, so there we stay on Docker (its auto-pull preserves the original behavior).
# Intentionally-vulnerable binaries for AUTHORIZED local practice only.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$here/bin"
img=gcc:13

engine=none
if command -v docker >/dev/null 2>&1 && docker image inspect "$img" >/dev/null 2>&1; then
  engine=docker                                   # image already present -> fastest, exact
elif [ "$(uname -s)" = "Linux" ] && command -v gcc >/dev/null 2>&1; then
  engine=host                                     # no image, but a Linux host gcc emits ELFs
elif command -v docker >/dev/null 2>&1; then
  engine=docker                                   # e.g. macOS: let docker pull gcc:13 as before
fi
if [ "$engine" = none ]; then
  echo "[!] necesito la imagen Docker '$img' (make pwn-image) o un gcc en un host Linux" >&2
  exit 1
fi
echo "[*] motor de compilacion: $engine"
run(){
  if [ "$engine" = "docker" ]; then
    docker run --rm --platform linux/amd64 -v "$here":/w -w /w "$img" bash -c "$1"
  else
    # Host gcc: the official gcc:13 image is VANILLA gcc (stack-protector and cf-protection OFF
    # by default), but a distro gcc (Ubuntu/Debian) turns BOTH on by default -- which would add
    # a canary to the "no-canary" samples and endbr64 padding that shifts win()'s address. We
    # inject the vanilla defaults right after `gcc`; the per-line flags come AFTER and still win
    # (e.g. the canary sample's -fstack-protector-all overrides). PIE/RELRO are already set
    # explicitly per line. Tolerate a single build failing (e.g. -static sin glibc-static, -m32
    # sin multilib) so the rest still builds.
    local cmd="$1"
    case "$cmd" in
      gcc\ *) cmd="gcc -fno-stack-protector -fcf-protection=none ${cmd#gcc }" ;;
    esac
    ( cd "$here" && bash -c "$cmd" ) || { echo "  [!] build fallo (host gcc): omitido"; return 0; }
  fi
}

echo "[*] ret2win  (no-PIE, no-canary, NX)"
run "gcc -w -fno-stack-protector -no-pie -o bin/ret2win  src/ret2win.c"
echo "[*] fmtstring(no-PIE, NX)"
run "gcc -w -no-pie -o bin/fmtstring src/fmtstring.c"
echo "[*] ret2libc (no-PIE, no-canary, NX)"
run "gcc -w -fno-stack-protector -no-pie -o bin/ret2libc  src/ret2libc.c"
echo "[*] ret2win.stripped"
run "gcc -w -fno-stack-protector -no-pie -s -o bin/ret2win.stripped src/ret2win.c"
echo "[*] heapexp (tcache-UAF, para practica manual)"
run "gcc -fno-stack-protector -no-pie -w -o bin/heapexp src/heapexp.c"
echo "[*] heapbug (double-free/overflow)"
run "gcc -fno-stack-protector -no-pie -w -o bin/heapbug src/heapbug.c"
echo "[*] ret2win_pie (PIE)"
run "gcc -fno-stack-protector -pie -fPIE -w -o bin/ret2win_pie src/ret2win.c"
echo "[*] fmtstring_pie (PIE)"
run "gcc -fno-stack-protector -pie -fPIE -w -o bin/fmtstring_pie src/fmtstring.c"
echo "[*] ropme_pie (static-PIE, ROP sin win)"
run "gcc -fno-stack-protector -static-pie -fPIE -w -o bin/ropme_pie src/ropme_pie.c"
echo "[*] srop (static, no-PIE, no-canary, SROP: pocos gadgets)"
run "gcc -fno-stack-protector -no-pie -static -w -o bin/srop src/srop.c"
echo "[*] --- corpus ampliado (variado) ---"
echo "[*] canary (stack overflow con canary, SIN fuga utilizable: degrada honesto)"
run "gcc -fstack-protector-all -no-pie -w -o bin/canary src/canary.c"
echo "[*] canleak (stack overflow con canary + fuga via %s: bypass verificable)"
run "gcc -fstack-protector-all -no-pie -w -o bin/canleak src/canleak.c"
echo "[*] canfmt (stack overflow con canary + fuga via format-string %p: bypass verificable)"
run "gcc -fstack-protector-all -no-pie -w -o bin/canfmt src/canfmt.c"
echo "[*] dlresolve (dinamico, no-PIE, Partial RELRO: ret2dlresolve sin leak; con gadgets asm)"
run "gcc -fno-stack-protector -no-pie -w -o bin/dlresolve src/dlresolve.c"
echo "[*] fmt_got (format string -> GOT overwrite)"
run "gcc -fno-stack-protector -no-pie -w -o bin/fmt_got src/fmt_got.c"
echo "[*] uaf (use-after-free con puntero de funcion)"
run "gcc -fno-stack-protector -no-pie -w -o bin/uaf src/uaf.c"
echo "[*] intoverflow (integer overflow -> heap overflow)"
run "gcc -fno-stack-protector -no-pie -w -o bin/intoverflow src/intoverflow.c"
echo "[*] oobwrite (out-of-bounds write-what-where)"
run "gcc -fno-stack-protector -no-pie -w -o bin/oobwrite src/oobwrite.c"
echo "[*] staticrop (static, ROP a execve, sin win)"
run "gcc -fno-stack-protector -no-pie -static -w -o bin/staticrop src/staticrop.c"
echo "[*] notes_heap (menu heap notes, UAF/tcache)"
run "gcc -fno-stack-protector -no-pie -w -o bin/notes_heap src/notes_heap.c"
echo "[*] ret2win32 (32-bit, requiere multilib; se omite si no esta)"
run "gcc -m32 -fno-stack-protector -no-pie -w -o bin/ret2win32 src/ret2win32.c" || echo "  (32-bit build omitido: sin multilib)"
echo "[*] srop32 (32-bit, static, SROP via int 0x80; requiere multilib+glibc-static)"
run "gcc -m32 -fno-stack-protector -no-pie -static -w -o bin/srop32 src/srop32.c" || echo "  (srop32 build omitido: sin multilib/glibc-static i386)"
echo "[*] win_chall.exe (Windows PE via mingw)"
docker run --rm --platform linux/amd64 -v "$here":/w -w /w debian:12 bash -c \
  'apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y gcc-mingw-w64-x86-64 >/dev/null 2>&1 && x86_64-w64-mingw32-gcc -w -o bin/win_chall.exe src/winchall.c' || echo "  (mingw build skipped)"
echo "[*] done:"; ls -la "$here/bin"
