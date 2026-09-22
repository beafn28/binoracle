#!/usr/bin/env bash
# Build the practice corpus as real Linux x86-64 ELFs using Docker (gcc:13).
# These are intentionally-vulnerable binaries for AUTHORIZED local practice only.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$here/bin"
img=gcc:13
run(){ docker run --rm --platform linux/amd64 -v "$here":/w -w /w "$img" bash -c "$1"; }

echo "[*] ret2win  (no-PIE, no-canary, NX)"
run "gcc -w -fno-stack-protector -no-pie -o bin/ret2win  src/ret2win.c"
echo "[*] fmtstring(no-PIE, NX)"
run "gcc -w -no-pie -o bin/fmtstring src/fmtstring.c"
echo "[*] ret2libc (no-PIE, no-canary, NX)"
run "gcc -w -fno-stack-protector -no-pie -o bin/ret2libc  src/ret2libc.c"
echo "[*] ret2win.stripped"
run "gcc -w -fno-stack-protector -no-pie -s -o bin/ret2win.stripped src/ret2win.c"
echo "[*] heapbug (double-free/overflow)"
run "gcc -fno-stack-protector -no-pie -w -o bin/heapbug src/heapbug.c"
echo "[*] ret2win_pie (PIE)"
run "gcc -fno-stack-protector -pie -fPIE -w -o bin/ret2win_pie src/ret2win.c"
echo "[*] fmtstring_pie (PIE)"
run "gcc -fno-stack-protector -pie -fPIE -w -o bin/fmtstring_pie src/fmtstring.c"
echo "[*] win_chall.exe (Windows PE via mingw)"
docker run --rm --platform linux/amd64 -v "$here":/w -w /w debian:12 bash -c \
  'apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y gcc-mingw-w64-x86-64 >/dev/null 2>&1 && x86_64-w64-mingw32-gcc -w -o bin/win_chall.exe src/winchall.c' || echo "  (mingw build skipped)"
echo "[*] done:"; ls -la "$here/bin"
