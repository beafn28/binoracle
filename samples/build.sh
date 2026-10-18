#!/usr/bin/env bash
# Build the practice corpus as real Linux x86-64 ELFs using Docker (gcc:13),
# falling back to the host's own gcc on Linux when Docker is unavailable
# (the README documents this fallback; it was missing here).
# These are intentionally-vulnerable binaries for AUTHORIZED local practice only.
set -e
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$here/bin"
img=gcc:13
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  run(){ docker run --rm --platform linux/amd64 -v "$here":/w -w /w "$img" bash -c "$1"; }
  have_docker=1
elif [ "$(uname -s)" = "Linux" ] && command -v gcc >/dev/null 2>&1; then
  echo "[*] Docker no disponible: compilando con el gcc nativo del host" >&2
  # el gcc:13 de Docker es VAINILLA (stack-protector/cf-protection apagados por defecto), pero
  # un gcc de distro (Ubuntu/Debian) enciende AMBOS por defecto -- confirmado en vivo:
  # '-fcf-protection=full' por defecto en este host anade padding endbr64 que desplaza win() de
  # su direccion esperada, rompiendo find_win()/tests que fijan una direccion concreta, aunque
  # cada linea ya pase '-fno-stack-protector' explicito (el canary si se neutraliza, el CET no).
  # Se inyectan los defaults de vainilla justo despues de 'gcc'; los flags de cada linea van
  # DESPUES y siguen ganando si alguno los necesitara.
  run(){
    local cmd="$1"
    case "$cmd" in
      gcc\ *) cmd="gcc -fno-stack-protector -fcf-protection=none ${cmd#gcc }" ;;
    esac
    ( cd "$here" && bash -c "$cmd" )
  }
  have_docker=0
else
  echo "ERROR: ni Docker ni un gcc nativo de Linux estan disponibles para construir el corpus" >&2
  exit 1
fi

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
echo "[*] canary (stack overflow con canary + leak)"
run "gcc -fstack-protector-all -no-pie -w -o bin/canary src/canary.c"
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
echo "[*] win_chall.exe (Windows PE via mingw)"
if [ "$have_docker" = "1" ]; then
  docker run --rm --platform linux/amd64 -v "$here":/w -w /w debian:12 bash -c \
    'apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y gcc-mingw-w64-x86-64 >/dev/null 2>&1 && x86_64-w64-mingw32-gcc -w -o bin/win_chall.exe src/winchall.c' || echo "  (mingw build skipped)"
elif command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
  ( cd "$here" && x86_64-w64-mingw32-gcc -w -o bin/win_chall.exe src/winchall.c ) || echo "  (mingw build skipped)"
else
  echo "  (mingw build skipped: sin Docker y sin x86_64-w64-mingw32-gcc en el host)"
fi
echo "[*] done:"; ls -la "$here/bin"
