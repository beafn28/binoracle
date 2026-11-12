#!/usr/bin/env bash
# Build the practice corpus as real Linux x86-64 ELFs.
# Prefers the gcc:13 Docker image when it's already present (fastest, exact vanilla toolchain);
# falls back to the HOST gcc on Linux when the image is unavailable (CI / cloud / any box
# without `make pwn-image`), so the corpus still builds with no Docker. The host fallback only
# engages on Linux -- a macOS `gcc` is clang and would emit Mach-O, not Linux ELFs, so there we
# stay on Docker (its auto-pull preserves the original behavior).
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
# have_docker: usado mas abajo solo para el build opcional de win_chall.exe via mingw (necesita
# un contenedor Debian con gcc-mingw-w64, no el host); independiente de 'engine' porque ese build
# concreto siempre prefiere Docker si lo hay, sin importar como se compilo el resto del corpus.
have_docker=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  have_docker=1
fi
run(){
  if [ "$engine" = "docker" ]; then
    docker run --rm --platform linux/amd64 -v "$here":/w -w /w "$img" bash -c "$1"
  else
    # Host gcc: the official gcc:13 image is VANILLA gcc (stack-protector and cf-protection OFF
    # by default), but a distro gcc (Ubuntu/Debian) turns BOTH on by default -- which would add
    # a canary to the "no-canary" samples and endbr64 padding that shifts win()'s address.
    # Confirmado en vivo: '-fcf-protection=full' por defecto en Ubuntu anade padding endbr64 que
    # desplaza win() de su direccion esperada, rompiendo find_win()/tests que fijan una direccion
    # concreta, aunque cada linea ya pase '-fno-stack-protector' explicito (el canary si se
    # neutraliza, el CET no). Se inyectan los defaults de vainilla justo despues de 'gcc'; los
    # flags de cada linea van DESPUES y siguen ganando (e.g. la muestra canary's
    # -fstack-protector-all la sobreescribe). PIE/RELRO ya van explicitos por linea. Tolera que
    # un build individual falle (p.ej. -static sin glibc-static, -m32 sin multilib) para que el
    # resto del corpus se siga construyendo.
    #
    # -std=gnu17 fuerza el dialecto PRE-C23: confirmado en vivo que es necesario, no cosmetico.
    # Varios de estos retos llaman a proposito a funciones "peligrosas" sin declarar
    # (system() sin <stdlib.h> en canary/canleak/canfmt/fmt_got/oobwrite; gets() -- que C23 ya
    # ni declara en ningun header -- en toda la familia ret2win/callhijack). Con gcc moderno
    # (Ubuntu 26.04 en CI) el dialecto por defecto es gnu23, donde una declaracion implicita de
    # funcion es un ERROR duro (no un warning) -- y '-w' NO lo silencia porque ya no es un
    # warning, es un error de C23. Confirmado reproduciendo el log real de CI: 9 builds de la
    # muestra fallaban asi en cada run, dejando 'canary' fuera del corpus. En gcc local
    # (Ubuntu 24.04, dialecto por defecto gnu17) la misma llamada sin declarar solo advertia y
    # el build seguia -- por eso nunca se vio localmente. Fijar el dialecto explicito restaura
    # ese comportamiento en cualquier gcc, sin tocar cada fuente uno por uno.
    local cmd="$1"
    case "$cmd" in
      gcc\ *) cmd="gcc -std=gnu17 -fno-stack-protector -fcf-protection=none ${cmd#gcc }" ;;
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
echo "[*] ret2win_patched (mismo fuente que ret2win, +canary -- par old/new para patch-diff v2/regress)"
run "gcc -w -fstack-protector-all -no-pie -o bin/ret2win_patched src/ret2win.c"
echo "[*] heapexp (tcache-UAF, para practica manual)"
run "gcc -fno-stack-protector -no-pie -w -o bin/heapexp src/heapexp.c"
echo "[*] heapbug (double-free/overflow)"
run "gcc -fno-stack-protector -no-pie -w -o bin/heapbug src/heapbug.c"
echo "[*] ret2win_pie (PIE)"
run "gcc -fno-stack-protector -pie -fPIE -w -o bin/ret2win_pie src/ret2win.c"
echo "[*] callhijack (no-PIE: hijack de llamada/salto indirecto POR REGISTRO -- call rax, no ret)"
run "gcc -w -fno-stack-protector -no-pie -o bin/callhijack src/callhijack.c"
echo "[*] callhijack_pie (PIE, mismo fuente)"
run "gcc -w -fno-stack-protector -pie -fPIE -o bin/callhijack_pie src/callhijack.c"
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
echo "[*] dlresolve32 (32-bit, dinamico, no-PIE, Partial RELRO: ret2dlresolve i386; requiere multilib)"
run "gcc -m32 -fno-stack-protector -no-pie -w -o bin/dlresolve32 src/dlresolve32.c" || echo "  (dlresolve32 build omitido: sin multilib)"
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
echo "[*] ret2csu (x86-64, no-PIE, gadgets universales + call con args controlados)"
run "gcc -fno-stack-protector -no-pie -w -o bin/ret2csu src/ret2csu.c"
echo "[*] csuexec (x86-64, no-PIE, ret2csu -> execve encadenado: csu fija rsi/rdx + pop rdi/rax + syscall)"
run "gcc -fno-stack-protector -no-pie -w -o bin/csuexec src/csuexec.c"
echo "[*] hof (x86-64, no-PIE, house-of-force: top-chunk pre-2.29 reproducido en el binario)"
run "gcc -fno-stack-protector -no-pie -w -o bin/hof src/hof.c"
echo "[*] hos (x86-64, no-PIE, house-of-spirit: chunk falso en tcache de glibc real)"
run "gcc -fno-stack-protector -no-pie -w -o bin/hos src/hos.c"
echo "[*] hoe (x86-64, no-PIE, house-of-einherjar: consolidacion hacia atras reproducida)"
run "gcc -fno-stack-protector -no-pie -w -o bin/hoe src/hoe.c"
echo "[*] botcake (x86-64, no-PIE, house-of-botcake: doble-free via unsorted en glibc real)"
run "gcc -fno-stack-protector -no-pie -w -o bin/botcake src/botcake.c"
echo "[*] largebin (x86-64, no-PIE, largebin attack: escritura de insercion reproducida)"
run "gcc -fno-stack-protector -no-pie -w -o bin/largebin src/largebin.c"
echo "[*] hoc (x86-64, no-PIE, house-of-corrosion: global_max_fast -> fastbin index write reproducido)"
run "gcc -fno-stack-protector -no-pie -w -o bin/hoc src/hoc.c"
echo "[*] unsafeunlink (x86-64, no-PIE, unsafe-unlink: unlink() corruption + bypass del chequeo 2.3.4+)"
run "gcc -fno-stack-protector -no-pie -w -o bin/unsafeunlink src/unsafeunlink.c"
echo "[*] fastbindup (x86-64, no-PIE, fastbin-dup clasico: doble-free A,B,A + fd poison, pre-safe-linking)"
run "gcc -fno-stack-protector -no-pie -w -o bin/fastbindup src/fastbindup.c"
echo "[*] homind (x86-64, no-PIE, house-of-mind: heap_for_ptr -> ar_ptr -> fastbin insertion write)"
run "gcc -fno-stack-protector -no-pie -w -o bin/homind src/homind.c"
echo "[*] iofile (x86-64, no-PIE, IO_FILE/FSOP: hijack de vtable de _IO_FILE -> __overflow)"
run "gcc -fno-stack-protector -no-pie -w -o bin/iofile src/iofile.c"
echo "[*] srop_aarch64 (ARM64, static, no-PIE, SROP; requiere aarch64-linux-gnu-gcc; se omite si no esta)"
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
  ( cd "$here" && aarch64-linux-gnu-gcc -fno-stack-protector -no-pie -static -w -o bin/srop_aarch64 src/srop_aarch64.c ) \
    || echo "  (srop_aarch64 build fallo)"
else
  echo "  (srop_aarch64 build omitido: sin aarch64-linux-gnu-gcc)"
fi
echo "[*] stash (x86-64, no-PIE, tcache stashing unlink: stash smallbin->tcache con chequeo >=2.31)"
run "gcc -fno-stack-protector -no-pie -w -o bin/stash src/stash.c"
echo "[*] fmtgot32 (32-bit, format-string -> printf@GOT=system; requiere multilib)"
run "gcc -m32 -fno-stack-protector -no-pie -w -o bin/fmtgot32 src/fmtgot32.c" || echo "  (fmtgot32 build omitido: sin multilib)"
echo "[*] pivot (x86-64, static, short overflow -> stack migration to .bss)"
run "gcc -fno-stack-protector -no-pie -static -w -o bin/pivot src/pivot.c"
echo "[*] mprotectshell (x86-64, static, no-PIE: ROP a mprotect() en un buffer .bss fijo -> shellcode real, NX bypass sin leak)"
run "gcc -fno-stack-protector -no-pie -static -w -o bin/mprotectshell src/mprotectshell.c"
echo "[*] leakchain (x86-64, no-PIE, dinamico: OOB read filtra puntero libc real -> OOB write hijacka callback -> system('/bin/sh'), infoleak chaining)"
run "gcc -fno-stack-protector -no-pie -w -o bin/leakchain src/leakchain.c"
echo "[*] win_chall.exe (Windows PE via mingw)"
# Real gap encontrado y confirmado en vivo: este build SIEMPRE prefirio Docker (debian:12)
# sobre el mingw del host cuando Docker estaba disponible, sin importar que el host YA
# tuviera x86_64-w64-mingw32-gcc instalado -- en este sandbox de desarrollo (sin daemon de
# Docker corriendo) el mingw del HOST (Ubuntu noble: gcc-mingw-w64-x86-64 13.2.0-6ubuntu1+26.1)
# se usaba sin darse cuenta, pero un runner de CI con Docker disponible tomaba SIEMPRE la rama
# debian:12 (gcc-mingw-w64-x86-64 12.2.0-14+25.2 -- GCC 12, version mayor distinta, confirmado
# comparando ambos paquetes). Esa diferencia de toolchain produce un win_chall.exe
# BINARIAMENTE DISTINTO entre ambos entornos -- causa confirmada de que
# test_symbolic_angr_reachable_works_on_pe_via_mingw_simprocedures fallara en CI (3/3) sin
# reproducirse nunca en local (18+ veces): no era aleatoriedad de angr, era compilar un
# binario diferente sin saberlo. Se invierte la prioridad -- host primero, Docker solo si el
# host no tiene mingw -- para que el mismo toolchain (el que SI se ha verificado en vivo, una
# y otra vez, esta noche) se use en cualquier entorno, sin depender de si Docker resulta estar
# corriendo o no.
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
  ( cd "$here" && x86_64-w64-mingw32-gcc -w -o bin/win_chall.exe src/winchall.c ) || echo "  (mingw build skipped)"
elif [ "$have_docker" = "1" ]; then
  docker run --rm --platform linux/amd64 -v "$here":/w -w /w debian:12 bash -c \
    'apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y gcc-mingw-w64-x86-64 >/dev/null 2>&1 && x86_64-w64-mingw32-gcc -w -o bin/win_chall.exe src/winchall.c' || echo "  (mingw build skipped)"
else
  echo "  (mingw build skipped: sin x86_64-w64-mingw32-gcc en el host y sin Docker)"
fi
echo "[*] done:"; ls -la "$here/bin"
