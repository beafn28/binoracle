#!/usr/bin/env bash
# binoracle — "probar todo" dentro del contenedor.
# Recorre el nucleo grounded (oraculos, lectores, arsenal, verificacion de exploits) y resume
# que funciona. Se ejecuta DENTRO de la imagen (ya trae el corpus compilado en samples/bin).
#   docker compose run --rm binoracle bash scripts/docker-smoke.sh
# o:  make docker-test
set -u
cd /app 2>/dev/null || cd "$(dirname "$0")/.." || true

pass=0; fail=0; skip=0
say() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok()  { printf '  \033[32mok\033[0m   %s\n' "$1"; pass=$((pass+1)); }
no()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
sk()  { printf '  \033[33m--\033[0m   %s\n' "$1"; skip=$((skip+1)); }

say "Herramientas base"
command -v radare2 >/dev/null 2>&1 && ok "radare2 $(radare2 -v 2>/dev/null | head -1)" || no "radare2 (recon/arsenal)"
command -v one_gadget >/dev/null 2>&1 && ok "one_gadget" || sk "one_gadget"
command -v checksec >/dev/null 2>&1 && ok "checksec" || sk "checksec"
command -v jadx >/dev/null 2>&1 && ok "jadx (APK->Java)" || sk "jadx"
command -v apktool >/dev/null 2>&1 && ok "apktool (manifest)" || sk "apktool"
command -v gdb >/dev/null 2>&1 && ok "gdb (dinamico)" || sk "gdb"
python3 -c 'import pwn' 2>/dev/null && ok "pwntools" || no "pwntools"
python3 -c 'import capstone' 2>/dev/null && ok "capstone" || sk "capstone"

say "binoracle doctor"
binoracle doctor 2>&1 | sed 's/^/  /' || no "doctor"

say "Lectores estaticos (sobre el propio corpus)"
for b in ret2win heapexp; do
  if [ -f "samples/bin/$b" ]; then
    binoracle identify "samples/bin/$b" >/dev/null 2>&1 && ok "identify $b" || no "identify $b"
    binoracle triage   "samples/bin/$b" >/dev/null 2>&1 && ok "triage $b"   || no "triage $b"
  else sk "sample $b (no compilado)"; fi
done
binoracle elf samples/bin/ret2win >/dev/null 2>&1 && ok "elf layout" || sk "elf layout"

say "Arsenal / cadenas (nativo)"
binoracle arsenal samples/bin/ret2libc >/dev/null 2>&1 && ok "rop arsenal" || no "rop arsenal"
binoracle analyze samples/bin/heapexp >/dev/null 2>&1 && ok "chain-analyzer (heap)" || no "chain-analyzer"

say "Verificacion de exploits por EJECUCION (shell real en sandbox)"
echo "  (ejecuta la suite; auto-salta lo que no aplica a esta plataforma)"
python3 -m pytest -q tests/test_smoke.py 2>&1 | tail -15 | sed 's/^/  /'

say "Resumen comprobaciones rapidas:  ok=$pass  FAIL=$fail  --=$skip"
[ "$fail" -eq 0 ] && echo "  nucleo OK (el veredicto de los exploits lo da pytest arriba)." \
                  || echo "  revisa los FAIL de arriba."
exit 0
