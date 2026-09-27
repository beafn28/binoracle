#!/usr/bin/env bash
# binoracle - instala el toolchain de pentest opcional que detecta `binoracle tools`.
# Idempotente: salta lo que ya este instalado. No requiere que TODO exista; instala lo que
# el gestor de paquetes de tu sistema permita. Ejecuta luego `binoracle tools` para ver el
# recuento. Los tiempos de ejecucion/PoC ya viven en la imagen Docker (make pwn-image).
set -u

PY="${PY:-python3}"
have(){ command -v "$1" >/dev/null 2>&1; }
os="$(uname -s)"

echo "== binoracle install-tools ($os) =="

pipx_or_pip(){ if have pipx; then pipx install "$1" 2>/dev/null || $PY -m pip install --user "$1"; else $PY -m pip install --user "$1"; fi; }

# --- pip (multiplataforma) ---
$PY -m pip install --user -q pyelftools capstone keystone-engine ropgadget ropper angr angrop unicorn qiling frida-tools 2>/dev/null \
  && echo "[ok] pip: pyelftools capstone keystone ropgadget ropper angr angrop unicorn qiling frida" \
  || echo "[--] pip: alguna libreria fallo (revisa el log)"

# --- pip: reversing/malware/pwn (individual: un fallo no tumba al resto) ---
for p in yara-python LibcSearcher flare-capa miasm manticore flare-floss; do
  $PY -m pip install --user -q "$p" 2>/dev/null && echo "[ok] pip: $p" \
    || echo "[--] pip: $p fallo (dep nativa que no compila en este host; opcional)"
done

# --- ruby gems ---
if have gem; then
  gem list -i one_gadget >/dev/null 2>&1 || gem install one_gadget 2>/dev/null && echo "[ok] gem: one_gadget"
  gem list -i seccomp-tools >/dev/null 2>&1 || gem install seccomp-tools 2>/dev/null && echo "[ok] gem: seccomp-tools"
  # los ejecutables de gem suelen quedar fuera del PATH: enlaza one_gadget a un dir del PATH.
  if ! have one_gadget; then
    ogp="$(gem contents one_gadget 2>/dev/null | grep -m1 '/bin/one_gadget$')"
    [ -n "$ogp" ] && have brew && ln -sf "$ogp" "$(brew --prefix)/bin/one_gadget" 2>/dev/null \
      && echo "[ok] one_gadget enlazado al PATH"
  fi
else
  echo "[--] gem no encontrado (one_gadget / seccomp-tools). Instala Ruby."
fi

# --- rust (cargo) ---
if have cargo; then
  have ropr    || cargo install ropr 2>/dev/null && echo "[ok] cargo: ropr"
  have pwninit || cargo install pwninit 2>/dev/null && echo "[ok] cargo: pwninit"
else
  echo "[--] cargo no encontrado (ropr / pwninit). Instala Rust: https://rustup.rs"
fi

# --- gestor del sistema ---
if [ "$os" = "Darwin" ] && have brew; then
  for f in radare2 patchelf qemu binwalk aflplusplus yara jadx apktool dex2jar; do
    brew list "$f" >/dev/null 2>&1 || brew install "$f" 2>/dev/null && echo "[ok] brew: $f"
  done
  brew list --cask detect-it-easy >/dev/null 2>&1 || brew install --cask detect-it-easy 2>/dev/null && echo "[ok] brew cask: detect-it-easy"
  echo "[i ] macOS: ltrace/strace y valgrind son de Linux (no aplican en el host); binoracle"
  echo "     ejecuta la parte dinamica en Docker Linux (make pwn-image)."
elif have apt-get; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq radare2 patchelf binwalk qemu-user ltrace strace valgrind gdb 2>/dev/null \
    && echo "[ok] apt: radare2 patchelf binwalk qemu-user ltrace strace valgrind gdb"
else
  echo "[--] sin brew/apt: instala radare2, patchelf, qemu-user, gdb a mano."
fi

echo
echo "Listo. Comprueba el recuento:  binoracle tools"
