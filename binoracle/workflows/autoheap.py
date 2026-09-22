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
