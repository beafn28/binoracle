"""binoracle MCP server: one MCP for grounded binary RE + exploit development.

Exposes binoracle's analysis and (authorized) exploit-development workflows as Model Context
Protocol tools, so any MCP-capable agent (Claude Code, etc.) can drive them. Design adopted from
REA (morluto/rea, MIT) -- one server registering many grounded tools over stdio, every result that
derives from the analysis target marked as untrusted content so hosts treat it as data, not
instructions. Implemented over raw JSON-RPC 2.0 (newline-delimited over stdio) with NO external
dependency, matching binoracle's dependency-light design.

Transport: reads one JSON-RPC message per line on stdin, writes one per line on stdout. Methods:
initialize, notifications/initialized, ping, tools/list, tools/call.

Exploit tools are for AUTHORIZED / CTF / research targets only (same policy as the CLI)."""
from __future__ import annotations

import json
import sys
import traceback
from typing import Callable, Dict, List

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "binoracle"

try:
    from . import __version__ as _VER
except Exception:
    _VER = "0"

# Results that derive from the analysis target are untrusted: a host/hook can read this marker and
# treat the text as data, never as instructions (a malicious binary can embed prompt-like strings).
_TARGET_META = {"provenance": {"untrusted_content": True, "source": "analysis_target"}}

_TOOLS: List[dict] = []
_HANDLERS: Dict[str, Callable[[dict], str]] = {}


def _tool(name: str, description: str, properties: dict, required: List[str]):
    """Register an MCP tool contract + handler. Handler takes the arguments dict, returns markdown."""
    def deco(fn: Callable[[dict], str]):
        _TOOLS.append({
            "name": name,
            "description": description,
            "inputSchema": {"type": "object", "properties": properties, "required": required},
        })
        _HANDLERS[name] = fn
        return fn
    return deco


# --- shared helpers -------------------------------------------------------------------------------

def _binary(args: dict) -> str:
    import os
    b = (args or {}).get("binary") or ""
    if not b:
        raise ValueError("falta el argumento 'binary' (ruta al ELF a analizar)")
    if not os.path.exists(b):
        raise FileNotFoundError(f"binario no encontrado: {b}")
    return b


def _reg(binary: str):
    from .oracles import build_registry
    return build_registry(binary)


def _render_chains(an, lang: str = "es") -> str:
    out = [f"## Analisis de cadenas de explotacion\n"]
    note = getattr(an, "note", "")
    if note:
        out.append(f"> {note}\n")
    for c in getattr(an, "chains", []) or []:
        flag = "VERIFICADA (shell real)" if getattr(c, "verified", False) else (
            "factible" if getattr(c, "feasible", False) else "no factible")
        out.append(f"### {c.name} -> {c.target}")
        out.append(f"- estado: **{flag}**  |  score: {getattr(c,'score',0)}  |  "
                   f"requisitos sin cumplir: {getattr(c,'unmet_requirements','?')}")
        if getattr(c, "sim_result", ""):
            out.append(f"- verificacion: {c.sim_result}")
        if getattr(c, "mitigations", None):
            out.append(f"- mitigaciones: {', '.join(c.mitigations)}")
        if getattr(c, "break_points", None):
            out.append(f"- puntos de rotura: {'; '.join(c.break_points)}")
        if getattr(c, "proof", None):
            out.append(f"- prueba: `{c.proof}`")
        out.append("")
    return "\n".join(out)


# --- analysis tools (safe, read-only) -------------------------------------------------------------

@_tool("triage", "Hechos fundamentados del binario: arquitectura, mitigaciones (NX/PIE/canary/RELRO), "
       "simbolos y superficie de ataque. Solo lectura, sin modelo.",
       {"binary": {"type": "string", "description": "ruta al ELF"}}, ["binary"])
def _h_triage(args):
    from .workflows.triage import run_triage
    from .report.render import render_triage
    b = _binary(args)
    return render_triage(run_triage(_reg(b), b))


@_tool("analyze_chains", "Analiza y puntua las cadenas de explotacion viables segun las defensas del "
       "binario (ret2win, ret2libc, ROP/execve, SROP, ret2dlresolve, format-string, canary-bypass, "
       "heap, etc.). Con verify=true las VERIFICA por ejecucion en sandbox (shell real).",
       {"binary": {"type": "string", "description": "ruta al ELF"},
        "verify": {"type": "boolean", "description": "verificar por ejecucion en sandbox (lento)"}},
       ["binary"])
def _h_chains(args):
    from .workflows.chainanalyzer import analyze_chains
    b = _binary(args)
    an = analyze_chains(b, None, verify=bool((args or {}).get("verify", False)), lang="es")
    return _render_chains(an)


@_tool("hunt", "Busca hipotesis de vulnerabilidad y las verifica contra oraculos (grounding). "
       "Devuelve hallazgos con su evidencia.",
       {"binary": {"type": "string", "description": "ruta al ELF"}}, ["binary"])
def _h_hunt(args):
    from .workflows.vulnhunt import run_hunt
    b = _binary(args)
    hunt = run_hunt(_reg(b), b)
    fs = getattr(hunt, "findings", []) or []
    if not fs:
        return "## Hunt\nSin hipotesis de vulnerabilidad encontradas."
    out = [f"## Hunt: {len(fs)} hallazgo(s)\n"]
    for f in fs:
        title = getattr(f, "title", None) or getattr(f, "name", str(f))
        verdict = getattr(f, "verdict", "?")
        out.append(f"- **{title}** [{verdict}]")
        ev = getattr(f, "evidence", None) or getattr(f, "detail", None)
        if ev:
            out.append(f"  - evidencia: {str(ev)[:200]}")
    return "\n".join(out)


@_tool("primitives", "Razona sobre la primitiva de explotacion probable (overflow, fmt, UAF, "
       "write-what-where...) a partir de los hechos del binario.",
       {"binary": {"type": "string", "description": "ruta al ELF"}}, ["binary"])
def _h_primitives(args):
    from .workflows.primitives import run_primitives
    b = _binary(args)
    r = run_primitives(_reg(b), b)
    return str(getattr(r, "answer", None) or getattr(r, "text", None) or r)


@_tool("inspect_go_binary", "Lee estaticamente la build-info de un binario Go (version del "
       "compilador, modulo principal, dependencias, replacements y build settings) SIN toolchain de "
       "Go ni ejecutar el binario. La ausencia de build-info no prueba que no sea Go.",
       {"binary": {"type": "string", "description": "ruta al binario (ELF/PE/Mach-O)"}}, ["binary"])
def _h_go(args):
    from .workflows.goinspect import inspect_go, render_go
    b = _binary(args)
    return render_go(inspect_go(b))


@_tool("inspect_elf_layout", "Layout ELF offline: cabecera, secciones, segmentos, simbolos, "
       "reubicaciones, linkage (libs/interprete) y candidatos de mitigacion (PIE/NX/pila "
       "ejecutable/canary/RELRO, segmentos RWX). Todo derivado del fichero; no ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta al ELF"}}, ["binary"])
def _h_elf(args):
    from .workflows.elflayout import inspect_elf, render_elf
    b = _binary(args)
    return render_elf(inspect_elf(b))


@_tool("inspect_core_dump", "Lee estaticamente un core dump ELF (Linux): la senal, la direccion de "
       "fallo, los registros por hilo y los mapeos de memoria -- el punto de partida fundamentado "
       "para convertir un crash en exploit (que registro controla la entrada). No ejecuta nada.",
       {"core": {"type": "string", "description": "ruta al core dump (ELF ET_CORE)"}}, ["core"])
def _h_core(args):
    import os
    from .workflows.coredump import inspect_core, render_core
    c = (args or {}).get("core") or ""
    if not c or not os.path.exists(c):
        raise FileNotFoundError(f"core no encontrado: {c}")
    return render_core(inspect_core(c))


@_tool("kb_search", "Consulta la base de conocimiento de explotacion (RAG) de binoracle: cheat "
       "sheets, metodologia y playbook verificado.",
       {"query": {"type": "string", "description": "consulta en lenguaje natural"},
        "k": {"type": "integer", "description": "numero de fragmentos (def. 4)"}}, ["query"])
def _h_kb(args):
    from .rag import get_kb
    q = (args or {}).get("query") or ""
    if not q:
        raise ValueError("falta 'query'")
    k = int((args or {}).get("k", 4) or 4)
    hits = get_kb().retrieve(q, k=k)
    if not hits:
        return "Sin resultados en la KB."
    out = ["## KB\n"]
    for h in hits:
        ch = h[0] if isinstance(h, tuple) else h
        title = getattr(ch, "title", "?")
        text = getattr(ch, "text", "")
        out.append(f"### {title}\n{text[:500]}\n")
    return "\n".join(out)


# --- exploit-development tools (AUTHORIZED / CTF only; verify by execution) ------------------------

@_tool("autopwn", "Orquestador autonomo: observa las defensas, razona que tecnica aplica, construye "
       "el exploit y lo VERIFICA por ejecucion en sandbox (shell real). AUTORIZADO/CTF.",
       {"binary": {"type": "string", "description": "ruta al ELF"},
        "run": {"type": "boolean", "description": "ejecutar en sandbox (def. true)"}}, ["binary"])
def _h_autopwn(args):
    from .workflows.autopwn import autopwn, render_autopwn
    b = _binary(args)
    r = autopwn(b, run=bool((args or {}).get("run", True)))
    return render_autopwn(r)


def _exploit_tool(name, desc, importer):
    @_tool(name, desc + " AUTORIZADO/CTF; verifica por ejecucion y degrada honestamente.",
           {"binary": {"type": "string", "description": "ruta al ELF"}}, ["binary"])
    def _h(args, _imp=importer):
        fn, render = _imp()
        b = _binary(args)
        return render(fn(b))
    return _h


_exploit_tool("autopoc", "ret2win: encuentra el offset y salta a win(), verificado en sandbox.",
              lambda: ((lambda b: __import__("binoracle.workflows.autopoc", fromlist=["autopoc"]).autopoc(b, run=True)),
                       __import__("binoracle.workflows.autopoc", fromlist=["render_poc"]).render_poc))
_exploit_tool("autolibc", "ret2libc con fuga de libc (+one_gadget) -> system('/bin/sh').",
              lambda: (__import__("binoracle.workflows.autolibc", fromlist=["autolibc"]).autolibc,
                       __import__("binoracle.workflows.autolibc", fromlist=["render_libc"]).render_libc))
_exploit_tool("autofmt", "format-string: printf@GOT=system (Partial RELRO) o ret2system (Full RELRO).",
              lambda: (__import__("binoracle.workflows.autofmt", fromlist=["autofmt"]).autofmt,
                       __import__("binoracle.workflows.autofmt", fromlist=["render_fmt"]).render_fmt))
_exploit_tool("autoheap", "heap -> shell (tcache poisoning, safe-linking) en binarios de menu.",
              lambda: (__import__("binoracle.workflows.autoheap", fromlist=["autoheap_shell"]).autoheap_shell,
                       __import__("binoracle.workflows.autoheap", fromlist=["render_heap"]).render_heap))
_exploit_tool("autocanary", "bypass de stack canary via fuga (%s o format-string) -> overflow a win().",
              lambda: (__import__("binoracle.workflows.autocanary", fromlist=["autocanary"]).autocanary,
                       __import__("binoracle.workflows.autocanary", fromlist=["render_canary"]).render_canary))
_exploit_tool("autosrop", "SROP: rt_sigreturn restaura un frame forjado -> execve('/bin/sh').",
              lambda: (__import__("binoracle.workflows.autosrop", fromlist=["autosrop"]).autosrop,
                       __import__("binoracle.workflows.autosrop", fromlist=["render_srop"]).render_srop))
_exploit_tool("autodlresolve", "ret2dlresolve: forja el resolver dinamico -> system('/bin/sh') sin leak.",
              lambda: (__import__("binoracle.workflows.autodlresolve", fromlist=["autodlresolve"]).autodlresolve,
                       __import__("binoracle.workflows.autodlresolve", fromlist=["render_dlresolve"]).render_dlresolve))


# --- JSON-RPC / MCP plumbing ----------------------------------------------------------------------

def _result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "_meta": _TARGET_META}


def handle(msg: dict):
    """Dispatch one JSON-RPC request; return a response dict, or None for notifications."""
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": str(_VER)},
            "instructions": ("binoracle: RE fundamentado y desarrollo de exploits verificado por "
                             "ejecucion. Resultados derivados del binario van marcados como contenido "
                             "no confiable. Las tools de exploit son solo para objetivos AUTORIZADOS/CTF."),
        }}
    if method in ("notifications/initialized", "initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": _TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        fn = _HANDLERS.get(name)
        if fn is None:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": f"tool desconocida: {name}"}}
        try:
            text = fn(args)
            return {"jsonrpc": "2.0", "id": mid, "result": _result(text)}
        except Exception as e:
            # tool-level error: report as an MCP tool result with isError, not a protocol error
            tb = traceback.format_exc(limit=3)
            return {"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": f"error en {name}: {e}\n{tb}"}],
                "isError": True}}
    if mid is not None:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"metodo no soportado: {method}"}}
    return None


def serve(instream=None, outstream=None) -> None:
    """Run the stdio MCP loop: one JSON-RPC message per line."""
    instream = instream or sys.stdin
    outstream = outstream or sys.stdout
    for line in instream:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        resp = handle(msg)
        if resp is not None:
            outstream.write(json.dumps(resp) + "\n")
            outstream.flush()


if __name__ == "__main__":
    serve()
