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
    ars = getattr(an, "arsenal", None) or {}
    if ars.get("total_gadgets"):
        out.append(f"### Arsenal ROP ({ars['total_gadgets']} gadgets clasificados)")
        argregs = ars.get("arg_regs") or {}
        if argregs:
            _b = ars.get("bits", 64)
            _order = (["ebx", "ecx", "edx", "esi", "edi", "eax"] if _b == 32
                      else ["rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax"])
            out.append("- control de registros:")
            for r in _order:
                g = argregs.get(r)
                if g:
                    cl = (" clobbers " + ",".join(g["clobbers"])) if g.get("clobbers") else ""
                    out.append(f"  - {r.upper()}: `{g['text']}` @ {g['addr']} (delta {g['delta']}B{cl})")
        if ars.get("syscall"):
            out.append(f"- syscall/int0x80: `{ars['syscall']['text']}` @ {ars['syscall']['addr']}")
        if ars.get("pivot"):
            out.append(f"- pivote de stack: `{ars['pivot']['text']}` @ {ars['pivot']['addr']}")
        if ars.get("write"):
            out.append(f"- write-what-where: `{ars['write']['mem_write']}` @ {ars['write']['addr']}")
        for mv in (ars.get("moves") or [])[:6]:
            out.append(f"- move {mv['move']}: `{mv['text']}` @ {mv['addr']}")
        cov = ars.get("execve_coverage") or {}
        if cov:
            mark = "COMPLETA" if cov.get("complete") else f"parcial ({','.join(cov.get('have') or []) or 'ninguno'})"
            _needtxt = "/".join(cov.get("need") or []) + ("+int0x80" if ars.get("bits") == 32 else "+syscall")
            out.append(f"- cobertura execve-por-syscall ({_needtxt}): **{mark}**")
        csu = ars.get("ret2csu")
        if csu:
            out.append(f"- **ret2csu disponible** (gadget universal __libc_csu_init): "
                       f"gadget1={csu.get('gadget1')} gadget2={csu.get('gadget2')} "
                       f"{'[completo]' if csu.get('complete') else '[parcial]'} — "
                       f"controla rdi/rsi/rdx sin `pop` directos")
        og = ars.get("one_gadget")
        if og:
            if og.get("available"):
                offs = ", ".join(og.get("offsets") or [])
                out.append(f"- **one_gadget** ({og.get('count')} magic gadgets, libc estatica "
                           f"embebida): {offs}")
                out.append(f"  - {og.get('note')}; {og.get('constraints')}")
            else:
                out.append(f"- one_gadget: no disponible ({og.get('note')})"
                           + (f" — instala: {og.get('hint')}" if og.get("hint") else ""))
        out.append("")
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


@_tool("rop_arsenal", "Arsenal ROP del binario (ELF x86): mejor gadget por registro de argumento, "
       "syscall, pivote de stack, write-what-where, movimientos reg-a-reg, cobertura execve-por-"
       "syscall, ret2csu (__libc_csu_init) y one_gadget (libc estatica). Fundamentado; no ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta al ELF"}}, ["binary"])
def _h_arsenal(args):
    from .workflows.chainanalyzer import analyze_arsenal, render_arsenal
    b = _binary(args)
    return render_arsenal(analyze_arsenal(b, None, lang="es"), lang="es")


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


@_tool("wasm_to_wat", "Desensambla un modulo .wasm a texto WAT usando WABT (wasm2wat) SI el "
       "llamador lo tiene instalado; si no, degrada indicando como obtenerlo. Integracion "
       "caller-supplied (binoracle no empaqueta WABT).",
       {"binary": {"type": "string", "description": "ruta al .wasm"}}, ["binary"])
def _h_wat(args):
    from .workflows.callertools import wat_disassemble, render_caller
    b = _binary(args)
    return render_caller("wat", wat_disassemble(b))


@_tool("pcap_summary", "Resumen de jerarquia de protocolos de un .pcap usando TShark SI el llamador "
       "lo tiene; si no, degrada. Integracion caller-supplied (binoracle no empaqueta TShark).",
       {"binary": {"type": "string", "description": "ruta al .pcap/.pcapng"}}, ["binary"])
def _h_pcap(args):
    from .workflows.callertools import pcap_summary, render_caller
    b = _binary(args)
    return render_caller("pcap", pcap_summary(b))


@_tool("firmware_scan", "Escaneo de firmas de una imagen de firmware con Binwalk (sin extraccion) SI "
       "el llamador lo tiene; si no, degrada. Integracion caller-supplied.",
       {"binary": {"type": "string", "description": "ruta a la imagen de firmware"}}, ["binary"])
def _h_fw(args):
    from .workflows.callertools import firmware_scan, render_caller
    b = _binary(args)
    return render_caller("firmware", firmware_scan(b))


@_tool("inspect_signal_decoders", "Lista los decodificadores de protocolo de sigrok (I2C/SPI/UART/"
       "USB/1-Wire...) via sigrok-cli SI el llamador lo tiene; si no, degrada. Opcional 'query' para "
       "filtrar. Integracion caller-supplied (binoracle no empaqueta sigrok). No decodifica nada aqui.",
       {"query": {"type": "string", "description": "subcadena para filtrar decodificadores (opcional)"}},
       [])
def _h_sigdec(args):
    from .workflows.callertools import signal_decoders, render_caller
    return render_caller("signal_decoders", signal_decoders((args or {}).get("query") or ""))


@_tool("decode_signal_recording", "Decodifica una captura de analizador logico (.sr) con un "
       "decodificador de protocolo de sigrok y devuelve sus anotaciones, via sigrok-cli SI el "
       "llamador lo tiene; si no, degrada. Integracion caller-supplied; salida no confiable; captura "
       "y objetivo autorizados. 'decoder' (p.ej. i2c, spi, uart) y opcional 'channels'.",
       {"binary": {"type": "string", "description": "ruta a la captura .sr (sigrok)"},
        "decoder": {"type": "string", "description": "decodificador de protocolo (i2c|spi|uart|...)"},
        "channels": {"type": "string", "description": "mapeo de canales, p.ej. 'scl=0,sda=1' (opcional)"}},
       ["binary", "decoder"])
def _h_sigdecode(args):
    from .workflows.callertools import decode_signal, render_caller
    a = args or {}
    return render_caller("signal", decode_signal(_binary(a), a.get("decoder") or "",
                                                 channels=a.get("channels") or ""))


@_tool("decompile_native", "Decompila un binario nativo (ELF/PE/Mach-O) a pseudocodigo C via el "
       "analizador headless de Ghidra SI el llamador lo tiene (Ghidra decompila estaticamente, no "
       "ejecuta el binario); si no, degrada con la pista de instalacion. Integracion caller-supplied. "
       "Opcional: 'func' para decompilar solo una funcion.",
       {"binary": {"type": "string", "description": "ruta al binario nativo"},
        "func": {"type": "string", "description": "nombre de funcion a decompilar (opcional)"}},
       ["binary"])
def _h_ghidra(args):
    from .workflows.callertools import ghidra_decompile, render_caller
    b = _binary(args)
    return render_caller("ghidra", ghidra_decompile(b, func=(args or {}).get("func")))


@_tool("analyze_function", "Analiza UNA funcion estaticamente via radare2 (desensambla, no ejecuta): "
       "info (nombre/addr/tamaño/bloques) y desensamblado. Degrada si no hay r2. 'func' por nombre o "
       "direccion.",
       {"binary": {"type": "string", "description": "ruta al binario nativo"},
        "func": {"type": "string", "description": "nombre o direccion de la funcion"}}, ["binary", "func"])
def _h_analyze_fn(args):
    from .workflows.nativequery import analyze_function, render_native_query
    a = args or {}
    return render_native_query("analyze_function", analyze_function(_binary(a), a.get("func") or ""))


@_tool("get_call_graph", "Grafo de llamadas estatico (nodos=funciones, aristas=llamadas directas) via "
       "radare2. Degrada si no hay r2. 'limit' acota el numero de funciones.",
       {"binary": {"type": "string", "description": "ruta al binario nativo"},
        "limit": {"type": "integer", "description": "maximo de funciones (def. 400)"}}, ["binary"])
def _h_callgraph(args):
    from .workflows.nativequery import get_call_graph, render_native_query
    a = args or {}
    return render_native_query("get_call_graph", get_call_graph(_binary(a), int(a.get("limit") or 400)))


@_tool("find_xrefs_to_name", "Lista todas las referencias cruzadas (call/data) que alcanzan un "
       "simbolo o funcion, via radare2 (axt). Estatico; degrada si no hay r2.",
       {"binary": {"type": "string", "description": "ruta al binario nativo"},
        "name": {"type": "string", "description": "nombre de simbolo/funcion o direccion"}}, ["binary", "name"])
def _h_xrefs(args):
    from .workflows.nativequery import find_xrefs_to_name, render_native_query
    a = args or {}
    return render_native_query("find_xrefs_to_name", find_xrefs_to_name(_binary(a), a.get("name") or ""))


@_tool("address_name", "Resuelve una direccion a su funcion contenedora y el flag/simbolo mas cercano "
       "via radare2. Estatico; degrada si no hay r2.",
       {"binary": {"type": "string", "description": "ruta al binario nativo"},
        "addr": {"type": "string", "description": "direccion (0x...) o entero"}}, ["binary", "addr"])
def _h_addrname(args):
    from .workflows.nativequery import address_name, render_native_query
    a = args or {}
    return render_native_query("address_name", address_name(_binary(a), a.get("addr") or ""))


@_tool("trace_call_path", "Encuentra una ruta de llamadas estatica entre dos funciones (BFS sobre el "
       "grafo de llamadas directas) via radare2. Estatico; degrada si no hay r2. 'src' y 'dst' por "
       "nombre o direccion.",
       {"binary": {"type": "string", "description": "ruta al binario nativo"},
        "src": {"type": "string", "description": "funcion origen"},
        "dst": {"type": "string", "description": "funcion destino"},
        "max_depth": {"type": "integer", "description": "profundidad maxima (def. 12)"}}, ["binary", "src", "dst"])
def _h_callpath(args):
    from .workflows.nativequery import call_path, render_native_query
    a = args or {}
    return render_native_query("call_path", call_path(_binary(a), a.get("src") or "", a.get("dst") or "",
                                                       max_depth=int(a.get("max_depth") or 12)))


@_tool("jeb_connect", "Conecta con un servidor MCP de JEB arrancado por el llamador (motor externo; "
       "define BINORACLE_JEB_MCP_URL o pasa 'url'). op=list lista sus herramientas; op=call invoca "
       "'name' con 'arguments'. Salida no confiable; degrada si no hay endpoint.",
       {"op": {"type": "string", "description": "list|call"},
        "name": {"type": "string", "description": "herramienta a invocar (op=call)"},
        "arguments": {"type": "object", "description": "argumentos para la herramienta (op=call)"},
        "url": {"type": "string", "description": "endpoint MCP de JEB (opcional)"}}, ["op"])
def _h_jeb(args):
    from .workflows.jebconnect import jeb_list_tools, jeb_call, render_jeb
    a = args or {}
    if a.get("op") == "call":
        return render_jeb(jeb_call(a.get("name") or "", a.get("arguments") or {}, url=a.get("url")))
    return render_jeb(jeb_list_tools(url=a.get("url")))


@_tool("ida_connect", "Conecta con un servidor MCP de IDA Pro arrancado por el llamador (motor "
       "externo; define BINORACLE_IDA_MCP_URL o pasa 'url'). op=list lista sus herramientas; op=call "
       "invoca 'name' con 'arguments'. Salida no confiable; degrada si no hay endpoint.",
       {"op": {"type": "string", "description": "list|call"},
        "name": {"type": "string", "description": "herramienta a invocar (op=call)"},
        "arguments": {"type": "object", "description": "argumentos para la herramienta (op=call)"},
        "url": {"type": "string", "description": "endpoint MCP de IDA (opcional)"}}, ["op"])
def _h_ida(args):
    from .workflows.nativeconnect import ida_list_tools, ida_call, render_ida
    a = args or {}
    if a.get("op") == "call":
        return render_ida(ida_call(a.get("name") or "", a.get("arguments") or {}, url=a.get("url")))
    return render_ida(ida_list_tools(url=a.get("url")))


@_tool("hopper_connect", "Conecta con un servidor MCP de Hopper arrancado por el llamador (motor "
       "externo; define BINORACLE_HOPPER_MCP_URL o pasa 'url'). op=list lista sus herramientas; "
       "op=call invoca 'name' con 'arguments'. Salida no confiable; degrada si no hay endpoint.",
       {"op": {"type": "string", "description": "list|call"},
        "name": {"type": "string", "description": "herramienta a invocar (op=call)"},
        "arguments": {"type": "object", "description": "argumentos para la herramienta (op=call)"},
        "url": {"type": "string", "description": "endpoint MCP de Hopper (opcional)"}}, ["op"])
def _h_hopper(args):
    from .workflows.nativeconnect import hopper_list_tools, hopper_call, render_hopper
    a = args or {}
    if a.get("op") == "call":
        return render_hopper(hopper_call(a.get("name") or "", a.get("arguments") or {}, url=a.get("url")))
    return render_hopper(hopper_list_tools(url=a.get("url")))


@_tool("record_unknown", "Registra una incognita residual del objetivo (pregunta abierta) con su "
       "obligacion para resolverse: required_authority (static-only|controlled-replay|instrumented|"
       "live) y required_confidence (asserted|observed|reproduced|verified), mas sondas sugeridas. "
       "Ledger JSON persistente ('ledger' opcional).",
       {"question": {"type": "string", "description": "la pregunta abierta"},
        "severity": {"type": "string", "description": "info|low|medium|high|critical"},
        "domain": {"type": "string", "description": "dominio (protocol|crypto|heap|...)"},
        "required_authority": {"type": "string", "description": "obligacion de fuente"},
        "required_confidence": {"type": "string", "description": "obligacion de establecimiento"},
        "ledger": {"type": "string", "description": "ruta del ledger (opcional)"}}, ["question"])
def _h_rec_unk(args):
    from .workflows.ledger import record_unknown, render_ledger
    a = args or {}
    return render_ledger(record_unknown(a.get("question") or "", a.get("severity") or "medium",
                                        a.get("domain") or "general",
                                        a.get("required_authority") or "static-only",
                                        a.get("required_confidence") or "observed",
                                        ledger=a.get("ledger")))


@_tool("record_evidence", "Registra una evidencia (observacion) con su authority y confidence y un "
       "sello de contenido sha256, para luego saldar la obligacion de una incognita.",
       {"summary": {"type": "string", "description": "resumen de la evidencia"},
        "kind": {"type": "string", "description": "tipo (observation|disasm|trace|...)"},
        "source": {"type": "string", "description": "herramienta/origen"},
        "authority": {"type": "string", "description": "static-only|controlled-replay|instrumented|live"},
        "confidence": {"type": "string", "description": "asserted|observed|reproduced|verified"},
        "ledger": {"type": "string", "description": "ruta del ledger (opcional)"}}, ["summary"])
def _h_rec_ev(args):
    from .workflows.ledger import add_evidence, render_ledger
    a = args or {}
    return render_ledger(add_evidence(a.get("summary") or "", a.get("kind") or "observation",
                                      a.get("source") or "binoracle", a.get("authority") or "static-only",
                                      a.get("confidence") or "observed", ledger=a.get("ledger")))


@_tool("update_unknown", "Actualiza una incognita con concurrencia optimista (expected_revision). "
       "Puede cambiar status (open|investigating|resolved|wont-fix), adjuntar evidencias de apoyo o "
       "contradictorias, y fijar la resolucion.",
       {"unknown_id": {"type": "string", "description": "id de la incognita"},
        "expected_revision": {"type": "integer", "description": "revision esperada (concurrencia)"},
        "status": {"type": "string", "description": "nuevo status"},
        "supporting_evidence_ids": {"type": "array", "items": {"type": "string"}, "description": "ids de apoyo"},
        "contradicting_evidence_ids": {"type": "array", "items": {"type": "string"}, "description": "ids contra"},
        "resolution": {"type": "string", "description": "texto de resolucion"},
        "ledger": {"type": "string", "description": "ruta del ledger (opcional)"}}, ["unknown_id"])
def _h_upd_unk(args):
    from .workflows.ledger import update_unknown, render_ledger
    a = args or {}
    return render_ledger(update_unknown(a.get("unknown_id") or "", a.get("expected_revision"),
                                        status=a.get("status"),
                                        supporting_evidence_ids=a.get("supporting_evidence_ids"),
                                        contradicting_evidence_ids=a.get("contradicting_evidence_ids"),
                                        resolution=a.get("resolution"), ledger=a.get("ledger")))


@_tool("list_unknowns", "Lista las incognitas residuales del ledger (mas recientes primero) con su "
       "estado y obligacion. offset/limit para paginar.",
       {"offset": {"type": "integer", "description": "desplazamiento"},
        "limit": {"type": "integer", "description": "maximo a devolver"},
        "ledger": {"type": "string", "description": "ruta del ledger (opcional)"}}, [])
def _h_list_unk(args):
    from .workflows.ledger import list_unknowns, render_ledger
    a = args or {}
    return render_ledger(list_unknowns(int(a.get("offset") or 0), int(a.get("limit") or 50),
                                       ledger=a.get("ledger")))


@_tool("verify_unknown_resolution", "Cierra una incognita SOLO si cumple su obligacion: tiene "
       "resolucion, >=1 evidencia de apoyo que alcanza authority y confidence requeridas, y ninguna "
       "evidencia contradictoria. Si no, dice que obligacion falta y la deja abierta (fundamentado).",
       {"unknown_id": {"type": "string", "description": "id de la incognita"},
        "ledger": {"type": "string", "description": "ruta del ledger (opcional)"}}, ["unknown_id"])
def _h_verify_unk(args):
    from .workflows.ledger import verify_unknown_resolution, render_ledger
    a = args or {}
    return render_ledger(verify_unknown_resolution(a.get("unknown_id") or "", ledger=a.get("ledger")))


@_tool("export_evidence_bundle", "Serializa todo el ledger (incognitas + evidencias) a un bundle "
       "JSON sellado con un digest sha256 sobre su forma canonica (detecta alteraciones al importar).",
       {"out_path": {"type": "string", "description": "ruta de salida del bundle"},
        "ledger": {"type": "string", "description": "ruta del ledger (opcional)"}}, ["out_path"])
def _h_exp_bundle(args):
    from .workflows.ledger import export_evidence_bundle, render_ledger
    a = args or {}
    return render_ledger(export_evidence_bundle(a.get("out_path") or "binoracle_bundle.json",
                                                ledger=a.get("ledger")))


@_tool("import_evidence_bundle", "Carga un bundle sellado, verifica su digest sha256 y lo importa al "
       "ledger (merge por defecto). Rechaza bundles alterados.",
       {"bundle_path": {"type": "string", "description": "ruta del bundle"},
        "merge": {"type": "boolean", "description": "fusionar (true) o reemplazar (false)"},
        "ledger": {"type": "string", "description": "ruta del ledger (opcional)"}}, ["bundle_path"])
def _h_imp_bundle(args):
    from .workflows.ledger import import_evidence_bundle, render_ledger
    a = args or {}
    merge = a.get("merge")
    return render_ledger(import_evidence_bundle(a.get("bundle_path") or "",
                                                ledger=a.get("ledger"),
                                                merge=(True if merge is None else bool(merge))))


@_tool("get_evidence_bundle", "Devuelve el ledger actual como vista de bundle con su digest canonico "
       "(cuenta de incognitas y evidencias).",
       {"ledger": {"type": "string", "description": "ruta del ledger (opcional)"}}, [])
def _h_get_bundle(args):
    from .workflows.ledger import get_evidence_bundle, render_ledger
    return render_ledger(get_evidence_bundle(ledger=(args or {}).get("ledger")))


@_tool("inspect_flutter", "Identifica una app Flutter/Dart AOT estaticamente (desde un APK o un "
       "libapp.so/libflutter.so): hashes de snapshot (fijan la revision del SDK/engine), arquitectura "
       "objetivo y modo runtime, ABIs; el engine libflutter.so (build-id=revision, linea de version "
       "de Dart, backend Impeller/Skia, API grafica Vulkan/GLES, toolchain); y el bundle "
       "flutter_assets (tipo de build AOT vs debug/JIT, AssetManifest/FontManifest, fuentes, shaders, "
       "NOTICES, version.json). No ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta a un APK o a libapp.so/libflutter.so"}}, ["binary"])
def _h_flutter(args):
    from .workflows.flutterinspect import inspect_flutter, render_flutter
    b = _binary(args)
    return render_flutter(inspect_flutter(b))


@_tool("inspect_dart_aot", "Inspecciona el snapshot AOT de Dart de una libreria (libapp.so): mapea "
       "los simbolos _kDart*Snapshot* por PT_LOAD, parsea la cabecera de cada snapshot (hash de "
       "version + cadena de features -> arquitectura objetivo x64/arm64/... y modo runtime product/"
       "profile/release) y lee la arquitectura ELF y el build-id. Lectura estatica.",
       {"binary": {"type": "string", "description": "ruta a libapp.so (o un APK que lo contenga)"}}, ["binary"])
def _h_dart(args):
    from .workflows.flutterinspect import inspect_dart_aot, render_dart_aot
    b = _binary(args)
    return render_dart_aot(inspect_dart_aot(b))


@_tool("inspect_javascript", "Lee JavaScript/Electron estaticamente: source maps (fuentes "
       "originales), imports de modulos (paquetes externos vs relativos), fronteras Electron/IPC "
       "(ipcMain/ipcRenderer, contextBridge, preload, child_process), rutas y add-ons nativos. "
       "Acepta un .js, un .js.map o un directorio de app. Heuristico; no ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta a .js / .js.map / directorio de app"}}, ["binary"])
def _h_js(args):
    from .workflows.jsinspect import inspect_js, render_js
    b = (args or {}).get("binary") or ""
    return render_js(inspect_js(b))


@_tool("recover_javascript_sources", "Reconstruye el ARBOL de fuentes original que un bundle "
       "incluyo en su .js.map (sourcesContent). Acepta un .js.map o un .js con sourceMappingURL a un "
       ".map adyacente (sin descargas remotas). Con 'out_dir' escribe los ficheros (rutas saneadas, "
       "sin traversal); sin el, solo lista. No ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta a un .js.map o .js"},
        "out_dir": {"type": "string", "description": "directorio de salida (opcional; si falta, solo lista)"}},
       ["binary"])
def _h_js_recover(args):
    from .workflows.jsinspect import recover_js_sources, render_js_recover
    a = args or {}
    return render_js_recover(recover_js_sources(_binary(a), out_dir=a.get("out_dir")))


@_tool("dynamic_adb", "Analisis RUNTIME de un dispositivo Android via adb (caller-supplied; SEPARADO "
       "del nucleo estatico; solo objetivos autorizados; salida no confiable). op: devices|packages|"
       "processes|logcat|getprop|apk-path. 'package' para apk-path, 'serial' para elegir dispositivo.",
       {"op": {"type": "string", "description": "devices|packages|processes|logcat|getprop|apk-path"},
        "package": {"type": "string", "description": "paquete (para apk-path)"},
        "serial": {"type": "string", "description": "serial del dispositivo adb (opcional)"}}, ["op"])
def _h_dyn_adb(args):
    from .workflows import dynamic as dyn
    a = args or {}
    op = a.get("op")
    serial = a.get("serial")
    table = {"devices": (lambda: dyn.adb_devices(), "adb-devices"),
             "packages": (lambda: dyn.adb_packages(serial=serial), "adb-packages"),
             "processes": (lambda: dyn.adb_processes(serial=serial), "adb-processes"),
             "logcat": (lambda: dyn.adb_logcat(serial=serial), "adb-logcat"),
             "getprop": (lambda: dyn.adb_getprop(serial=serial), "adb-getprop"),
             "apk-path": (lambda: dyn.adb_apk_path(a.get("package") or "", serial=serial), "adb-apk-path")}
    if op not in table:
        return f"op desconocida: {op}"
    fn, kind = table[op]
    return dyn.render_dynamic(kind, fn())


@_tool("dynamic_frida", "Enumeracion RUNTIME via Frida (caller-supplied; solo objetivos autorizados; "
       "NO inyecta ni instrumenta). op: devices|processes.",
       {"op": {"type": "string", "description": "devices|processes"}}, ["op"])
def _h_dyn_frida(args):
    from .workflows import dynamic as dyn
    op = (args or {}).get("op")
    if op == "devices":
        return dyn.render_dynamic("frida-devices", dyn.frida_devices())
    return dyn.render_dynamic("frida-ps", dyn.frida_processes())


@_tool("dynamic_browser", "Observacion RUNTIME de una pagina web en un Chromium local (Playwright; "
       "SEPARADO del nucleo estatico; solo objetivos autorizados). Captura URL final, titulo, "
       "scripts, peticiones/respuestas, consola, cookies/localStorage y secretos (heuristica). "
       "Observacion pasiva: no envia formularios.",
       {"url": {"type": "string", "description": "URL a observar"},
        "screenshot": {"type": "string", "description": "ruta para guardar captura (opcional)"}}, ["url"])
def _h_dyn_browser(args):
    from .workflows import dynamic as dyn
    a = args or {}
    return dyn.render_dynamic("browser", dyn.browser_observe(a.get("url") or "", screenshot=a.get("screenshot")))


@_tool("capture_process_scenario", "Captura RUNTIME de un escenario de proceso (SEPARADO del nucleo "
       "estatico; EJECUTA el objetivo -> solo objetivos AUTORIZADOS; salida no confiable). Corre el "
       "binario una vez con timeout acotado y registra argv, codigo de salida, bucket de duracion y "
       "stdout/stderr NORMALIZADOS (direcciones/PIDs/timestamps colapsados), con sello sha256. "
       "Opcional: 'args' (lista), 'stdin', 'out_path' para guardar la captura.",
       {"binary": {"type": "string", "description": "ruta al ejecutable objetivo"},
        "args": {"type": "array", "items": {"type": "string"}, "description": "argumentos (opcional)"},
        "stdin": {"type": "string", "description": "datos para stdin (opcional)"},
        "out_path": {"type": "string", "description": "ruta para guardar la captura JSON (opcional)"},
        "timeout": {"type": "integer", "description": "timeout en segundos (def. 20)"}}, ["binary"])
def _h_proc_capture(args):
    from .workflows.proccapture import capture_process, render_capture
    a = args or {}
    argv = [_binary(a)] + list(a.get("args") or [])
    stdin = (a.get("stdin") or "").encode("utf-8", "replace")
    return render_capture(capture_process(argv, stdin_data=stdin,
                                          timeout=int(a.get("timeout") or 20),
                                          out_path=a.get("out_path")))


@_tool("compare_process_captures", "Compara dos capturas de escenario de proceso (rutas JSON de "
       "capture_process_scenario) y resalta el comportamiento cambiado: codigo de salida/timeout, "
       "bucket de duracion y un diff unificado de stdout/stderr normalizados. 'identical' es cierto "
       "solo si los sellos coinciden.",
       {"a": {"type": "string", "description": "ruta de la captura A"},
        "b": {"type": "string", "description": "ruta de la captura B"}}, ["a", "b"])
def _h_proc_compare(args):
    from .workflows.proccapture import compare_captures, render_compare
    a = args or {}
    return render_compare(compare_captures(a.get("a") or "", a.get("b") or ""))


@_tool("find_changed_behavior", "Ejecuta DOS builds (A y B) con la MISMA entrada y reporta como "
       "difiere su comportamiento observable: codigo de salida, timing y diff normalizado de stdout/"
       "stderr. RUNTIME, solo objetivos AUTORIZADOS; salida no confiable. Contraparte runtime de "
       "patchdiff. Opcional 'args' (lista) y 'stdin'.",
       {"a": {"type": "string", "description": "ruta al binario A"},
        "b": {"type": "string", "description": "ruta al binario B"},
        "args": {"type": "array", "items": {"type": "string"}, "description": "argumentos (opcional)"},
        "stdin": {"type": "string", "description": "datos para stdin (opcional)"},
        "timeout": {"type": "integer", "description": "timeout en segundos (def. 20)"}}, ["a", "b"])
def _h_changed(args):
    from .workflows.proccapture import find_changed_behavior, render_changed_behavior
    a = args or {}
    return render_changed_behavior(find_changed_behavior(
        a.get("a") or "", a.get("b") or "", args=a.get("args"),
        stdin_data=(a.get("stdin") or "").encode("utf-8", "replace"), timeout=int(a.get("timeout") or 20)))


@_tool("correlate_static_and_runtime", "Ejecuta el objetivo una vez y correlaciona su salida runtime "
       "con hechos ESTATICOS (nombres de simbolos dinamicos del ELF + 'markers' del llamador), "
       "reportando que nombres presentes estaticamente dejaron una traza observable. RUNTIME, solo "
       "AUTORIZADOS; salida no confiable; la correlacion es una traza, no prueba de ejecucion.",
       {"binary": {"type": "string", "description": "ruta al binario objetivo"},
        "args": {"type": "array", "items": {"type": "string"}, "description": "argumentos (opcional)"},
        "stdin": {"type": "string", "description": "datos para stdin (opcional)"},
        "markers": {"type": "array", "items": {"type": "string"}, "description": "cadenas de interes (opcional)"},
        "timeout": {"type": "integer", "description": "timeout en segundos (def. 20)"}}, ["binary"])
def _h_correlate(args):
    from .workflows.proccapture import correlate_static_and_runtime, render_correlate
    a = args or {}
    return render_correlate(correlate_static_and_runtime(
        _binary(a), args=a.get("args"), markers=a.get("markers"),
        stdin_data=(a.get("stdin") or "").encode("utf-8", "replace"), timeout=int(a.get("timeout") or 20)))


@_tool("apk_decompile", "Decompila el DEX de un APK a codigo Java via JADX (un decompilador: no "
       "ejecuta la app) SI el llamador lo tiene; si no, degrada. Devuelve un resumen de clases "
       "recuperadas. Integracion caller-supplied.",
       {"binary": {"type": "string", "description": "ruta al .apk"}}, ["binary"])
def _h_jadx(args):
    from .workflows.callertools import jadx_decompile, render_caller
    b = _binary(args)
    return render_caller("jadx", jadx_decompile(b))


@_tool("search_android_classes", "Lista las clases decompiladas de un APK cuyo nombre completo "
       "contiene una subcadena, via JADX (decompila, no ejecuta). Degrada si no hay JADX.",
       {"binary": {"type": "string", "description": "ruta al .apk"},
        "query": {"type": "string", "description": "subcadena del nombre de clase (opcional)"}}, ["binary"])
def _h_android_search(args):
    from .workflows.androidquery import search_android_classes, render_android_query
    a = args or {}
    return render_android_query("search", search_android_classes(_binary(a), a.get("query") or ""))


@_tool("inspect_android_class", "Devuelve el Java decompilado de una clase de un APK (+ sus metodos "
       "declarados), via JADX. Estatico; degrada si no hay JADX.",
       {"binary": {"type": "string", "description": "ruta al .apk"},
        "classname": {"type": "string", "description": "nombre completo de la clase (p.ej. com.app.MainActivity)"}},
       ["binary", "classname"])
def _h_android_class(args):
    from .workflows.androidquery import inspect_android_class, render_android_query
    a = args or {}
    return render_android_query("class", inspect_android_class(_binary(a), a.get("classname") or ""))


@_tool("inspect_android_package", "Lista las clases declaradas bajo un prefijo de paquete de un APK, "
       "via JADX. Estatico; degrada si no hay JADX.",
       {"binary": {"type": "string", "description": "ruta al .apk"},
        "package": {"type": "string", "description": "prefijo de paquete (p.ej. com.app.net)"}},
       ["binary", "package"])
def _h_android_pkg(args):
    from .workflows.androidquery import inspect_android_package, render_android_query
    a = args or {}
    return render_android_query("package", inspect_android_package(_binary(a), a.get("package") or ""))


@_tool("trace_android_references", "Lista cada sitio decompilado que menciona un identificador "
       "(clase/metodo/campo/cadena) de un APK como clase:linea, via JADX. Grep estatico; degrada si "
       "no hay JADX.",
       {"binary": {"type": "string", "description": "ruta al .apk"},
        "name": {"type": "string", "description": "identificador a rastrear"}}, ["binary", "name"])
def _h_android_refs(args):
    from .workflows.androidquery import trace_android_references, render_android_query
    a = args or {}
    return render_android_query("references", trace_android_references(_binary(a), a.get("name") or ""))


@_tool("apk_manifest", "Decodifica el AndroidManifest.xml binario de un APK (paquete, permisos, "
       "componentes) via Apktool SI el llamador lo tiene; si no, degrada. Integracion caller-supplied "
       "(completa inspect_apk, que detecta el manifest pero no lo decodifica).",
       {"binary": {"type": "string", "description": "ruta al .apk"}}, ["binary"])
def _h_manifest(args):
    from .workflows.callertools import apktool_manifest, render_caller
    b = _binary(args)
    return render_caller("manifest", apktool_manifest(b))


@_tool("one_gadget", "Lista los 'magic gadgets' (una sola direccion que lanza shell) de una libc, "
       "via one_gadget SI el llamador lo tiene; si no, degrada. Integracion caller-supplied.",
       {"binary": {"type": "string", "description": "ruta a la libc (libc.so.6)"}}, ["binary"])
def _h_onegadget(args):
    from .workflows.callertools import one_gadget, render_caller
    b = _binary(args)
    return render_caller("one_gadget", one_gadget(b))


@_tool("pcap_fileinfo", "Metadata de un fichero de captura (numero de paquetes, duracion, tasas) "
       "via capinfos SI el llamador lo tiene; si no, degrada. Integracion caller-supplied.",
       {"binary": {"type": "string", "description": "ruta al .pcap/.pcapng"}}, ["binary"])
def _h_capinfos(args):
    from .workflows.callertools import pcap_fileinfo, render_caller
    b = _binary(args)
    return render_caller("capinfos", pcap_fileinfo(b))


@_tool("inspect_pe", "Lee un PE de Windows (EXE/DLL) estaticamente: arquitectura, secciones con "
       "entropia (heuristica de packing), mitigaciones (ASLR/DEP/CFG/SafeSEH), imports y un mapa "
       "de capacidades (proceso/red/cripto/inyeccion/registro/anti-debug). No ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta al PE (.exe/.dll)"}}, ["binary"])
def _h_pe(args):
    from .workflows.peinspect import inspect_pe, render_pe
    b = _binary(args)
    return render_pe(inspect_pe(b))


@_tool("identify_artifact", "Detecta el formato de CUALQUIER fichero (ELF/core/Mach-O/PE·.NET/WASM/"
       "SQLite/APK/HAR/Go) y lo enruta al lector adecuado de binoracle, devolviendo su analisis. "
       "La puerta de entrada 'reverse engineer anything'. No ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta a cualquier artefacto"}}, ["binary"])
def _h_identify(args):
    from .workflows.identify import identify, render_identify
    b = _binary(args)
    return render_identify(identify(b))


@_tool("inspect_apk", "Lee un APK de Android (ZIP) estaticamente: DEX, librerias nativas por ABI, "
       "framework (Flutter/React Native/Unity/Xamarin), firma (v1 JAR y bloque v2/v3) y digests "
       "SHA-256 de los snapshots Flutter (libapp.so). No decodifica el AndroidManifest binario.",
       {"binary": {"type": "string", "description": "ruta al .apk"}}, ["binary"])
def _h_apk(args):
    from .workflows.apkinspect import inspect_apk, render_apk
    b = _binary(args)
    return render_apk(inspect_apk(b))


@_tool("inspect_macho", "Lee un binario Mach-O (macOS) estaticamente: arquitectura, tipo, "
       "segmentos y protecciones, dylibs enlazadas (LC_LOAD_DYLIB), entrypoint (LC_MAIN) y "
       "flags de mitigacion (PIE, pila ejecutable). Detecta binarios universales (fat). No ejecuta.",
       {"binary": {"type": "string", "description": "ruta al Mach-O"}}, ["binary"])
def _h_macho(args):
    from .workflows.machoinspect import inspect_macho, render_macho
    b = _binary(args)
    return render_macho(inspect_macho(b))


@_tool("inspect_dotnet_assembly", "Lee un ensamblado .NET/CLI (PE gestionado) estaticamente: "
       "version de runtime/metadata, streams, conteos de tablas de metadata (Module/TypeDef/"
       "MethodDef/Assembly...) y una muestra del heap de nombres #Strings. No ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta al .dll/.exe gestionado"}}, ["binary"])
def _h_dotnet(args):
    from .workflows.dotnetinspect import inspect_dotnet, render_dotnet
    b = _binary(args)
    return render_dotnet(inspect_dotnet(b))


@_tool("compare_managed_members", "Compara dos ensamblados .NET a nivel de nombres de miembros "
       "(heap #Strings) y forma de tablas de metadata: añadidos, eliminados y cambios de conteo de "
       "tabla. Estatico; no desensambla CIL.",
       {"a": {"type": "string", "description": "ruta al ensamblado A"},
        "b": {"type": "string", "description": "ruta al ensamblado B"}}, ["a", "b"])
def _h_managed_compare(args):
    from .workflows.managedquery import compare_managed_members, render_managed
    a = args or {}
    return render_managed("compare", compare_managed_members(a.get("a") or "", a.get("b") or ""))


@_tool("verify_reconstruction", "Verifica cuan fielmente un ensamblado .NET reconstruido reproduce "
       "al original (cobertura de nombres de miembros + similitud de forma de tablas), y declara la "
       "obligacion cumplida o no (no afirma fidelidad sin alcanzar el umbral). Estatico.",
       {"original": {"type": "string", "description": "ensamblado original"},
        "reconstructed": {"type": "string", "description": "ensamblado reconstruido"},
        "threshold": {"type": "number", "description": "umbral de cobertura (def. 0.9)"}}, ["original", "reconstructed"])
def _h_managed_verify(args):
    from .workflows.managedquery import verify_reconstruction, render_managed
    a = args or {}
    return render_managed("verify", verify_reconstruction(
        a.get("original") or "", a.get("reconstructed") or "", threshold=float(a.get("threshold") or 0.9)))


@_tool("verify_managed_native_boundaries", "Expone la frontera gestionado<->nativo de un ensamblado "
       ".NET: el tamaño de la tabla P/Invoke ImplMap y los nombres de librerias nativas presentes en "
       "#Strings. Estatico.",
       {"binary": {"type": "string", "description": "ruta al ensamblado .NET"}}, ["binary"])
def _h_managed_boundaries(args):
    from .workflows.managedquery import verify_managed_native_boundaries, render_managed
    return render_managed("boundaries", verify_managed_native_boundaries(_binary(args)))


@_tool("inspect_java", "Lee un artefacto Java estaticamente: un JAR (ZIP) -> manifiesto "
       "(Main-Class/versiones), inventario de clases/paquetes, framework (Spring/Jakarta/Kotlin/"
       "Scala/Android), firma y version de bytecode; o un .class suelto -> magic/version y "
       "clase/superclase del constant pool. No desensambla ni ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta al .jar o .class"}}, ["binary"])
def _h_java(args):
    from .workflows.jarinspect import inspect_jar, render_jar
    b = _binary(args)
    return render_jar(inspect_jar(b))


@_tool("scan_iocs", "Escanea CUALQUIER artefacto (ELF/PE/firmware/config/...) en busca de IOCs y "
       "secretos embebidos: URLs, hosts, IPs, emails, credenciales cloud/API (AWS/GCP/Slack/GitHub/"
       "Stripe), JWT, cabeceras PEM de clave privada y tokens de alta entropia. Heuristico; no "
       "ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta a cualquier fichero"}}, ["binary"])
def _h_iocscan(args):
    from .workflows.iocscan import scan_iocs, render_iocs
    b = _binary(args)
    return render_iocs(scan_iocs(b))


@_tool("inspect_plist", "Lee un property-list de Apple (Info.plist binario bplist00 o XML) "
       "estaticamente: bundle id, ejecutable, versiones, min OS, esquemas URL y las claves de "
       "privacidad NS*UsageDescription (lo que la app toca). No ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta al fichero .plist"}}, ["binary"])
def _h_plist(args):
    from .workflows.plistinspect import inspect_plist, render_plist
    b = _binary(args)
    return render_plist(inspect_plist(b))


@_tool("inspect_asar", "Lee un archivo ASAR de Electron (app.asar) estaticamente: arbol de "
       "ficheros, package.json (nombre/version/main/dependencias), modulos JS y bloques de "
       "integridad. Extrae package.json por offset pero NO ejecuta ni desminifica JS.",
       {"binary": {"type": "string", "description": "ruta al archivo .asar"}}, ["binary"])
def _h_asar(args):
    from .workflows.asarinspect import inspect_asar, render_asar
    b = _binary(args)
    return render_asar(inspect_asar(b))


@_tool("inspect_har_capture", "Lee una captura de red HAR (JSON) estaticamente: peticiones/"
       "respuestas, hosts, y SECRETOS expuestos (Authorization/Bearer, api_key/token/password, "
       "JWT, claves AWS) en URL/cabeceras/cuerpo. Heuristico; no descifra TLS.",
       {"binary": {"type": "string", "description": "ruta al fichero .har"}}, ["binary"])
def _h_har(args):
    from .workflows.harinspect import inspect_har, render_har
    b = _binary(args)
    return render_har(inspect_har(b))


@_tool("inspect_sqlite_database", "Abre una base SQLite en SOLO LECTURA y reporta su esquema "
       "(tablas, columnas, indices, vistas, triggers) y una muestra acotada de filas. No escribe "
       "nada ni dispara triggers.",
       {"binary": {"type": "string", "description": "ruta al fichero .sqlite/.db"}}, ["binary"])
def _h_sqlite(args):
    from .workflows.sqliteinspect import inspect_sqlite, render_sqlite
    b = _binary(args)
    return render_sqlite(inspect_sqlite(b))


@_tool("inspect_evm_bytecode", "Lee bytecode EVM (raw o hex) estaticamente: selectores de funcion "
       "(heuristica PUSH4), opcodes de capacidad (CALL/DELEGATECALL/CREATE/SELFDESTRUCT) y la "
       "metadata CBOR de Solidity (version de solc, hash IPFS/Swarm). No ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta al bytecode (raw o hex)"}}, ["binary"])
def _h_evm(args):
    from .workflows.evminspect import inspect_evm, render_evm
    b = _binary(args)
    return render_evm(inspect_evm(b))


@_tool("inspect_wasm_artifact", "Lee un modulo WebAssembly (.wasm) estaticamente: version, "
       "secciones, firmas de tipos, imports y exports con su kind. No decodifica cuerpos a WAT "
       "(eso requiere WABT). No ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta al modulo .wasm"}}, ["binary"])
def _h_wasm(args):
    from .workflows.wasminspect import inspect_wasm, render_wasm
    b = _binary(args)
    return render_wasm(inspect_wasm(b))


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
_exploit_tool("autocsu", "ret2csu: gadgets universales de __libc_csu_init fijan rdi/rsi/rdx y hacen "
              "una llamada indirecta (sin pop rsi/rdx directos), verificado en sandbox.",
              lambda: (__import__("binoracle.workflows.autocsu", fromlist=["autocsu"]).autocsu,
                       __import__("binoracle.workflows.autocsu", fromlist=["render_csu"]).render_csu))
_exploit_tool("autopivot", "stack pivot: overflow corto -> migra RSP a un buffer fijo en .bss con la "
              "cadena escalonada (saved rbp=&buf, saved rip=`leave; ret`), verificado en sandbox.",
              lambda: (__import__("binoracle.workflows.autopivot", fromlist=["autopivot"]).autopivot,
                       __import__("binoracle.workflows.autopivot", fromlist=["render_pivot"]).render_pivot))
_exploit_tool("autohof", "house-of-force: sobrescribe el tamano del top chunk -> alloc huge mueve "
              "`top` a direccion arbitraria -> escritura -> hijack de puntero de funcion -> shell, "
              "verificado en sandbox (glibc >=2.29 lo mitiga; se usa un asignador pre-2.29).",
              lambda: (__import__("binoracle.workflows.autohof", fromlist=["autohof"]).autohof,
                       __import__("binoracle.workflows.autohof", fromlist=["render_hof"]).render_hof))
_exploit_tool("autohos", "house-of-spirit: libera un chunk FALSO que entra en tcache; el siguiente "
              "malloc lo devuelve -> escritura sobre un puntero de funcion -> shell. Verificado en "
              "sandbox (tcache de glibc real; no mitigado).",
              lambda: (__import__("binoracle.workflows.autohos", fromlist=["autohos"]).autohos,
                       __import__("binoracle.workflows.autohos", fromlist=["render_hos"]).render_hos))
_exploit_tool("autohoe", "house-of-einherjar: consolidacion hacia atras (prev_size forjado + "
              "PREV_INUSE limpio) -> el chunk liberado aterriza en una direccion arbitraria -> "
              "escritura -> hijack -> shell. Verificado en sandbox.",
              lambda: (__import__("binoracle.workflows.autohoe", fromlist=["autohoe"]).autohoe,
                       __import__("binoracle.workflows.autohoe", fromlist=["render_hoe"]).render_hoe))
_exploit_tool("autobotcake", "house-of-botcake: doble-free enrutado por la unsorted bin (esquiva el "
              "key del tcache) -> chunks solapados -> tcache poison con safe-linking -> alloc sobre "
              "un puntero de funcion -> shell. Verificado en glibc real 2.39.",
              lambda: (__import__("binoracle.workflows.autobotcake", fromlist=["autobotcake"]).autobotcake,
                       __import__("binoracle.workflows.autobotcake", fromlist=["render_botcake"]).render_botcake))
_exploit_tool("autolargebin", "largebin attack: una insercion en largebin con bk_nextsize corrupto "
              "ejecuta `victim->bk_nextsize->fd_nextsize = victim` -> escritura de puntero arbitraria "
              "-> hijack -> shell. Verificado en sandbox.",
              lambda: (__import__("binoracle.workflows.autolargebin", fromlist=["autolargebin"]).autolargebin,
                       __import__("binoracle.workflows.autolargebin", fromlist=["render_largebin"]).render_largebin))
_exploit_tool("autostash", "tcache stashing unlink: un stash de smallbin->tcache con bk corrupto "
              "mete un chunk falso en el tcache (satisface el chequeo >=2.31 `bck->fd==tc_victim`, "
              "disparo via calloc) -> alloc en direccion elegida -> hijack -> shell. Verificado en sandbox.",
              lambda: (__import__("binoracle.workflows.autostash", fromlist=["autostash"]).autostash,
                       __import__("binoracle.workflows.autostash", fromlist=["render_stash"]).render_stash))


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
