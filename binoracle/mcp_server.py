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


@_tool("inspect_javascript", "Lee JavaScript/Electron estaticamente: source maps (fuentes "
       "originales), imports de modulos (paquetes externos vs relativos), fronteras Electron/IPC "
       "(ipcMain/ipcRenderer, contextBridge, preload, child_process), rutas y add-ons nativos. "
       "Acepta un .js, un .js.map o un directorio de app. Heuristico; no ejecuta nada.",
       {"binary": {"type": "string", "description": "ruta a .js / .js.map / directorio de app"}}, ["binary"])
def _h_js(args):
    from .workflows.jsinspect import inspect_js, render_js
    b = (args or {}).get("binary") or ""
    return render_js(inspect_js(b))


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


@_tool("apk_decompile", "Decompila el DEX de un APK a codigo Java via JADX (un decompilador: no "
       "ejecuta la app) SI el llamador lo tiene; si no, degrada. Devuelve un resumen de clases "
       "recuperadas. Integracion caller-supplied.",
       {"binary": {"type": "string", "description": "ruta al .apk"}}, ["binary"])
def _h_jadx(args):
    from .workflows.callertools import jadx_decompile, render_caller
    b = _binary(args)
    return render_caller("jadx", jadx_decompile(b))


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
