"""Optional caller-supplied tool integrations: run an external tool if present, degrade if not.

Some reversing steps need a heavy external tool (WABT for WAT disassembly, TShark for pcap
summaries, Binwalk for firmware signatures). binoracle does NOT bundle them -- that would break
the offline, dependency-light design -- but will drive one when the caller has installed it, and
degrade honestly (naming the tool and how to get it) when it is absent. Each runner passes the
artifact path as an argument (never through a shell), bounds the runtime, and treats the tool's
output as untrusted data derived from the artifact. For AUTHORIZED analysis."""
from __future__ import annotations

import shutil
import subprocess

_INSTALL = {
    "wasm2wat": "WABT (https://github.com/WebAssembly/wabt): instala 'wabt' y usa wasm2wat",
    "tshark": "Wireshark/TShark (apt install tshark); capinfos viene con el paquete",
    "capinfos": "parte de Wireshark/TShark (apt install tshark)",
    "binwalk": "Binwalk (pip install binwalk / apt install binwalk)",
    "one_gadget": "one_gadget (gem install one_gadget): magic gadgets de una libc",
    "apktool": "Apktool (https://apktool.org): decodifica el AndroidManifest.xml binario y recursos",
    "jadx": "JADX (https://github.com/skylot/jadx): decompila DEX a codigo Java",
    "analyzeHeadless": "Ghidra (https://ghidra-sre.org): decompilador nativo; define GHIDRA_INSTALL_DIR "
                       "o pon support/analyzeHeadless en el PATH",
    "sigrok-cli": "sigrok-cli (https://sigrok.org / apt install sigrok-cli): decodificadores de "
                  "protocolo (I2C/SPI/UART/USB/1-Wire...) sobre capturas de analizador logico",
}


def _find_ghidra_headless():
    """Localiza el lanzador headless de Ghidra: en el PATH, o bajo GHIDRA_INSTALL_DIR/GHIDRA_HOME/
    support/. Devuelve la ruta o None (sin ejecutar nada)."""
    import os
    exe = shutil.which("analyzeHeadless")
    if exe:
        return exe
    for env in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME", "GHIDRA_DIR"):
        base = os.environ.get(env)
        if base:
            cand = os.path.join(base, "support", "analyzeHeadless")
            if os.path.exists(cand):
                return cand
    return None


# postScript Jython que corre dentro de Ghidra: decompila funciones y vuelca su pseudocodigo C
# delimitado por marcadores que luego parseamos de la salida (ruidosa) de analyzeHeadless.
_GHIDRA_DECOMP_SCRIPT = r'''# -*- coding: utf-8 -*-
# binoracle headless decompile post-script (Jython, runs inside Ghidra). Emits each function's
# pseudocode between <<<BINO_FN ...>>> markers. Bounded by BINORACLE_DECOMP_MAX functions.
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
di = DecompInterface()
di.openProgram(currentProgram)
want = os.environ.get("BINORACLE_DECOMP_FN") or ""
try:
    maxfn = int(os.environ.get("BINORACLE_DECOMP_MAX") or "40")
except Exception:
    maxfn = 40
mon = ConsoleTaskMonitor()
n = 0
for f in currentProgram.getFunctionManager().getFunctions(True):
    if want and f.getName() != want:
        continue
    if f.isExternal() or f.isThunk():
        continue
    res = di.decompileFunction(f, 60, mon)
    if res is None or not res.decompileCompleted():
        continue
    df = res.getDecompiledFunction()
    if df is None:
        continue
    print("<<<BINO_FN %s @ %s>>>" % (f.getName(), f.getEntryPoint()))
    print(df.getC())
    print("<<<BINO_END>>>")
    n += 1
    if n >= maxfn:
        break
print("<<<BINO_COUNT %d>>>" % n)
'''


def ghidra_decompile(binary: str, func: str = None, max_functions: int = 40, timeout: int = 300) -> dict:
    """Decompile a native binary to C pseudocode via Ghidra's headless analyzer, IF the caller has
    Ghidra installed. Ghidra DECOMPILES statically -- it never runs the target. Imports into a
    throwaway project dir (removed afterwards). Output is untrusted (derived from the binary).
    Returns {ok, functions:[{name,addr,pseudocode}], count} or an honest degrade."""
    import os
    import shutil as _sh
    import tempfile
    headless = _find_ghidra_headless()
    if headless is None:
        return _missing("analyzeHeadless")
    proj = tempfile.mkdtemp(prefix="binoracle_ghidra_")
    spath = tempfile.mkdtemp(prefix="binoracle_gscript_")
    try:
        script_file = os.path.join(spath, "binoracle_decomp.py")
        with open(script_file, "w") as fh:
            fh.write(_GHIDRA_DECOMP_SCRIPT)
        env = dict(os.environ)
        env["BINORACLE_DECOMP_MAX"] = str(int(max_functions))
        if func:
            env["BINORACLE_DECOMP_FN"] = func
        argv = [headless, proj, "binoracle_proj", "-import", binary, "-scriptPath", spath,
                "-postScript", "binoracle_decomp.py", "-deleteProject", "-analysisTimeoutPerFile",
                str(max(30, timeout - 30))]
        try:
            p = subprocess.run(argv, capture_output=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            return {"ok": False, "available": True, "tool": "analyzeHeadless",
                    "note": f"Ghidra excedio {timeout}s (binario grande; sube el timeout o fija una funcion)"}
        out = p.stdout.decode("utf-8", "replace")
        funcs = parse_ghidra_pseudocode(out)
        if not funcs:
            tail = (p.stderr.decode("utf-8", "replace") or out)[-300:]
            return {"ok": False, "available": True, "tool": "analyzeHeadless",
                    "note": f"Ghidra no produjo pseudocodigo (¿binario no soportado?). {tail}"}
        return {"ok": True, "available": True, "tool": "ghidra", "functions": funcs,
                "count": len(funcs),
                "limitations": ["pseudocodigo del decompilador de Ghidra (no verificado por binoracle); "
                                "Ghidra decompila estaticamente, no ejecuta el binario"]}
    except Exception as e:
        return {"ok": False, "available": True, "tool": "analyzeHeadless", "note": f"fallo Ghidra: {e}"}
    finally:
        _sh.rmtree(proj, ignore_errors=True)
        _sh.rmtree(spath, ignore_errors=True)


def parse_ghidra_pseudocode(out: str) -> list:
    """Extrae los bloques <<<BINO_FN name @ addr>>> ... <<<BINO_END>>> del stdout de analyzeHeadless.
    Pura y testeable sin Ghidra."""
    import re as _re
    funcs = []
    for m in _re.finditer(r"<<<BINO_FN (.+?) @ (\S+)>>>\n(.*?)\n<<<BINO_END>>>", out, _re.S):
        funcs.append({"name": m.group(1), "addr": m.group(2),
                      "pseudocode": m.group(3).rstrip()})
    return funcs


def _missing(tool: str) -> dict:
    return {"ok": False, "available": False, "tool": tool,
            "note": f"herramienta caller-supplied ausente: {tool}. {_INSTALL.get(tool, 'instalala y reintenta')}"}


def run_caller_tool(argv, timeout: int = 60) -> dict:
    """Run an external tool by argv (no shell). Returns {ok, available, stdout, stderr, code} or a
    degrade dict when the tool is absent. Output is untrusted (derived from the analyzed artifact)."""
    tool = argv[0]
    if shutil.which(tool) is None:
        return _missing(tool)
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "available": True, "tool": tool, "note": f"{tool} excedio {timeout}s"}
    except Exception as e:
        return {"ok": False, "available": True, "tool": tool, "note": f"fallo al ejecutar {tool}: {e}"}
    return {"ok": True, "available": True, "tool": tool, "code": p.returncode,
            "stdout": p.stdout.decode("utf-8", "replace"), "stderr": p.stderr.decode("utf-8", "replace")}


def wat_disassemble(wasm_path: str, timeout: int = 60) -> dict:
    """WAT text for a .wasm module, via WABT's wasm2wat if the caller supplied it."""
    r = run_caller_tool(["wasm2wat", wasm_path], timeout)
    if not r.get("ok"):
        return r
    wat = r["stdout"]
    return {"ok": True, "available": True, "tool": "wasm2wat", "wat": wat,
            "functions": wat.count("(func "), "limitations": ["salida de WABT (no verificada por binoracle)"]}


def pcap_summary(pcap_path: str, timeout: int = 90) -> dict:
    """Protocol-hierarchy summary of a pcap, via TShark if the caller supplied it."""
    r = run_caller_tool(["tshark", "-r", pcap_path, "-q", "-z", "io,phs"], timeout)
    if not r.get("ok"):
        return r
    return {"ok": True, "available": True, "tool": "tshark", "protocol_hierarchy": r["stdout"],
            "limitations": ["salida de TShark; no se descifra TLS"]}


def firmware_scan(path: str, timeout: int = 120) -> dict:
    """Signature scan of a firmware image, via Binwalk if present (no extraction -> no files written)."""
    r = run_caller_tool(["binwalk", "-B", path], timeout)
    if not r.get("ok"):
        return r
    lines = [ln for ln in r["stdout"].splitlines() if ln.strip()]
    sigs = [ln for ln in lines if ln[:1].isdigit()]        # table rows start with a decimal offset
    return {"ok": True, "available": True, "tool": "binwalk", "signatures": sigs[:200],
            "signature_count": len(sigs), "raw": r["stdout"][:4000],
            "limitations": ["escaneo de firmas (sin extraccion); salida de Binwalk"]}


def signal_decoders(query: str = "", timeout: int = 60) -> dict:
    """inspect_signal_decoders: list the protocol decoders sigrok offers (I2C/SPI/UART/USB/...),
    optionally filtered by a substring, via sigrok-cli if the caller supplied it. Nothing is
    recorded or decoded here -- this only enumerates the engine's catalog."""
    r = run_caller_tool(["sigrok-cli", "--list-supported"], timeout)
    if not r.get("ok"):
        return r
    decoders = []
    in_section = False
    for ln in (r["stdout"] or "").splitlines():
        if ln.startswith("Supported protocol decoders:"):
            in_section = True
            continue
        if in_section:
            if not ln.strip() or not ln.startswith("  "):
                if ln.strip() and not ln.startswith("  "):
                    in_section = False
                continue
            parts = ln.strip().split(None, 1)
            if parts:
                did, name = parts[0], (parts[1] if len(parts) > 1 else "")
                if not query or query.lower() in (did + " " + name).lower():
                    decoders.append({"id": did, "name": name})
    return {"ok": True, "available": True, "tool": "sigrok-cli", "decoders": decoders,
            "decoder_count": len(decoders),
            "limitations": ["catalogo de sigrok (no verificado por binoracle)"]}


def decode_signal(recording_path: str, decoder: str, channels: str = "", timeout: int = 120) -> dict:
    """decode_signal_recording: decode a logic-analyzer capture (.sr) with a sigrok protocol decoder
    and return its annotations, via sigrok-cli if present. The capture path is passed as an argument
    (never through a shell); the decoder output is untrusted data derived from the capture."""
    argv = ["sigrok-cli", "-i", recording_path, "-P", decoder, "-A", decoder]
    if channels:
        argv += ["-C", channels]
    r = run_caller_tool(argv, timeout)
    if not r.get("ok"):
        return r
    annotations = [ln for ln in (r["stdout"] or "").splitlines() if ln.strip()]
    return {"ok": True, "available": True, "tool": "sigrok-cli", "decoder": decoder,
            "annotations": annotations[:500], "annotation_count": len(annotations),
            "raw": (r["stdout"] or "")[:8000],
            "limitations": ["anotaciones de sigrok (" + decoder + "); salida no verificada; "
                            "objetivo/captura autorizados"]}


def one_gadget(libc_path: str, timeout: int = 60) -> dict:
    """libc-relative 'magic gadget' offsets (a single address that spawns a shell), via one_gadget."""
    r = run_caller_tool(["one_gadget", "--raw", libc_path], timeout)
    if not r.get("ok"):
        return r
    offs = []
    for tok in (r["stdout"] or "").split():
        try:
            offs.append(int(tok, 0))
        except ValueError:
            pass
    return {"ok": True, "available": True, "tool": "one_gadget",
            "gadgets": [hex(o) for o in offs], "count": len(offs),
            "limitations": ["offsets relativos a la libc; sus restricciones de registros se validan "
                            "por ejecucion (autolibc ya las filtra al verificar ret2libc)"]}


def pcap_fileinfo(pcap_path: str, timeout: int = 30) -> dict:
    """Capture file metadata (packet count, duration, data rates) via capinfos."""
    r = run_caller_tool(["capinfos", pcap_path], timeout)
    if not r.get("ok"):
        return r
    info = {}
    for line in (r["stdout"] or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    return {"ok": True, "available": True, "tool": "capinfos", "info": info,
            "limitations": ["salida de capinfos"]}


def apktool_manifest(apk_path: str, timeout: int = 120) -> dict:
    """Decode the binary AndroidManifest.xml (package, permissions, components) via Apktool. Runs
    into a throwaway temp dir (-s skips DEX disassembly); the dir is removed afterwards."""
    import shutil as _sh
    import tempfile
    import os
    if _sh.which("apktool") is None:
        return _missing("apktool")
    tmp = tempfile.mkdtemp(prefix="binoracle_apktool_")
    try:
        r = run_caller_tool(["apktool", "d", "-f", "-s", "-o", tmp, apk_path], timeout)
        if not r.get("ok"):
            return r
        mpath = os.path.join(tmp, "AndroidManifest.xml")
        if not os.path.exists(mpath):
            return {"ok": False, "available": True, "tool": "apktool",
                    "note": "apktool no produjo AndroidManifest.xml"}
        import xml.etree.ElementTree as ET
        tree = ET.parse(mpath)
        root = tree.getroot()
        ns = "{http://schemas.android.com/apk/res/android}"
        pkg = root.get("package")
        perms = [e.get(ns + "name") for e in root.iter("uses-permission") if e.get(ns + "name")]
        comps = {"activity": [], "service": [], "receiver": [], "provider": []}
        app = root.find("application")
        if app is not None:
            for tag in comps:
                for e in app.iter(tag):
                    nm = e.get(ns + "name")
                    if nm:
                        comps[tag].append(nm)
        return {"ok": True, "available": True, "tool": "apktool", "package": pkg,
                "permissions": perms, "components": {k: v for k, v in comps.items() if v},
                "limitations": ["decodificado por Apktool en un dir temporal (eliminado); solo manifest"]}
    except Exception as e:
        return {"ok": False, "available": True, "tool": "apktool", "note": f"fallo al decodificar: {e}"}
    finally:
        _sh.rmtree(tmp, ignore_errors=True)


def jadx_decompile(apk_path: str, timeout: int = 180) -> dict:
    """Decompile an APK's DEX to Java via JADX (a decompiler -- it does not run the app). Runs into
    a throwaway temp dir (--no-res, no deobfuscation) and returns a summary of the recovered sources
    (count + sample class paths); the dir is removed afterwards."""
    import os
    import shutil as _sh
    import tempfile
    if _sh.which("jadx") is None:
        return _missing("jadx")
    tmp = tempfile.mkdtemp(prefix="binoracle_jadx_")
    try:
        r = run_caller_tool(["jadx", "--no-res", "-d", tmp, apk_path], timeout)
        # jadx returns non-zero on partial failures but still writes sources; don't hard-fail on code
        if not r.get("available"):
            return r
        src_root = os.path.join(tmp, "sources")
        java = []
        for root, _dirs, files in os.walk(src_root if os.path.isdir(src_root) else tmp):
            for fn in files:
                if fn.endswith(".java"):
                    rel = os.path.relpath(os.path.join(root, fn), tmp)
                    java.append(rel)
                    if len(java) >= 5000:
                        break
            if len(java) >= 5000:
                break
        classes = sorted(p.replace("sources/", "").replace("/", ".")[:-5] for p in java)
        return {"ok": True, "available": True, "tool": "jadx", "java_file_count": len(java),
                "classes": classes[:80],
                "limitations": ["decompilado por JADX en un dir temporal (eliminado); muestra de clases; "
                                "JADX decompila, no ejecuta la app"]}
    except Exception as e:
        return {"ok": False, "available": True, "tool": "jadx", "note": f"fallo al decompilar: {e}"}
    finally:
        _sh.rmtree(tmp, ignore_errors=True)


def render_caller(kind: str, r: dict) -> str:
    out = [f"## Integracion caller-supplied: {kind}\n"]
    if not r.get("ok"):
        return "\n".join(out + [f"- No disponible: {r.get('note','')}"])
    if kind == "wat":
        out.append(f"- wasm2wat OK ({r.get('functions')} funciones)")
        out.append("\n```wat\n" + (r.get("wat", "")[:3000]) + "\n```")
    elif kind == "pcap":
        out.append("- TShark OK\n\n```\n" + r.get("protocol_hierarchy", "")[:3000] + "\n```")
    elif kind == "firmware":
        out.append(f"- Binwalk OK: {r.get('signature_count')} firmas")
        for s in (r.get("signatures") or [])[:40]:
            out.append(f"  - {s}")
    elif kind == "one_gadget":
        out.append(f"- one_gadget OK: {r.get('count')} gadgets")
        for g in (r.get("gadgets") or [])[:20]:
            out.append(f"  - {g}")
    elif kind == "capinfos":
        out.append("- capinfos OK")
        for k, v in (r.get("info") or {}).items():
            out.append(f"  - {k}: {v}")
    elif kind == "manifest":
        out.append(f"- Apktool OK: paquete `{r.get('package')}`")
        perms = r.get("permissions") or []
        if perms:
            out.append(f"- permisos ({len(perms)}): " + ", ".join(perms[:30]))
        for tag, items in (r.get("components") or {}).items():
            out.append(f"- {tag} ({len(items)}): " + ", ".join(items[:12]))
    elif kind == "jadx":
        out.append(f"- JADX OK: {r.get('java_file_count')} ficheros .java")
        for c in (r.get("classes") or [])[:40]:
            out.append(f"  - {c}")
    elif kind == "ghidra":
        fns = r.get("functions") or []
        out.append(f"- Ghidra OK: {r.get('count')} funcion(es) decompiladas")
        for fn in fns[:10]:
            out.append(f"\n### {fn['name']} @ {fn['addr']}\n```c\n{fn['pseudocode'][:4000]}\n```")
    elif kind == "signal_decoders":
        out.append(f"- sigrok-cli OK: {r.get('decoder_count')} decodificador(es)")
        for d in (r.get("decoders") or [])[:40]:
            out.append(f"  - `{d['id']}` — {d['name']}")
    elif kind == "signal":
        out.append(f"- sigrok-cli OK: decodificador `{r.get('decoder')}`, "
                   f"{r.get('annotation_count')} anotacion(es)")
        out.append("\n```\n" + "\n".join((r.get("annotations") or [])[:60]) + "\n```")
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
