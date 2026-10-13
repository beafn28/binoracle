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
}


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
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
