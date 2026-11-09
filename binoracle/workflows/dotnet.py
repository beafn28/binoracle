"""Decompilacion de ensamblados .NET (alternativa para binarios gestionados/CLR).

Muchos retos y binarios reales son .NET (PE con cabecera CLR): el disasm nativo (r2/objdump)
no sirve, hay que leer el bytecode CIL o recuperar el C#. Este modulo:
- detecta si el binario es un ensamblado .NET (firma de metadatos 'BSJB');
- lo decompila con la mejor herramienta disponible: ilspycmd (C# limpio) > monodis/ikdasm (CIL);
- escanea el codigo recuperado en busca de secretos hardcodeados (habitual en .NET: constantes
  de conexion, claves, contrasenas embebidas), como hallazgos GROUNDED (evidencia estatica).

Grounded: la decompilacion es la salida real de la herramienta; los secretos se citan del codigo
recuperado. Solo para binarios autorizados/laboratorio.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from ..store.session import Finding


@dataclass
class DotnetDecompilation:
    ok: bool = False
    is_dotnet: bool = False
    tool: str = ""
    lang: str = ""          # csharp | cil
    code: str = ""
    note: str = ""
    install_hint: str = ""


def is_dotnet(binary: str) -> bool:
    """True si el fichero es un ensamblado .NET/CLR. Se apoya en la firma del stream de metadatos
    'BSJB' (0x424A5342) presente en todo ensamblado gestionado, ademas de la cabecera PE 'MZ'."""
    try:
        with open(binary, "rb") as fh:
            head = fh.read(2)
            if head != b"MZ":
                return False
            fh.seek(0)
            data = fh.read(4 * 1024 * 1024)   # los metadatos estan en los primeros MB
        return b"BSJB" in data
    except OSError:
        return False


def _env_with_tools() -> dict:
    """Entorno con ~/.dotnet/tools en el PATH y roll-forward para ejecutar ilspycmd (net8) sobre
    un runtime mas nuevo/antiguo si es necesario."""
    env = dict(os.environ)
    tools = os.path.expanduser("~/.dotnet/tools")
    if tools not in env.get("PATH", ""):
        env["PATH"] = env.get("PATH", "") + os.pathsep + tools
    env.setdefault("DOTNET_ROLL_FORWARD", "LatestMajor")
    env.setdefault("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
    return env


def _which(name: str, env: dict) -> Optional[str]:
    return shutil.which(name, path=env.get("PATH"))


_INSTALL = ("Instala un decompilador .NET: `dotnet tool install -g ilspycmd --version 8.0.0.7345` "
            "(C#), o `brew install mono` (aporta monodis para CIL).")


def decompile_dotnet(binary: str, member: Optional[str] = None, timeout: int = 120) -> DotnetDecompilation:
    """Decompila el ensamblado con la mejor herramienta disponible. C# con ilspycmd; si no, CIL
    con monodis/ikdasm. No lanza."""
    if not is_dotnet(binary):
        return DotnetDecompilation(ok=False, is_dotnet=False, note="no es un ensamblado .NET")
    env = _env_with_tools()
    # 1) ilspycmd -> C# legible
    ilspy = _which("ilspycmd", env)
    if ilspy:
        try:
            r = subprocess.run([ilspy, binary], capture_output=True, text=True, timeout=timeout, env=env)
            out = r.stdout or ""
            if out.strip() and ("class " in out or "namespace " in out or "void " in out):
                return DotnetDecompilation(ok=True, is_dotnet=True, tool="ilspycmd", lang="csharp",
                                           code=out, note="decompilacion a C# (ICSharpCode.Decompiler)")
        except Exception:
            pass
    # 2) monodis / ikdasm -> CIL
    for tool in ("monodis", "ikdasm"):
        exe = _which(tool, env)
        if not exe:
            continue
        try:
            r = subprocess.run([exe, binary], capture_output=True, text=True, timeout=timeout, env=env)
            out = r.stdout or ""
            if out.strip():
                return DotnetDecompilation(ok=True, is_dotnet=True, tool=tool, lang="cil",
                                           code=out, note="desensamblado a CIL (bytecode .NET)")
        except Exception:
            pass
    return DotnetDecompilation(ok=False, is_dotnet=True,
                               note="ensamblado .NET detectado pero no hay decompilador instalado",
                               install_hint=_INSTALL)


# nombres de identificador que sugieren un secreto + patrones de valor sospechoso
_SECRET_NAME = re.compile(
    r'(password|passwd|pwd|secret|api[_]?key|apikey|token|connection[_]?string|connstr|'
    r'private[_]?key|access[_]?key|client[_]?secret)', re.I)
_STR_CONST = re.compile(
    r'(?:const|static|readonly|private|public|internal)[\w\s]*?string\s+(\w+)\s*=\s*"([^"]{4,200})"', re.I)
_ASSIGN = re.compile(r'\b(\w*(?:password|secret|api[_]?key|token|pwd|connstr|clientsecret)\w*)\s*=\s*"([^"]{4,200})"', re.I)
_CONNSTR = re.compile(r'"([^"]*(?:Server|Data Source|Initial Catalog|Password|User Id|Uid|Pwd)=[^"]{4,})"', re.I)
# valores claramente placeholder que NO son secretos reales
_FP = re.compile(r'^(your|xxx|example|changeme|placeholder|test|dummy|none|null|\{[^}]*\}|<[^>]*>|\.\.\.)$|^(0+|1234+|abcd)+$', re.I)


def _scan_code_secrets(code: str) -> List[dict]:
    """Extrae secretos hardcodeados del codigo decompilado. Devuelve [{name, value, kind}]."""
    hits = {}
    for rx, kind in ((_STR_CONST, "constante"), (_ASSIGN, "asignacion"), (_CONNSTR, "cadena de conexion")):
        for m in rx.finditer(code):
            if rx is _CONNSTR:
                name, value = "connectionString", m.group(1)
            else:
                name, value = m.group(1), m.group(2)
            if _FP.match(value.strip()):
                continue
            if rx is _STR_CONST and not _SECRET_NAME.search(name):
                continue   # constante string generica sin nombre sospechoso: se ignora
            hits.setdefault(value, {"name": name, "value": value, "kind": kind})
    return list(hits.values())


def scan_dotnet(reg, binary: str, lang: str = "es") -> List[Finding]:
    """Si el binario es .NET, lo decompila y reporta: (a) que es gestionado/decompilable, y
    (b) secretos hardcodeados hallados en el codigo recuperado. `reg` se acepta por consistencia
    con los demas scanners (no se usa)."""
    if not is_dotnet(binary):
        return []
    d = decompile_dotnet(binary)
    findings: List[Finding] = []
    es = lang == "es"
    if not d.ok:
        findings.append(Finding(
            title="Ensamblado .NET (sin decompilador instalado)" if es else ".NET assembly (no decompiler installed)",
            severity="info", verdict="grounded", location="formato / CLR",
            evidence="[dotnet]\n" + (d.note or ""),
            rationale=("El binario es un ensamblado .NET gestionado (bytecode CIL). El disasm nativo no "
                       "aplica; hace falta un decompilador .NET para analizarlo." if es else
                       "The binary is a managed .NET assembly (CIL bytecode). Native disasm does not "
                       "apply; a .NET decompiler is needed to analyze it."),
            rationale_en="The binary is a managed .NET assembly (CIL bytecode). Native disasm does not apply.",
            recommendation=d.install_hint or _INSTALL, recommendation_en=_INSTALL))
        return findings
    findings.append(Finding(
        title="Ensamblado .NET decompilado" if es else ".NET assembly decompiled",
        severity="info", verdict="grounded", location="formato / CLR",
        evidence=f"[{d.tool}]\n{d.note}\n({len(d.code)} bytes de {'C#' if d.lang=='csharp' else 'CIL'})",
        rationale=("Binario gestionado .NET recuperado a codigo fuente legible: el codigo original "
                   "(logica, comparaciones, secretos) queda expuesto casi por completo." if es else
                   "Managed .NET binary recovered to readable source: the original code (logic, "
                   "comparisons, secrets) is almost fully exposed."),
        rationale_en="Managed .NET binary recovered to readable source; original logic is exposed.",
        recommendation=("Ofusca el ensamblado si contiene logica/secretos sensibles; no confies en la "
                        "compilacion como proteccion." if es else
                        "Obfuscate the assembly if it holds sensitive logic/secrets; do not rely on "
                        "compilation as protection."),
        recommendation_en="Obfuscate the assembly if it holds sensitive logic/secrets."))
    for s in _scan_code_secrets(d.code)[:12]:
        findings.append(Finding(
            title=(f"Secreto hardcodeado en .NET: {s['name']}" if es else
                   f"Hardcoded secret in .NET: {s['name']}"),
            severity="high", verdict="grounded", location=f"{d.tool} / {s['kind']}",
            evidence=f"[{d.tool}]\n{s['name']} = \"{s['value'][:80]}\"",
            rationale=(f"El codigo decompilado embebe un valor sensible ({s['kind']}). En .NET es "
                       "trivial de extraer con cualquier decompilador; sirve para bypass de auth, "
                       "acceso a BBDD o suplantacion." if es else
                       f"The decompiled code embeds a sensitive value ({s['kind']}). In .NET it is "
                       "trivially extractable with any decompiler; usable for auth bypass, DB access "
                       "or impersonation."),
            rationale_en=(f"The decompiled code embeds a sensitive value ({s['kind']}); trivially "
                          "extractable in .NET."),
            recommendation=("No embebas secretos en el codigo; usa un almacen de secretos / variables "
                            "de entorno y rota lo expuesto." if es else
                            "Do not embed secrets in code; use a secrets store / env vars and rotate "
                            "what is exposed."),
            recommendation_en="Do not embed secrets in code; use a secrets store and rotate them."))
    return findings
