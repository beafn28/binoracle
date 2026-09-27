"""Deteccion del toolchain de pentest de binarios que binoracle puede aprovechar.

No reinventa las herramientas: detecta cuales estan instaladas en el entorno y explica
para que las usa binoracle (o para que las usarias tu). Todo local; solo `which` y probes
de import, sin ejecutar los binarios de forma intrusiva.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class ToolStatus:
    name: str
    kind: str            # static | rop | dynamic | symbolic | exploit
    present: bool
    detail: str          # ruta / version corta
    used_for: str        # para que lo usa binoracle


def _which(*names: str) -> str:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return ""


def _pymod(name: str) -> str:
    try:
        return "modulo python" if importlib.util.find_spec(name) else ""
    except Exception:
        return ""


_PROBE = True   # cuando es False, _ver no lanza subprocesos (catalogo rapido para el RAG)


def _ver(path: str, *args: str) -> str:
    if not path or not _PROBE:
        return ""
    try:
        out = subprocess.run([path, *args], capture_output=True, text=True, timeout=5)
        line = (out.stdout or out.stderr).strip().splitlines()
        return line[0][:60] if line else ""
    except Exception:
        return ""


def tool_catalog() -> list[ToolStatus]:
    """check_tools() sin probes de version (rapido y sin efectos): la fuente UNICA del
    saber-herramientas que el RAG inyecta como conocimiento (para que la IA sepa que
    herramienta usar en cada situacion, ademas de detectar cuales estan instaladas)."""
    global _PROBE
    _PROBE = False
    try:
        return check_tools()
    finally:
        _PROBE = True


def check_tools() -> list[ToolStatus]:
    st: list[ToolStatus] = []

    r2 = _which("radare2", "r2")
    st.append(ToolStatus("radare2/rizin", "static", bool(r2 or _which("rizin")),
                         _ver(r2, "-v") or _which("rizin"),
                         "recon estatico: info, imports, funciones, xrefs, sinks, ROP, checksec"))

    st.append(ToolStatus("pyelftools", "static", bool(_pymod("elftools")), _pymod("elftools"),
                         "parseo ELF: secciones, simbolos, GOT/PLT, relocs"))

    st.append(ToolStatus("angr", "symbolic", bool(_pymod("angr")), _pymod("angr"),
                         "ejecucion simbolica: offset a RIP, alcanzabilidad -> verdict 'verified'"))

    st.append(ToolStatus("pwntools", "exploit", bool(_pymod("pwn")), _pymod("pwn"),
                         "PoC ejecutable en sandbox: ELF, ROP, fmtstr_payload, cyclic, shellcraft"))

    og = _which("one_gadget")
    st.append(ToolStatus("one_gadget", "exploit", bool(og), og,
                         "fallback ret2libc: gadget unico que da shell en libc"))

    rg = _which("ROPgadget")
    rp = _which("ropper")
    st.append(ToolStatus("ROPgadget/ropper", "rop", bool(rg or rp), rg or rp,
                         "listado/cadena de gadgets (complementa el /R de radare2)"))

    gdb = _which("gdb")
    plugin = ""
    if gdb:
        try:
            out = subprocess.run([gdb, "-batch", "-ex", "version"], capture_output=True,
                                 text=True, timeout=5)
            blob = (out.stdout + out.stderr).lower()
            plugin = next((p for p in ("pwndbg", "gef", "peda") if p in blob), "")
        except Exception:
            pass
    st.append(ToolStatus("gdb (+pwndbg/gef)", "dynamic", bool(gdb),
                         (_ver(gdb, "--version") + (f" +{plugin}" if plugin else "")) if gdb else "",
                         "debug dinamico: breakpoints, heap, telescope, confirmar crashes"))

    lldb = _which("lldb")
    st.append(ToolStatus("lldb", "dynamic", bool(lldb), _ver(lldb, "--version"),
                         "debug dinamico (macOS / cross)"))

    st.append(ToolStatus("ltrace/strace", "dynamic", bool(_which("ltrace") or _which("strace")),
                         _which("ltrace") or _which("strace"),
                         "trazar llamadas a libc / syscalls en ejecucion"))

    st.append(ToolStatus("checksec", "static", bool(_which("checksec")), _which("checksec"),
                         "mitigaciones de un vistazo (binoracle ya trae r2_checksec propio)"))

    st.append(ToolStatus("objdump/nm/strings", "static",
                         bool(_which("objdump") or _which("nm") or _which("strings")),
                         _which("objdump") or _which("nm") or _which("strings"),
                         "desensamblado/simbolos/cadenas rapidos (binutils)"))

    docker = _which("docker")
    st.append(ToolStatus("docker", "exploit", bool(docker), _ver(docker, "--version"),
                         "sandbox aislado (--network none) para ejecutar y VERIFICAR los PoC"))

    # --- decompiladores / analisis profundo ---
    ghidra = _which("ghidra", "ghidraRun", "analyzeHeadless")
    st.append(ToolStatus("Ghidra", "static", bool(ghidra), ghidra,
                         "decompilador (headless con analyzeHeadless para batch)"))
    st.append(ToolStatus("rizin/cutter", "static", bool(_which("rizin") or _which("cutter")),
                         _which("rizin") or _which("cutter"),
                         "fork de radare2 + GUI cutter (decompilador Ghidra integrado)"))
    st.append(ToolStatus("binwalk", "static", bool(_which("binwalk")), _which("binwalk"),
                         "extraccion de firmware/blobs (carve de imagenes empotradas)"))

    # --- emulacion / instrumentacion dinamica ---
    st.append(ToolStatus("qemu-user", "dynamic",
                         bool(_which("qemu-x86_64") or _which("qemu-aarch64") or _which("qemu-mips")),
                         _which("qemu-x86_64") or _which("qemu-aarch64") or _which("qemu-mips"),
                         "ejecutar binarios de otra arquitectura (ARM/MIPS) + gdbstub (-g)"))
    st.append(ToolStatus("unicorn", "dynamic", bool(_pymod("unicorn")), _pymod("unicorn"),
                         "emulador de CPU multi-arch (emular trozos, resolver flujos)"))
    st.append(ToolStatus("qiling", "dynamic", bool(_pymod("qiling")), _pymod("qiling"),
                         "framework de emulacion (syscalls/OS) sobre unicorn"))
    st.append(ToolStatus("frida", "dynamic", bool(_which("frida") or _pymod("frida")),
                         _which("frida") or _pymod("frida"),
                         "instrumentacion dinamica: hooks en runtime (anti-debug, tracing)"))
    st.append(ToolStatus("valgrind", "dynamic", bool(_which("valgrind")), _which("valgrind"),
                         "memcheck: detecta UAF, double-free, OOB y leaks en dinamico"))

    # --- exploit / heap / libc ---
    st.append(ToolStatus("seccomp-tools", "exploit", bool(_which("seccomp-tools")), _which("seccomp-tools"),
                         "dump del filtro seccomp (que syscalls estan ALLOW/KILL)"))
    st.append(ToolStatus("pwninit", "exploit", bool(_which("pwninit")), _which("pwninit"),
                         "parchea el binario con su libc/loader para depurar en local"))
    st.append(ToolStatus("patchelf", "exploit", bool(_which("patchelf")), _which("patchelf"),
                         "cambia interprete/RPATH del ELF (usar la libc del reto)"))
    st.append(ToolStatus("ropr/angrop", "rop", bool(_which("ropr") or _pymod("angrop")),
                         _which("ropr") or _pymod("angrop"),
                         "busqueda rapida de gadgets (ropr) y cadenas ROP automaticas (angrop)"))

    # --- libs de asm/disasm y gadgets extra ---
    st.append(ToolStatus("capstone", "static", bool(_pymod("capstone")), _pymod("capstone"),
                         "motor de desensamblado multi-arch (base de muchas tools)"))
    st.append(ToolStatus("keystone", "static", bool(_pymod("keystone")), _pymod("keystone"),
                         "ensamblador multi-arch (asm() sin depender de binutils)"))

    # --- fuzzing / simbolico ---
    # --- decompiladores open source ---
    st.append(ToolStatus("retdec", "static", bool(_which("retdec-decompiler", "retdec-decompiler.py")),
                         _which("retdec-decompiler", "retdec-decompiler.py"),
                         "decompilador open source (LLVM IR -> C), util para triaje rapido"))

    # --- Android / Java / .NET ---
    st.append(ToolStatus("jadx", "static", bool(_which("jadx", "jadx-gui")), _which("jadx", "jadx-gui"),
                         "APK/DEX -> pseudo-Java (decompilado Android rapido)"))
    st.append(ToolStatus("apktool", "static", bool(_which("apktool")), _which("apktool"),
                         "desempaqueta APK: smali, recursos, AndroidManifest"))
    st.append(ToolStatus("dex2jar", "static", bool(_which("d2j-dex2jar", "d2j-dex2jar.sh")),
                         _which("d2j-dex2jar", "d2j-dex2jar.sh"),
                         "DEX -> JAR (para decompilar con herramientas Java)"))
    # --- malware / capacidades / strings ---
    st.append(ToolStatus("yara", "static", bool(_which("yara") or _pymod("yara")),
                         _which("yara") or _pymod("yara"),
                         "reglas de deteccion (familias de malware, packers, patrones)"))
    st.append(ToolStatus("capa", "static", bool(_which("capa") or _pymod("capa")),
                         _which("capa") or _pymod("capa"),
                         "detecta CAPACIDADES del binario (ATT&CK/MBC) a partir de reglas"))
    st.append(ToolStatus("file", "static", bool(_which("file")), _which("file"),
                         "identificacion rapida de formato/arquitectura del artefacto"))

    # --- simbolico / taint / emulacion extra ---
    st.append(ToolStatus("miasm", "symbolic", bool(_pymod("miasm")), _pymod("miasm"),
                         "IR + emulacion simbolica multi-arch (unpacking, deofuscacion)"))
    st.append(ToolStatus("manticore", "symbolic", bool(_pymod("manticore") or _which("manticore")),
                         _pymod("manticore") or _which("manticore"),
                         "ejecucion simbolica de binarios y smart contracts (Trail of Bits)"))

    # --- pwn: identificacion de libc ---
    st.append(ToolStatus("libc-database", "exploit",
                         bool(_which("libc-database") or _pymod("LibcSearcher")),
                         _which("libc-database") or _pymod("LibcSearcher"),
                         "identifica la libc por simbolos filtrados -> offsets de system/one_gadget"))

    return st


def render(statuses: list[ToolStatus], lang: str = "es") -> str:
    order = ["static", "rop", "symbolic", "dynamic", "exploit"]
    titles = {"static": "Estatico / triage", "rop": "ROP / gadgets",
              "symbolic": "Simbolico", "dynamic": "Dinamico / debug",
              "exploit": "Explotacion / sandbox"}
    have = sum(1 for s in statuses if s.present)
    lines = [f"binoracle: toolchain de pentest de binarios  ({have}/{len(statuses)} disponibles)",
             "=" * 62]
    for k in order:
        group = [s for s in statuses if s.kind == k]
        if not group:
            continue
        lines.append(f"\n[{titles[k]}]")
        for s in group:
            mark = "ok " if s.present else "-- "
            det = f"  ({s.detail})" if s.present and s.detail else ""
            lines.append(f"  {mark}{s.name:<20}{det}")
            lines.append(f"       -> {s.used_for}")
    missing = [s.name for s in statuses if not s.present]
    if missing:
        lines.append("\nno instaladas (opcionales, mejoran cobertura):")
        lines.append("  " + ", ".join(missing))
    lines.append("\nbinoracle funciona con lo que haya: los oraculos base (radare2/angr/")
    lines.append("pwntools/docker) dan el nucleo grounded; el resto suma cobertura.")
    return "\n".join(lines)
