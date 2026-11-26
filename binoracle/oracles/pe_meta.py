"""PE (Windows) metadata + mitigation oracle.

Uses pefile when available; falls back to r2pipe/radare2 for systems without it."""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
from typing import Optional

from .base import Oracle, Tool, ToolResult

try:
    import pefile as _pefile  # type: ignore
    _HAVE_PEFILE = True
except ImportError:
    _HAVE_PEFILE = False

try:
    import r2pipe as _r2pipe  # type: ignore
    _HAVE_R2PIPE = True
except ImportError:
    _HAVE_R2PIPE = False


def _is_pe(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except Exception:
        return False


def _r2_cmd(path: str, cmd: str) -> str:
    if _HAVE_R2PIPE:
        try:
            r2 = _r2pipe.open(path, flags=["-e", "scr.color=0", "-e", "log.quiet=true", "-2"])
            out = r2.cmd(cmd)
            r2.quit()
            return out or ""
        except Exception:
            pass
    exe = shutil.which("r2") or shutil.which("radare2")
    if not exe:
        return ""
    try:
        result = subprocess.run(
            [exe, "-q", "-e", "scr.color=0", "-e", "log.quiet=true", "-2", "-c", cmd, path],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout or ""
    except Exception:
        return ""


def pe_arch(path: str) -> str:
    if _HAVE_PEFILE:
        try:
            pe = _pefile.PE(path, fast_load=True)
            m = pe.FILE_HEADER.Machine
            pe.close()
            return {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64", 0x1C4: "armv7"}.get(m, hex(m))
        except Exception:
            pass
    out = _r2_cmd(path, "iIj")
    if '"arch":"x86"' in out and '"bits":64' in out:
        return "x86_64"
    if '"arch":"x86"' in out:
        return "x86"
    return "unknown"


def pe_has_nx(path: str) -> bool:
    """NX/DEP: PE DllCharacteristics bit 0x100 (IMAGE_DLLCHARACTERISTICS_NX_COMPAT)."""
    if _HAVE_PEFILE:
        try:
            pe = _pefile.PE(path, fast_load=True)
            nx = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x100)
            pe.close()
            return nx
        except Exception:
            pass
    out = _r2_cmd(path, "iI")
    return "nx       true" in out.lower()


def pe_has_aslr(path: str) -> bool:
    """ASLR: DllCharacteristics bit 0x40 (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)."""
    if _HAVE_PEFILE:
        try:
            pe = _pefile.PE(path, fast_load=True)
            aslr = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40)
            pe.close()
            return aslr
        except Exception:
            pass
    out = _r2_cmd(path, "iI")
    return "pic      true" in out.lower()


def pe_has_cfg(path: str) -> bool:
    """Control Flow Guard: DllCharacteristics bit 0x4000."""
    if _HAVE_PEFILE:
        try:
            pe = _pefile.PE(path, fast_load=True)
            cfg = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000)
            pe.close()
            return cfg
        except Exception:
            pass
    out = _r2_cmd(path, "ii~__guard_check_icall")
    return bool(out.strip())


def pe_has_gs(path: str) -> bool:
    """Stack cookies (/GS): presence of __security_cookie in imports/symbols."""
    out = _r2_cmd(path, "ii~security_cookie") + _r2_cmd(path, "is~security_cookie")
    return bool(out.strip())


def pe_has_safe_seh(path: str) -> bool:
    """SafeSEH: IMAGE_DLLCHARACTERISTICS_NO_SEH (0x400) means safe exception handlers table."""
    if _HAVE_PEFILE:
        try:
            pe = _pefile.PE(path, fast_load=True)
            # NO_SEH flag means the binary opts out of SEH entirely (safer for x86)
            no_seh = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x400)
            pe.close()
            return no_seh
        except Exception:
            pass
    return False


def pe_imports(path: str) -> list[dict]:
    """Return list of {dll, functions} dicts."""
    if _HAVE_PEFILE:
        try:
            pe = _pefile.PE(path)
            result = []
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                dll = entry.dll.decode(errors="replace")
                funcs = []
                for imp in entry.imports:
                    name = imp.name.decode(errors="replace") if imp.name else f"ord_{imp.ordinal}"
                    funcs.append(name)
                result.append({"dll": dll, "functions": funcs})
            pe.close()
            return result
        except Exception:
            pass
    out = _r2_cmd(path, "ii")
    seen_dll: dict = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            func = parts[-1]
            dll = parts[-2] if len(parts) >= 4 else "unknown"
            seen_dll.setdefault(dll, []).append(func)
    return [{"dll": dll, "functions": fns} for dll, fns in seen_dll.items()]


def pe_exports(path: str) -> list[str]:
    if _HAVE_PEFILE:
        try:
            pe = _pefile.PE(path)
            names = []
            for exp in getattr(pe, "DIRECTORY_ENTRY_EXPORT", _FakeExports()).symbols:
                if exp.name:
                    names.append(exp.name.decode(errors="replace"))
            pe.close()
            return names
        except Exception:
            pass
    out = _r2_cmd(path, "iE")
    return [line.split()[-1] for line in out.splitlines() if line.strip() and not line.startswith("#")]


class _FakeExports:
    symbols = []


def pe_sections(path: str) -> list[dict]:
    if _HAVE_PEFILE:
        try:
            pe = _pefile.PE(path, fast_load=True)
            secs = []
            for s in pe.sections:
                name = s.Name.rstrip(b"\x00").decode(errors="replace")
                flags = s.Characteristics
                secs.append({
                    "name": name,
                    "vaddr": hex(s.VirtualAddress),
                    "vsize": s.Misc_VirtualSize,
                    "raw_size": s.SizeOfRawData,
                    "exec": bool(flags & 0x20000000),
                    "write": bool(flags & 0x80000000),
                    "read": bool(flags & 0x40000000),
                })
            pe.close()
            return secs
        except Exception:
            pass
    out = _r2_cmd(path, "iS")
    secs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].startswith("0x"):
            secs.append({"name": parts[-1], "vaddr": parts[0], "flags": parts[4] if len(parts) > 4 else ""})
    return secs


def pe_is_driver(path: str) -> bool:
    """True if the file looks like a Windows kernel driver (.sys / DriverEntry export)."""
    if path.lower().endswith(".sys"):
        return True
    exports = pe_exports(path)
    if "DriverEntry" in exports or "GsDriverEntry" in exports:
        return True
    out = _r2_cmd(path, "is~DriverEntry")
    return bool(out.strip())


def extract_pe_meta(path: str) -> dict:
    """Combined PE metadata: mitigations, arch, sections, imports summary, driver flag."""
    if not _is_pe(path):
        return {"error": "not a PE file"}
    all_imports = pe_imports(path)
    flat_imports = [f for entry in all_imports for f in entry["functions"]]
    return {
        "arch": pe_arch(path),
        "is_driver": pe_is_driver(path),
        "mitigations": {
            "nx": pe_has_nx(path),
            "aslr": pe_has_aslr(path),
            "cfg": pe_has_cfg(path),
            "gs": pe_has_gs(path),
            "safe_seh": pe_has_safe_seh(path),
        },
        "sections": pe_sections(path),
        "import_dlls": [e["dll"] for e in all_imports],
        "imports_flat": flat_imports[:200],
        "exports": pe_exports(path)[:100],
    }


class PeMetaOracle(Oracle):
    name = "pe_meta"

    def __init__(self, binary: str):
        self.binary = binary

    def available(self) -> bool:
        return _is_pe(self.binary) and (_HAVE_PEFILE or _HAVE_R2PIPE or bool(shutil.which("r2")))

    def why_unavailable(self) -> str:
        if not _is_pe(self.binary):
            return "target is not a PE file (MZ magic not found)"
        return "neither pefile nor radare2 available (pip install pefile or install radare2)"

    def tools(self) -> list:
        return [
            Tool("pe_info", "PE header summary: arch, type, mitigations (NX/ASLR/CFG/GS), driver flag.",
                 [], lambda: self._info(), self.name),
            Tool("pe_imports", "Imported DLLs and function names.",
                 [], lambda: self._imports(), self.name),
            Tool("pe_exports", "Exported function names.",
                 [], lambda: self._exports(), self.name),
            Tool("pe_sections", "Section table: names, permissions, sizes.",
                 [], lambda: self._sections(), self.name),
            Tool("pe_driver_analysis", "Driver-specific analysis: IOCTL handler detection, dangerous kernel APIs.",
                 [], lambda: self._driver(), self.name),
        ]

    def _info(self) -> ToolResult:
        meta = extract_pe_meta(self.binary)
        if "error" in meta:
            return ToolResult(False, "pe_meta", "", error=meta["error"])
        m = meta["mitigations"]
        txt = (
            f"arch:     {meta['arch']}\n"
            f"driver:   {meta['is_driver']}\n"
            f"NX/DEP:   {m['nx']}\n"
            f"ASLR:     {m['aslr']}\n"
            f"CFG:      {m['cfg']}\n"
            f"/GS:      {m['gs']}\n"
            f"SafeSEH:  {m['safe_seh']}\n"
            f"sections: {len(meta['sections'])}\n"
            f"imp DLLs: {', '.join(meta['import_dlls'][:8])}"
        )
        return ToolResult(True, "pe_meta: header + mitigations", txt, meta=meta)

    def _imports(self) -> ToolResult:
        entries = pe_imports(self.binary)
        lines = []
        for e in entries:
            lines.append(f"# {e['dll']}")
            lines.extend(f"  {f}" for f in e["functions"][:30])
        txt = "\n".join(lines) if lines else "(no imports)"
        return ToolResult(True, "pe_meta: imports", txt)

    def _exports(self) -> ToolResult:
        exps = pe_exports(self.binary)
        txt = "\n".join(exps[:200]) if exps else "(no exports / not a DLL/driver)"
        return ToolResult(True, "pe_meta: exports", txt)

    def _sections(self) -> ToolResult:
        secs = pe_sections(self.binary)
        lines = []
        for s in secs:
            perms = ("r" if s.get("read") else "-") + ("w" if s.get("write") else "-") + ("x" if s.get("exec") else "-")
            lines.append(f"{s['name']:12s}  {s.get('vaddr','?'):10s}  {perms}  vsize={s.get('vsize','?')}")
        txt = "\n".join(lines) if lines else "(no sections)"
        return ToolResult(True, "pe_meta: sections", txt)

    def _driver(self) -> ToolResult:
        if not pe_is_driver(self.binary):
            return ToolResult(True, "pe_meta: driver analysis", "(not a kernel driver)")
        all_imports = pe_imports(self.binary)
        flat = [f for e in all_imports for f in e["functions"]]
        dangerous_kernel = [
            "MmMapLockedPagesSpecifyCache", "MmMapLockedPages", "MmProbeAndLockPages",
            "ZwMapViewOfSection", "ZwAllocateVirtualMemory", "ExAllocatePool",
            "ExAllocatePoolWithTag", "ObReferenceObjectByHandle", "IoCreateDevice",
            "IoCreateSymbolicLink", "IoBuildDeviceIoControlRequest",
        ]
        ioctl_patterns = ["IRP_MJ_DEVICE_CONTROL", "IoControlCode", "DeviceIoControl", "METHOD_BUFFERED"]
        found_dangerous = [f for f in flat if any(d in f for d in dangerous_kernel)]
        found_ioctl = [f for f in flat if any(p in f for p in ioctl_patterns)]
        exports = pe_exports(self.binary)
        driver_entry = "DriverEntry" in exports or "GsDriverEntry" in exports
        lines = [
            f"DriverEntry exported: {driver_entry}",
            f"Dangerous kernel APIs: {', '.join(found_dangerous[:10]) or 'none detected'}",
            f"IOCTL-related imports: {', '.join(found_ioctl[:10]) or 'none detected'}",
        ]
        # Heuristic vuln signals
        if "ExAllocatePool" in flat and "ExFreePool" not in flat:
            lines.append("WARN: ExAllocatePool without ExFreePool import — possible pool leak or UAF")
        if any("ZwAllocateVirtualMemory" in f or "MmMapLockedPages" in f for f in flat):
            lines.append("NOTE: kernel memory mapping APIs present — shellcode injection vector")
        return ToolResult(True, "pe_meta: driver analysis", "\n".join(lines),
                          meta={"dangerous_apis": found_dangerous, "ioctl": found_ioctl})
