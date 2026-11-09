"""Static PE (Windows) reader: header, sections, mitigations, imports, packing hint.

Reads a PE image with pefile -- no execution: architecture and subsystem, the sections with their
Shannon entropy (a high-entropy section hints at packing/encryption), the DllCharacteristics
mitigations (ASLR/DYNAMIC_BASE, DEP/NX_COMPAT, Control Flow Guard, SafeSEH/NO_SEH, high-entropy
ASLR, force-integrity), the imported DLLs and a capability map of their functions (process,
network, crypto, filesystem, registry, injection), and the entry point. Design adapted from REA's
PE tooling (morluto/rea, MIT); re-implemented in Python."""
from __future__ import annotations

import math

# DllCharacteristics bits -> mitigation name
_DLLCHAR = [
    (0x0020, "high_entropy_va"), (0x0040, "aslr_dynamic_base"), (0x0080, "force_integrity"),
    (0x0100, "dep_nx"), (0x0200, "no_isolation"), (0x0400, "no_seh"),
    (0x0800, "no_bind"), (0x1000, "appcontainer"), (0x2000, "wdm_driver"),
    (0x4000, "control_flow_guard"), (0x8000, "terminal_server_aware"),
]

# import function -> capability category (substring match, case-insensitive)
_CAPS = {
    "process": ("createprocess", "shellexecute", "winexec", "createremotethread", "openprocess"),
    "injection": ("virtualalloc", "virtualprotect", "writeprocessmemory", "setwindowshookex",
                  "ntunmapviewofsection", "queueuserapc"),
    "network": ("socket", "connect", "wsastartup", "internetopen", "httpsendrequest", "send", "recv"),
    "crypto": ("cryptencrypt", "cryptdecrypt", "cryptacquirecontext", "bcryptencrypt"),
    "filesystem": ("createfile", "readfile", "writefile", "deletefile", "movefile"),
    "registry": ("regopenkey", "regsetvalue", "regcreatekey", "regqueryvalue"),
    "anti_debug": ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"),
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return round(h, 2)


def decode_mitigations(dllchar: int) -> dict:
    """Pure decode of the DllCharacteristics word into named mitigations."""
    return {name: bool(dllchar & bit) for bit, name in _DLLCHAR}


def inspect_pe(path: str) -> dict:
    """Read a PE statically. Returns {ok, is_pe, arch, mitigations, sections, imports, ...}."""
    try:
        import pefile
    except Exception as e:
        return {"ok": False, "is_pe": False, "note": f"falta pefile: {e}"}
    try:
        pe = pefile.PE(path)
    except Exception as e:
        return {"ok": True, "is_pe": False, "note": f"no es PE: {e}"}
    try:
        machine = pe.FILE_HEADER.Machine
        arch = {0x14C: "x86", 0x8664: "x86_64", 0x1C0: "arm", 0xAA64: "arm64"}.get(machine, hex(machine))
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        dllchar = pe.OPTIONAL_HEADER.DllCharacteristics
        mit = decode_mitigations(dllchar)
        sections = []
        packed = False
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
            ent = _entropy(s.get_data() or b"")
            if ent >= 7.0:
                packed = True
            ch = s.Characteristics
            perms = ("r" if ch & 0x40000000 else "-") + ("w" if ch & 0x80000000 else "-") + \
                    ("x" if ch & 0x20000000 else "-")
            sections.append({"name": name, "vsize": s.Misc_VirtualSize, "rawsize": s.SizeOfRawData,
                             "entropy": ent, "perms": perms})
        imports = {}
        caps = {}
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                dll = (entry.dll or b"").decode("latin-1", "replace")
                funcs = []
                for imp in entry.imports:
                    fn = (imp.name or b"").decode("latin-1", "replace") if imp.name else f"ord{imp.ordinal}"
                    funcs.append(fn)
                    low = fn.lower()
                    for cat, needles in _CAPS.items():
                        if any(nd in low for nd in needles):
                            caps.setdefault(cat, set()).add(fn)
                imports[dll] = funcs[:60]
        except Exception:
            pass
        return {"ok": True, "is_pe": True, "arch": arch, "is_dll": is_dll,
                "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                "entrypoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                "mitigations": mit, "sections": sections, "packed_hint": packed,
                "imports": imports, "capabilities": {k: sorted(v) for k, v in caps.items()},
                "limitations": ["entropia por seccion como heuristica de packing; no se desempaqueta "
                                "ni se desensambla; capacidades por nombre de import"]}
    except Exception as e:
        return {"ok": True, "is_pe": True, "note": f"PE malformado: {e}"}
    finally:
        try:
            pe.close()
        except Exception:
            pass


def render_pe(r: dict) -> str:
    out = ["## Inspeccion de PE Windows (estatica)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_pe"):
        return "\n".join(out + ["- No es un PE: " + r.get("note", "")])
    if r.get("note"):
        out.append(f"- nota: {r['note']}")
    out.append(f"- arquitectura: {r.get('arch')}  |  tipo: {'DLL' if r.get('is_dll') else 'EXE'}"
               f"  |  entrypoint: {hex(r.get('entrypoint', 0))}")
    m = r.get("mitigations") or {}
    out.append("\n### Mitigaciones (DllCharacteristics)")
    out.append(f"- ASLR (DYNAMIC_BASE): **{'si' if m.get('aslr_dynamic_base') else 'no'}**")
    out.append(f"- DEP/NX (NX_COMPAT): **{'si' if m.get('dep_nx') else 'no'}**")
    out.append(f"- Control Flow Guard: **{'si' if m.get('control_flow_guard') else 'no'}**")
    out.append(f"- High-Entropy ASLR: **{'si' if m.get('high_entropy_va') else 'no'}**  |  "
               f"Force Integrity: {'si' if m.get('force_integrity') else 'no'}  |  "
               f"SEH: {'no (NO_SEH)' if m.get('no_seh') else 'si'}")
    if r.get("packed_hint"):
        out.append("\n- **posible empaquetado/cifrado (seccion con entropia >= 7.0)**")
    secs = r.get("sections") or []
    if secs:
        out.append(f"\n### Secciones ({len(secs)})")
        for s in secs[:30]:
            out.append(f"- {s['name']}  {s['perms']}  vsize={hex(s['vsize'])} entropia={s['entropy']}")
    caps = r.get("capabilities") or {}
    if caps:
        out.append("\n### Capacidades (por imports)")
        for cat, fns in caps.items():
            out.append(f"- **{cat}**: {', '.join(fns[:10])}")
    imps = r.get("imports") or {}
    if imps:
        out.append(f"\n### DLLs importadas ({len(imps)}): " + ", ".join(list(imps.keys())[:20]))
    for lim in r.get("limitations", []):
        out.append(f"\n_limite: {lim}_")
    return "\n".join(out)
