"""Offline ELF layout + static mitigation candidates, read with pyelftools.

A grounded, no-execution view of an ELF: header (arch/bits/type/entry), sections (perms), load
segments, symbol and relocation counts, linkage (needed libraries, interpreter), and the static
mitigation candidates an exploit engineer checks first -- PIE, NX (GNU_STACK non-exec), executable
stack, stack-canary presence (__stack_chk_*), and RELRO (Partial via GNU_RELRO, Full via BIND_NOW),
plus any writable+executable segment. Everything is derived from the file; nothing is run. The
mitigation layer is labelled "inferred" and flags its limitations. Design adapted from REA's binary
layout reader (morluto/rea, MIT); re-implemented in Python."""
from __future__ import annotations


def _seg_perm(flags: int) -> str:
    return ("r" if flags & 0x4 else "-") + ("w" if flags & 0x2 else "-") + ("x" if flags & 0x1 else "-")


def inspect_elf(path: str) -> dict:
    """Return the ELF layout + mitigation candidates, or {ok: False}/{is_elf: False} otherwise."""
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.relocation import RelocationSection
        from elftools.elf.sections import SymbolTableSection
    except Exception as e:
        return {"ok": False, "is_elf": False, "note": f"falta pyelftools: {e}"}
    try:
        f = open(path, "rb")
    except Exception as e:
        return {"ok": False, "is_elf": False, "note": f"no se pudo abrir: {e}"}
    with f:
        try:
            elf = ELFFile(f)
        except Exception as e:
            return {"ok": True, "is_elf": False, "note": f"no es un ELF: {e}"}
        hdr = {
            "type": elf["e_type"], "machine": elf["e_machine"],
            "bits": elf.elfclass, "endian": "little" if elf.little_endian else "big",
            "entry": elf["e_entry"],
        }
        sections = []
        for s in elf.iter_sections():
            fl = s["sh_flags"]
            perms = ("a" if fl & 0x2 else "-") + ("w" if fl & 0x1 else "-") + ("x" if fl & 0x4 else "-")
            sections.append({"name": s.name, "type": s["sh_type"], "addr": s["sh_addr"],
                             "offset": s["sh_offset"], "size": s["sh_size"], "perms": perms})
        segments, gnu_stack, gnu_relro, interp, rwx = [], None, False, None, []
        for seg in elf.iter_segments():
            t = seg["p_type"]
            perm = _seg_perm(seg["p_flags"])
            row = {"type": t, "perms": perm, "vaddr": seg["p_vaddr"],
                   "filesz": seg["p_filesz"], "memsz": seg["p_memsz"]}
            segments.append(row)
            if t == "PT_GNU_STACK":
                gnu_stack = seg["p_flags"]
            elif t == "PT_GNU_RELRO":
                gnu_relro = True
            elif t == "PT_INTERP":
                try:
                    interp = seg.get_interp_name()
                except Exception:
                    interp = None
            if t == "PT_LOAD" and (seg["p_flags"] & 0x2) and (seg["p_flags"] & 0x1):
                rwx.append(seg["p_vaddr"])

        # symbols + canary indicator + notable gifts
        sym_count = 0
        canary = False
        notable = {}
        for sec in elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    sym_count += 1
                    nm = sym.name
                    if nm in ("__stack_chk_fail", "__stack_chk_guard"):
                        canary = True
                    low = nm.lower()
                    if low in ("win", "system", "main", "giveshell", "backdoor") and nm not in notable:
                        notable[nm] = sym["st_value"]

        # relocations + dynamic linkage (needed libs, BIND_NOW)
        reloc_total = 0
        for sec in elf.iter_sections():
            if isinstance(sec, RelocationSection):
                try:
                    reloc_total += sec.num_relocations()
                except Exception:
                    pass
        needed, bind_now = [], False
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(tag.needed)
                    elif (tag.entry.d_tag == "DT_BIND_NOW"
                          or (tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8))      # DF_BIND_NOW
                          or (tag.entry.d_tag == "DT_FLAGS_1" and (tag.entry.d_val & 0x1))):  # DF_1_NOW
                        bind_now = True

        pie = elf["e_type"] == "ET_DYN"
        nx = (gnu_stack is not None) and not (gnu_stack & 0x1)
        exec_stack = (gnu_stack is not None) and bool(gnu_stack & 0x1)
        relro = ("Full" if (gnu_relro and bind_now) else ("Partial" if gnu_relro else None))

        limits = []
        if gnu_stack is None:
            limits.append("sin PT_GNU_STACK: el estado NX no es observable (nx=null)")
        if elf["e_type"] == "ET_DYN" and interp is None:
            limits.append("ET_DYN sin PT_INTERP: puede ser PIE ejecutable o una biblioteca compartida")
        if not canary:
            limits.append("sin __stack_chk_*: la ausencia no prueba que no haya canary (puede estar inlined/stripped)")
        elif not needed and interp is None:
            limits.append("binario estatico: __stack_chk_* puede provenir de la libc enlazada aunque el "
                          "codigo de usuario NO use canary (falso positivo tipico en estaticos)")

        return {"ok": True, "is_elf": True, "header": hdr, "sections": sections,
                "segments": segments, "interpreter": interp, "needed_libraries": needed,
                "symbol_count": sym_count, "relocation_count": reloc_total, "notable_symbols": notable,
                "rwx_segments": rwx,
                "mitigations": {"evidence": "inferred", "position_independent": pie,
                                "nx": (None if gnu_stack is None else nx),
                                "executable_stack": exec_stack, "stack_canary": canary, "relro": relro},
                "limitations": limits}


def render_elf(r: dict) -> str:
    out = ["## Layout ELF + candidatos de mitigacion (estatico)\n"]
    if not r.get("ok"):
        return "\n".join(out + ["No disponible: " + r.get("note", "")])
    if not r.get("is_elf"):
        return "\n".join(out + ["- No es un ELF: " + r.get("note", "")])
    h = r["header"]
    out.append(f"- tipo: **{h['type']}**  |  maquina: {h['machine']}  |  {h['bits']}-bit {h['endian']}"
               f"  |  entry: {hex(h['entry'])}")
    if r.get("interpreter"):
        out.append(f"- interprete: `{r['interpreter']}`")
    if r.get("needed_libraries"):
        out.append(f"- bibliotecas necesarias: {', '.join(r['needed_libraries'])}")
    out.append(f"- simbolos: {r['symbol_count']}  |  reubicaciones: {r['relocation_count']}")
    if r.get("notable_symbols"):
        out.append("- simbolos notables: " + ", ".join(f"`{k}`@{hex(v)}" for k, v in r["notable_symbols"].items()))
    m = r["mitigations"]
    out.append("\n### Mitigaciones (inferido)")
    out.append(f"- PIE: **{'si' if m['position_independent'] else 'no'}**")
    out.append(f"- NX: **{'si' if m['nx'] else ('no' if m['nx'] is False else 'desconocido')}**")
    out.append(f"- pila ejecutable: **{'SI (peligro)' if m['executable_stack'] else 'no'}**")
    out.append(f"- stack canary: **{'si' if m['stack_canary'] else 'no observado'}**")
    out.append(f"- RELRO: **{m['relro'] or 'ninguno'}**")
    if r.get("rwx_segments"):
        out.append(f"- **segmentos RWX (escribible+ejecutable): {', '.join(hex(a) for a in r['rwx_segments'])}**")
    out.append(f"\n### Secciones ({len(r['sections'])}) / Segmentos ({len(r['segments'])})")
    for s in r["sections"][:40]:
        if s["type"] in ("SHT_NULL",):
            continue
        out.append(f"- {s['name'] or '(sin nombre)'}  {s['perms']}  addr={hex(s['addr'])} size={hex(s['size'])}")
    for seg in r["segments"]:
        if seg["type"] in ("PT_LOAD", "PT_GNU_STACK", "PT_GNU_RELRO", "PT_INTERP"):
            out.append(f"- seg {seg['type']}  {seg['perms']}  vaddr={hex(seg['vaddr'])} memsz={hex(seg['memsz'])}")
    for lim in r.get("limitations", []):
        out.append(f"- _limite: {lim}_")
    return "\n".join(out)
