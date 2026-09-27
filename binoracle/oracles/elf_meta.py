"""ELF metadata + mitigation (checksec-style) oracle.

Uses pyelftools when available for full detail, and falls back to a tiny stdlib struct
parser so that basic triage works with zero pip installs."""
from __future__ import annotations

import struct
from pathlib import Path
from typing import List

from .base import Oracle, Tool, ToolParam, ToolResult

try:
    from elftools.elf.elffile import ELFFile  # type: ignore
    from elftools.elf.dynamic import DynamicSection  # type: ignore
    from elftools.elf.sections import SymbolTableSection  # type: ignore
    _HAVE_PYELF = True
except Exception:
    _HAVE_PYELF = False


class ElfMetaOracle(Oracle):
    name = "elf_meta"

    def __init__(self, binary: str):
        self.binary = binary

    def available(self) -> bool:
        try:
            with open(self.binary, "rb") as f:
                return f.read(4) == b"\x7fELF"
        except Exception:
            return False

    def why_unavailable(self) -> str:
        return "target is not an ELF file (or unreadable)"

    def tools(self) -> List[Tool]:
        return [
            Tool(
                name="elf_info",
                description="ELF header summary: class, arch, type (PIE?), entry, stripped.",
                params=[],
                run=lambda: self._info(),
                oracle=self.name,
            ),
            Tool(
                name="elf_mitigations",
                description="checksec-style mitigations: NX, PIE, RELRO, stack canary, stripped.",
                params=[],
                run=lambda: self._mitigations(),
                oracle=self.name,
            ),
            Tool(
                name="elf_relocations",
                description="Relocations and GOT/PLT entries (needs pyelftools). Useful for GOT-overwrite planning.",
                params=[],
                run=lambda: self._relocations(),
                oracle=self.name,
            ),
            Tool(
                name="elf_symbols",
                description="Defined and imported symbols with addresses (needs pyelftools).",
                params=[],
                run=lambda: self._symbols(),
                oracle=self.name,
            ),
        ]

    # ---- stdlib fallback ----
    def _fallback_info(self) -> ToolResult:
        with open(self.binary, "rb") as f:
            hdr = f.read(64)
        if hdr[:4] != b"\x7fELF":
            return ToolResult(False, "elf_meta(stdlib)", "", error="not ELF")
        ei_class = hdr[4]
        ei_data = hdr[5]
        is64 = ei_class == 2
        endian = "<" if ei_data == 1 else ">"
        e_type = struct.unpack_from(endian + "H", hdr, 16)[0]
        e_machine = struct.unpack_from(endian + "H", hdr, 18)[0]
        entry = struct.unpack_from(endian + ("Q" if is64 else "I"), hdr, 24)[0]
        types = {1: "REL", 2: "EXEC", 3: "DYN(PIE/so)", 4: "CORE"}
        machines = {0x3E: "x86-64", 0x03: "x86", 0xB7: "aarch64", 0x28: "arm", 0xF3: "riscv"}
        txt = (
            f"class: {'ELF64' if is64 else 'ELF32'}\n"
            f"endianness: {'little' if ei_data == 1 else 'big'}\n"
            f"machine: {machines.get(e_machine, hex(e_machine))}\n"
            f"type: {types.get(e_type, e_type)}\n"
            f"entrypoint: {hex(entry)}\n"
            f"(parser: stdlib fallback; install pyelftools for full detail)"
        )
        return ToolResult(True, "elf_meta(stdlib): ELF header", txt,
                          meta={"pie": e_type == 3, "arch": machines.get(e_machine)})

    def _info(self) -> ToolResult:
        if not _HAVE_PYELF:
            return self._fallback_info()
        with open(self.binary, "rb") as f:
            elf = ELFFile(f)
            stripped = elf.get_section_by_name(".symtab") is None
            e_type = elf.header["e_type"]
            txt = (
                f"class: {elf.elfclass}-bit\n"
                f"machine: {elf.get_machine_arch()}\n"
                f"type: {e_type}\n"
                f"entrypoint: {hex(elf.header['e_entry'])}\n"
                f"stripped: {stripped}\n"
                f"sections: {elf.num_sections()}"
            )
        return ToolResult(True, "elf_meta(pyelftools): header", txt,
                          meta={"pie": e_type == "ET_DYN", "stripped": stripped})

    def _mitigations(self) -> ToolResult:
        if not _HAVE_PYELF:
            r = self._fallback_info()
            nx = self._fallback_nx()
            txt = (
                f"PIE: {r.meta.get('pie')}\n"
                f"NX: {nx}\n"
                f"RELRO/Canary: unknown (install pyelftools for full checksec)\n"
            )
            return ToolResult(True, "elf_meta(stdlib): mitigations", txt)
        with open(self.binary, "rb") as f:
            elf = ELFFile(f)
            e_type = elf.header["e_type"]
            pie = e_type == "ET_DYN"
            nx = True
            relro = "None"
            canary = False
            for seg in elf.iter_segments():
                t = seg["p_type"]
                if t == "PT_GNU_STACK":
                    nx = not bool(seg["p_flags"] & 0x1)  # X bit clear -> NX on
                if t == "PT_GNU_RELRO":
                    relro = "Partial"
            dyn = elf.get_section_by_name(".dynamic")
            if isinstance(dyn, DynamicSection):
                flags = [t.entry.d_val for t in dyn.iter_tags("DT_FLAGS")]
                if any(v & 0x8 for v in flags) and relro == "Partial":  # DF_BIND_NOW
                    relro = "Full"
            for secname in (".dynsym", ".symtab"):
                sec = elf.get_section_by_name(secname)
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        if "__stack_chk_fail" in sym.name or "__stack_chk_guard" in sym.name:
                            canary = True
                            break
            stripped = elf.get_section_by_name(".symtab") is None
            txt = (
                f"PIE:          {pie}\n"
                f"NX:           {nx}\n"
                f"RELRO:        {relro}\n"
                f"Stack canary: {canary}\n"
                f"Stripped:     {stripped}"
            )
        return ToolResult(True, "elf_meta(pyelftools): checksec", txt,
                          meta={"pie": pie, "nx": nx, "relro": relro, "canary": canary})

    def _fallback_nx(self) -> str:
        # Minimal PT_GNU_STACK scan without pyelftools.
        try:
            with open(self.binary, "rb") as f:
                data = f.read()
            is64 = data[4] == 2
            endian = "<" if data[5] == 1 else ">"
            if is64:
                e_phoff = struct.unpack_from(endian + "Q", data, 32)[0]
                e_phentsize = struct.unpack_from(endian + "H", data, 54)[0]
                e_phnum = struct.unpack_from(endian + "H", data, 56)[0]
                for i in range(e_phnum):
                    off = e_phoff + i * e_phentsize
                    p_type = struct.unpack_from(endian + "I", data, off)[0]
                    p_flags = struct.unpack_from(endian + "I", data, off + 4)[0]
                    if p_type == 0x6474E551:  # PT_GNU_STACK
                        return str(not bool(p_flags & 0x1))
            return "unknown"
        except Exception:
            return "unknown"

    def _relocations(self) -> ToolResult:
        if not _HAVE_PYELF:
            return ToolResult(False, "elf_meta", "", error="pyelftools not installed")
        from elftools.elf.relocation import RelocationSection  # type: ignore
        lines = []
        with open(self.binary, "rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if isinstance(sec, RelocationSection):
                    symtab = elf.get_section(sec["sh_link"])
                    lines.append(f"# {sec.name} ({sec.num_relocations()} relocs)")
                    for reloc in sec.iter_relocations():
                        symname = ""
                        try:
                            symname = symtab.get_symbol(reloc["r_info_sym"]).name
                        except Exception:
                            pass
                        lines.append(f"  {hex(reloc['r_offset'])}  {symname}")
        txt = "\n".join(lines) if lines else "(no relocation sections)"
        return ToolResult(True, "elf_meta(pyelftools): relocations", txt)

    def _symbols(self) -> ToolResult:
        if not _HAVE_PYELF:
            return ToolResult(False, "elf_meta", "", error="pyelftools not installed")
        lines = []
        with open(self.binary, "rb") as f:
            elf = ELFFile(f)
            for secname in (".dynsym", ".symtab"):
                sec = elf.get_section_by_name(secname)
                if isinstance(sec, SymbolTableSection):
                    lines.append(f"# {secname}")
                    for sym in sec.iter_symbols():
                        if not sym.name:
                            continue
                        addr = sym["st_value"]
                        typ = sym["st_info"]["type"]
                        lines.append(f"  {hex(addr)}  {typ:14s} {sym.name}")
        txt = "\n".join(lines[:400]) if lines else "(no symbol tables; stripped?)"
        return ToolResult(True, "elf_meta(pyelftools): symbols", txt)
