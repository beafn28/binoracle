"""Capstone disassembly fallback oracle.

radare2 is binoracle's primary static oracle (cross-references, function-boundary
detection, decompiler-grade analysis). Capstone is a bare instruction decoder with
none of that, so this oracle only activates when radare2 itself is unavailable on
the host (no `r2pipe` python package, and no `r2`/`radare2` binary on PATH): a real,
degraded-but-grounded fallback for raw disassembly instead of the hard blank
R2Oracle leaves in that case. This closes the ROADMAP gap ("the capstone fallback
oracle -- the extra exists but is currently unused").

Needs pyelftools (to locate sections / entry point) and capstone (to decode). Covers
ELF only, x86-64 / x86-32 / ARM / AArch64 -- the architectures capstone and this
codebase's exploit engine both care about. Degrades honestly (not registered at all)
when either dependency, or radare2 itself, makes it redundant or impossible."""
from __future__ import annotations

import shutil
from typing import List, Optional, Tuple

from .base import Oracle, Tool, ToolParam, ToolResult

try:
    import capstone  # type: ignore
    _HAVE_CAPSTONE = True
except Exception:
    _HAVE_CAPSTONE = False

try:
    from elftools.elf.elffile import ELFFile  # type: ignore
    _HAVE_PYELF = True
except Exception:
    _HAVE_PYELF = False

try:
    import r2pipe  # type: ignore
    _HAVE_R2PIPE = True
except Exception:
    _HAVE_R2PIPE = False


def _r2_available() -> bool:
    return _HAVE_R2PIPE or shutil.which("r2") is not None or shutil.which("radare2") is not None


# (elfclass is 32/64, e_machine string) -> (capstone arch, capstone mode)
_ARCH_MODE = {
    (64, "EM_X86_64"): ("CS_ARCH_X86", "CS_MODE_64"),
    (32, "EM_386"): ("CS_ARCH_X86", "CS_MODE_32"),
    (32, "EM_ARM"): ("CS_ARCH_ARM", "CS_MODE_ARM"),
    (64, "EM_AARCH64"): ("CS_ARCH_ARM64", "CS_MODE_ARM"),
}

# Bounded like every other oracle call here: a disassembly dump is for grounding a
# specific hypothesis, not for dumping the whole binary through the agent loop.
_MAX_INSNS = 200
_MAX_BYTES = 4096


class CapstoneOracle(Oracle):
    name = "capstone_fallback"

    def __init__(self, binary: str):
        self.binary = binary

    def available(self) -> bool:
        if not (_HAVE_CAPSTONE and _HAVE_PYELF):
            return False
        if _r2_available():
            return False  # radare2 covers this and far more; no point duplicating
        try:
            with open(self.binary, "rb") as f:
                return f.read(4) == b"\x7fELF"
        except Exception:
            return False

    def why_unavailable(self) -> str:
        if _r2_available():
            return "radare2 is available and covers disassembly (this fallback stays off)"
        if not _HAVE_CAPSTONE:
            return "capstone not installed (pip install capstone)"
        if not _HAVE_PYELF:
            return "pyelftools not installed (pip install pyelftools)"
        return "target is not an ELF file (or unreadable)"

    def tools(self) -> List[Tool]:
        return [
            Tool(
                "cs_disasm_entry",
                "Disassemble from the ELF entry point with capstone (radare2 unavailable "
                "fallback; no xrefs/function boundaries, just raw linear decode).",
                [ToolParam("count", "number of instructions (default 40, max 200)",
                           required=False, default=40)],
                lambda count=40: self._disasm_at(None, count),
                self.name,
            ),
            Tool(
                "cs_disasm_at",
                "Disassemble `count` instructions at a given virtual address with capstone "
                "(radare2 unavailable fallback).",
                [ToolParam("addr", "virtual address, e.g. 0x401136"),
                 ToolParam("count", "number of instructions (default 40, max 200)",
                           required=False, default=40)],
                lambda addr, count=40: self._disasm_at(addr, count),
                self.name,
            ),
        ]

    # ---- internals ----
    def _arch_mode(self, elf: "ELFFile") -> Optional[Tuple[int, int]]:
        elfclass = 64 if elf.elfclass == 64 else 32
        machine = elf.header["e_machine"]
        key = _ARCH_MODE.get((elfclass, machine))
        if not key:
            return None
        arch = getattr(capstone, key[0])
        mode = getattr(capstone, key[1])
        return arch, mode

    def _read_at(self, elf: "ELFFile", vaddr: int, size: int) -> Optional[bytes]:
        """Read `size` bytes at virtual address `vaddr` from whichever PT_LOAD/section
        actually maps it, the way a loader would -- not just the .text section, so a
        caller-given address anywhere in the mapped image resolves."""
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            lo, hi = seg["p_vaddr"], seg["p_vaddr"] + seg["p_filesz"]
            if lo <= vaddr < hi:
                off = seg["p_offset"] + (vaddr - lo)
                avail = hi - vaddr
                data = seg.data()
                rel = vaddr - lo
                return data[rel:rel + min(size, avail)]
        return None

    def _disasm_at(self, addr, count) -> ToolResult:
        try:
            count = max(1, min(int(count), _MAX_INSNS))
        except (TypeError, ValueError):
            count = 40
        try:
            with open(self.binary, "rb") as f:
                elf = ELFFile(f)
                arch_mode = self._arch_mode(elf)
                if not arch_mode:
                    return ToolResult(
                        False, "capstone", "",
                        error=f"unsupported e_machine={elf.header['e_machine']!r} for this fallback",
                    )
                if addr is None:
                    vaddr = elf.header["e_entry"]
                else:
                    try:
                        vaddr = int(str(addr), 0)
                    except ValueError:
                        return ToolResult(False, "capstone", "", error=f"bad address {addr!r}")
                blob = self._read_at(elf, vaddr, _MAX_BYTES)
                if not blob:
                    return ToolResult(
                        False, "capstone", "",
                        error=f"address {hex(vaddr)} is not inside any PT_LOAD segment",
                    )
                arch, mode = arch_mode
                md = capstone.Cs(arch, mode)
                lines = []
                for insn in md.disasm(blob, vaddr):
                    lines.append(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
                    if len(lines) >= count:
                        break
                if not lines:
                    return ToolResult(
                        False, "capstone", "",
                        error=f"capstone could not decode any instruction at {hex(vaddr)}",
                    )
                return ToolResult(
                    True, f"capstone: disasm @ {hex(vaddr)} ({count} insns, no-r2 fallback)",
                    "\n".join(lines),
                    meta={"addr": hex(vaddr), "count": len(lines), "fallback": True},
                )
        except Exception as e:
            return ToolResult(False, "capstone", "", error=f"capstone error: {e}")
