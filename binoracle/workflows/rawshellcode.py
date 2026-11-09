"""Raw shellcode analysis: disassemble a bare byte blob with no ELF/PE/Mach-O container.

ROADMAP v0.4 "[S] More formats & backends" -- "raw shellcode analysis". Every existing static
oracle (`oracles/static_r2.py`, `oracles/capstone_fallback.py`) assumes a recognizable binary
container (ELF here) to find the entry point and architecture; a raw shellcode dump (what a
heap-spray, an XSS->shellcode chain, or a CTF "here are N bytes, pwn it" challenge hands you) has
neither. capstone is the oracle, same dependency `capstone_fallback.py` already uses, but there is
no header to read the architecture from -- so this tries every architecture capstone knows how to
decode x86/ARM/MIPS shellcode in, and RANKS the candidates with a heuristic score (bytes
successfully consumed as valid instructions, penalized for classic "decoded x86 noise" mnemonics
that show up when you disassemble non-code as x86 by chance, rewarded for a syscall/interrupt
instruction actually present). Per this project's "no false positives by construction" rule, the
result is always a RANKED LIST OF CANDIDATES with their scores shown -- never a single asserted
"this is ARM" verdict. Confirmed live against this project's own real execve shellcode
(`workflows/shellcode.py`'s precompiled amd64 blob): x86-64 scores highest and correctly shows the
`syscall` instruction, while x86-32 decodes the SAME bytes as valid-looking but score lower (it
picks up classic decode noise like `das`) and ARM/ARM64/MIPS fail to consume most of the bytes at
all."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import capstone  # type: ignore
    _HAVE_CAPSTONE = True
except Exception:
    _HAVE_CAPSTONE = False

# Mnemonics that overwhelmingly show up when x86 decodes NON-code bytes by chance (obsolete/BCD
# arithmetic, privileged I/O) -- a real-world shellcode author essentially never emits these.
_X86_JUNK = {"das", "aad", "aam", "into", "salc", "bound", "arpl", "lahf", "sahf",
            "clts", "hlt", "out", "in", "lock", "wait"}
_SYSCALL_MNEMONICS = {"syscall", "sysenter", "int", "svc", "trap", "swi"}

_ARCH_CANDIDATES: List[tuple] = []
if _HAVE_CAPSTONE:
    _ARCH_CANDIDATES = [
        ("x86-64", capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        ("x86-32", capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        ("arm", capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
        ("thumb", capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB),
        ("arm64", capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        ("mips32-le", capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
        ("mips32-be", capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 + capstone.CS_MODE_BIG_ENDIAN),
    ]

_MAX_BYTES = 4096
_MAX_INSNS = 300


@dataclass
class Insn:
    addr: int
    mnemonic: str
    op_str: str


@dataclass
class ArchCandidate:
    arch: str
    score: float
    n_insns: int
    bytes_consumed: int
    bytes_total: int
    n_junk: int
    n_syscall_insns: int
    insns: List[Insn] = field(default_factory=list)


@dataclass
class RawShellcodeResult:
    ok: bool = False
    note: str = ""
    size: int = 0
    candidates: List[ArchCandidate] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)

    @property
    def best(self) -> Optional[ArchCandidate]:
        return self.candidates[0] if self.candidates else None


def _extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(m.group().decode("ascii", "replace"))
    return out


def _score_candidate(arch: str, insns, total_len: int) -> ArchCandidate:
    consumed = sum(i.size for i in insns)
    n_junk = sum(1 for i in insns if i.mnemonic in _X86_JUNK)
    n_sys = sum(1 for i in insns if i.mnemonic in _SYSCALL_MNEMONICS)
    n = max(len(insns), 1)
    score = (consumed / max(total_len, 1)) - 0.3 * (n_junk / n) + 0.2 * min(n_sys, 1)
    return ArchCandidate(
        arch=arch, score=round(score, 4), n_insns=len(insns), bytes_consumed=consumed,
        bytes_total=total_len, n_junk=n_junk, n_syscall_insns=n_sys,
        insns=[Insn(i.address, i.mnemonic, i.op_str) for i in insns[:_MAX_INSNS]],
    )


def analyze_raw_shellcode(data: bytes, base_addr: int = 0) -> RawShellcodeResult:
    """Prueba cada arquitectura que capstone conoce contra `data` (un blob SIN contenedor ELF/
    PE/Mach-O) y devuelve los candidatos RANKEADOS por heuristica -- nunca una unica arquitectura
    afirmada como cierta. `data` esta limitado a 4KB (un blob de shellcode real cabe de sobra;
    esto no es para volcar un binario entero sin cabecera)."""
    res = RawShellcodeResult(size=len(data))
    if not _HAVE_CAPSTONE:
        res.note = "capstone no esta instalado (pip install capstone)"
        return res
    if not data:
        res.note = "blob vacio"
        return res
    blob = data[:_MAX_BYTES]
    res.strings = _extract_strings(blob)

    candidates = []
    for name, arch, mode in _ARCH_CANDIDATES:
        try:
            md = capstone.Cs(arch, mode)
            insns = list(md.disasm(blob, base_addr))
        except Exception:
            continue
        if not insns:
            continue
        candidates.append(_score_candidate(name, insns, len(blob)))

    if not candidates:
        res.note = "ninguna arquitectura logro decodificar ni una instruccion valida"
        return res
    candidates.sort(key=lambda c: c.score, reverse=True)
    res.ok = True
    res.candidates = candidates
    best = candidates[0]
    res.note = (f"mejor candidato: {best.arch} (score={best.score}, "
               f"{best.bytes_consumed}/{best.bytes_total} bytes consumidos, "
               f"{best.n_syscall_insns} instruccion(es) de syscall/interrupcion) -- "
               f"heuristica, no una verificacion de ejecucion real")
    return res


def render_raw_shellcode(r: RawShellcodeResult, top_n: int = 3, max_insns_shown: int = 40) -> str:
    out = ["## Raw shellcode analysis\n", f"- tamano: {r.size} bytes\n"]
    if not r.ok:
        return "\n".join(out + ["No disponible: " + r.note])
    out.append(r.note + "\n")
    out.append("| arquitectura (candidato) | score | instrucciones | bytes consumidos | syscalls |")
    out.append("|---|---|---|---|---|")
    for c in r.candidates[:top_n]:
        out.append(f"| {c.arch} | {c.score} | {c.n_insns} | {c.bytes_consumed}/{c.bytes_total} | {c.n_syscall_insns} |")
    best = r.best
    if best and best.insns:
        out.append(f"\n### Desensamblado ({best.arch}, mejor candidato)\n```")
        for i in best.insns[:max_insns_shown]:
            out.append(f"{hex(i.addr)}:  {i.mnemonic} {i.op_str}".rstrip())
        if len(best.insns) > max_insns_shown:
            out.append(f"... ({len(best.insns) - max_insns_shown} instrucciones mas)")
        out.append("```")
    if r.strings:
        out.append("\n### Cadenas embebidas\n```")
        out.extend(r.strings[:30])
        out.append("```")
    return "\n".join(out)
