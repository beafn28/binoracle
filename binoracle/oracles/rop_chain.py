"""ROP gadget extraction and chain building oracle (Windows/Linux PE/ELF).

Uses ropper or ROPgadget when available; falls back to radare2's /Rl.
Focuses on gadget classification and chain building primitives, NOT on
auto-generating working shellcode — the output is evidence-grounded candidates."""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from .base import Oracle, Tool, ToolParam, ToolResult

# Gadget categories: (label, regex patterns that must all match)
_GADGET_CLASSES: list[tuple[str, list[str]]] = [
    ("stack_pivot",    [r"(xchg|mov)\s+(rsp|esp)\s*,\s*(r\w+|e\w+|rbp|ebp)"]),
    ("ret2libc_setup", [r"pop\s+rdi\b"]),                    # 1st arg x86_64 Linux
    ("pop_rdi",        [r"pop\s+rdi\b"]),
    ("pop_rsi",        [r"pop\s+rsi\b"]),
    ("pop_rdx",        [r"pop\s+rdx\b"]),
    ("pop_rcx",        [r"pop\s+rcx\b"]),                    # 4th arg Windows x64
    ("pop_r8",         [r"pop\s+r8\b"]),
    ("pop_r9",         [r"pop\s+r9\b"]),
    ("pop_rbp",        [r"pop\s+rbp\b"]),
    ("pop_rsp",        [r"pop\s+rsp\b"]),
    ("ret",            [r"^\s*ret\s*$"]),                    # bare ret for alignment
    ("jmp_esp",        [r"jmp\s+esp\b"]),                    # classic x86 SEH
    ("jmp_eax",        [r"jmp\s+eax\b"]),
    ("call_esp",       [r"call\s+esp\b"]),
    ("xchg_eax_esp",   [r"xchg\s+eax\s*,\s*esp"]),
    ("leave_ret",      [r"leave\s*;?\s*ret"]),
    ("nop_ret",        [r"nop\s*;?\s*ret"]),
    ("add_rsp",        [r"add\s+rsp\s*,\s*0x"]),
    ("syscall",        [r"\bsyscall\b"]),
    ("int80",          [r"int\s+0x80"]),
    ("write_what_where", [r"mov\s+\[r\w+\]\s*,\s*r\w+", r"ret"]),
    ("read_mem",       [r"mov\s+r\w+\s*,\s*\[r\w+\]", r"ret"]),
]

_CHAIN_PRIMITIVES_x64 = [
    "pop_rdi", "pop_rsi", "pop_rdx", "pop_rcx", "pop_r8", "pop_r9",
    "ret", "stack_pivot", "syscall",
]
_CHAIN_PRIMITIVES_x86 = [
    "jmp_esp", "jmp_eax", "call_esp", "xchg_eax_esp", "pop_rbp", "leave_ret",
]
_CHAIN_PRIMITIVES_win64 = [
    "pop_rcx", "pop_rdx", "pop_r8", "pop_r9", "ret", "stack_pivot",
]


@dataclass
class Gadget:
    addr: str
    insns: str
    category: str


def _run_ropper(binary: str, search: Optional[str] = None) -> str:
    exe = shutil.which("ropper")
    if not exe:
        return ""
    cmd = [exe, "--file", binary, "--nocolor"]
    if search:
        cmd += ["--search", search]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.stdout or ""
    except Exception:
        return ""


def _run_ropgadget(binary: str, search: Optional[str] = None) -> str:
    exe = shutil.which("ROPgadget") or shutil.which("ropgadget")
    if not exe:
        return ""
    cmd = [exe, "--binary", binary, "--nojop", "--nosys"]
    if search:
        cmd += ["--re", search]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.stdout or ""
    except Exception:
        return ""


def _run_r2_gadgets(binary: str) -> str:
    exe = shutil.which("r2") or shutil.which("radare2")
    if not exe:
        return ""
    try:
        r = subprocess.run(
            [exe, "-q", "-e", "scr.color=0", "-e", "log.quiet=true",
             "-2", "-c", "/Rl", binary],
            capture_output=True, text=True, timeout=90,
        )
        return r.stdout or ""
    except Exception:
        return ""


def extract_gadgets(binary: str) -> list[Gadget]:
    """Return raw gadget list from the best available tool."""
    raw = _run_ropper(binary) or _run_ropgadget(binary) or _run_r2_gadgets(binary)
    gadgets: list[Gadget] = []
    for line in raw.splitlines():
        # Both ropper and ROPgadget: "0xdeadbeef: pop rdi; ret"
        m = re.match(r"(0x[0-9a-fA-F]+)\s*[:]\s*(.+)", line.strip())
        if not m:
            continue
        addr, insns = m.group(1), m.group(2).strip()
        cat = _classify(insns)
        gadgets.append(Gadget(addr=addr, insns=insns, category=cat))
    return gadgets


def _classify(insns: str) -> str:
    for label, patterns in _GADGET_CLASSES:
        if all(re.search(p, insns, re.IGNORECASE) for p in patterns):
            return label
    return "generic"


def filter_gadgets(gadgets: list[Gadget], category: str) -> list[Gadget]:
    if category == "all":
        return gadgets
    return [g for g in gadgets if g.category == category]


def gadget_summary(gadgets: list[Gadget]) -> dict[str, list[Gadget]]:
    """Group gadgets by category."""
    groups: dict[str, list[Gadget]] = {}
    for g in gadgets:
        groups.setdefault(g.category, []).append(g)
    return groups


def chain_assessment(gadgets: list[Gadget], arch: str = "x64") -> dict:
    """Given extracted gadgets, assess which chain primitives are covered."""
    summary = gadget_summary(gadgets)
    present = set(summary.keys())
    if arch in ("x86_64", "x64"):
        wanted = _CHAIN_PRIMITIVES_x64
    elif arch in ("win64",):
        wanted = _CHAIN_PRIMITIVES_win64
    else:
        wanted = _CHAIN_PRIMITIVES_x86
    covered = [p for p in wanted if p in present]
    missing = [p for p in wanted if p not in present]
    return {
        "arch": arch,
        "covered": covered,
        "missing": missing,
        "total_gadgets": len(gadgets),
        "viable_chain": len(missing) == 0,
    }


class RopChainOracle(Oracle):
    name = "rop_chain"

    def __init__(self, binary: str, arch: str = "x64"):
        self.binary = binary
        self.arch = arch
        self._gadgets: Optional[list[Gadget]] = None

    def available(self) -> bool:
        return bool(
            shutil.which("ropper") or
            shutil.which("ROPgadget") or
            shutil.which("ropgadget") or
            shutil.which("r2") or
            shutil.which("radare2")
        )

    def why_unavailable(self) -> str:
        return "none of ropper / ROPgadget / radare2 available (pip install ropper or ROPgadget)"

    def _get_gadgets(self) -> list[Gadget]:
        if self._gadgets is None:
            self._gadgets = extract_gadgets(self.binary)
        return self._gadgets

    def tools(self) -> list:
        arch_param = ToolParam("arch", "Target architecture: x64, x86, win64", False)
        cat_param = ToolParam("category", "Gadget category filter (e.g. pop_rdi, stack_pivot, all)", False)
        return [
            Tool("rop_summary", "Extract all ROP gadgets and show category breakdown + chain viability.",
                 [arch_param], lambda arch="x64": self._summary(arch), self.name),
            Tool("rop_gadgets", "List gadgets of a specific category (pop_rdi, jmp_esp, stack_pivot, …).",
                 [cat_param], lambda category="all": self._list(category), self.name),
            Tool("rop_chain_primitives", "Show which chain primitives are present/missing for the target arch.",
                 [arch_param], lambda arch="x64": self._chain(arch), self.name),
            Tool("rop_search", "Search gadgets by instruction fragment (e.g. 'pop rdi').",
                 [ToolParam("pattern", "Instruction fragment to search", True)],
                 lambda pattern="": self._search(pattern), self.name),
        ]

    def _summary(self, arch: str = "x64") -> ToolResult:
        gadgets = self._get_gadgets()
        if not gadgets:
            return ToolResult(False, "rop_chain: summary", "(no gadgets found — tool may be missing or binary has no code)",
                              error="no gadgets")
        by_cat = gadget_summary(gadgets)
        lines = [f"Total gadgets: {len(gadgets)}", ""]
        for cat, gs in sorted(by_cat.items(), key=lambda x: -len(x[1])):
            lines.append(f"  {cat:25s} x{len(gs)}")
        assessment = chain_assessment(gadgets, arch)
        lines.append("")
        lines.append(f"Chain viability ({arch}): {'YES — all primitives present' if assessment['viable_chain'] else 'PARTIAL — missing: ' + ', '.join(assessment['missing'])}")
        return ToolResult(True, "rop_chain: gadget summary", "\n".join(lines),
                          meta={"assessment": assessment, "total": len(gadgets)})

    def _list(self, category: str = "all") -> ToolResult:
        gadgets = self._get_gadgets()
        filtered = filter_gadgets(gadgets, category)
        if not filtered:
            return ToolResult(True, f"rop_chain: {category}", f"(no gadgets of category '{category}')")
        lines = [f"{g.addr}: {g.insns}" for g in filtered[:100]]
        txt = "\n".join(lines)
        if len(filtered) > 100:
            txt += f"\n... ({len(filtered) - 100} more)"
        return ToolResult(True, f"rop_chain: {category}", txt,
                          meta={"count": len(filtered)})

    def _chain(self, arch: str = "x64") -> ToolResult:
        gadgets = self._get_gadgets()
        a = chain_assessment(gadgets, arch)
        lines = [
            f"Arch: {arch}",
            f"Total gadgets: {a['total_gadgets']}",
            "",
            "Covered primitives:",
        ]
        for p in a["covered"]:
            gs = [g for g in gadgets if g.category == p]
            lines.append(f"  [+] {p:25s} — best: {gs[0].addr}: {gs[0].insns[:60]}")
        if a["missing"]:
            lines.append("")
            lines.append("Missing primitives:")
            for p in a["missing"]:
                lines.append(f"  [-] {p}")
        lines.append("")
        lines.append("Viable: " + ("YES" if a["viable_chain"] else "NO — chain incomplete"))
        return ToolResult(True, f"rop_chain: primitives ({arch})", "\n".join(lines), meta=a)

    def _search(self, pattern: str) -> ToolResult:
        gadgets = self._get_gadgets()
        try:
            rx = re.compile(pattern, re.IGNORECASE)
            matched = [g for g in gadgets if rx.search(g.insns)]
        except re.error:
            matched = [g for g in gadgets if pattern.lower() in g.insns.lower()]
        lines = [f"{g.addr}: {g.insns}" for g in matched[:50]]
        txt = "\n".join(lines) if lines else f"(no gadgets matching '{pattern}')"
        return ToolResult(True, f"rop_chain: search '{pattern}'", txt,
                          meta={"count": len(matched)})
