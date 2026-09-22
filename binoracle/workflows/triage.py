"""Triage workflow: run the cheap grounding oracles directly (NO model required) and
produce a facts-only report. This is deliberately deterministic and offline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..oracles.base import ToolRegistry


@dataclass
class TriageReport:
    binary: str
    sections: List[tuple] = field(default_factory=list)  # (title, source, text)

    def add(self, title: str, source: str, text: str) -> None:
        self.sections.append((title, source, text))


# Tools we run unconditionally during triage, in order, if available.
TRIAGE_TOOLS = [
    ("elf_info", "File / ELF header"),
    ("elf_mitigations", "Exploit mitigations (checksec)"),
    ("r2_info", "radare2 binary info"),
    ("r2_checksec", "Exploit mitigations (cross-format: ELF/PE/Mach-O)"),
    ("r2_hardening", "Modern hardening (FORTIFY/ASan/CFI/SafeStack)"),
    ("r2_imports", "Imports"),
    ("r2_sinks", "Dangerous sinks and their callers"),
    ("r2_vtables", "C++ / vtables"),
    ("r2_heap", "Heap attack surface (UAF/double-free candidates)"),
    ("r2_indirect", "Control de flujo indirecto (punteros a funcion / vtables)"),
]


def run_triage(registry: ToolRegistry, binary: str, store=None, on_step=None) -> TriageReport:
    report = TriageReport(binary=binary)
    for tool_name, title in TRIAGE_TOOLS:
        tool = registry.get(tool_name)
        if tool is None:
            continue
        if on_step:
            on_step(f"triage: {title} ({tool_name})...")
        try:
            res = tool.run()
        except Exception as e:  # oracle-level failure should not kill triage
            report.add(title, tool_name, f"[error running {tool_name}: {e}]")
            continue
        if res.ok:
            report.add(title, res.source, res.data)
            if store:
                store.add_fact(tool_name, res.source, res.data)
        else:
            report.add(title, res.source, f"[unavailable: {res.error}]")
    return report
